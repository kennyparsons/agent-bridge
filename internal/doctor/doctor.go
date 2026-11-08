package doctor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/netbind"
	"github.com/kennyparsons/agent-bridge/internal/pki"
	"github.com/kennyparsons/agent-bridge/internal/protocol"
)

const (
	// StatusPass indicates a check completed with zero anomalies.
	StatusPass = "pass"
	// StatusWarn indicates a non-fatal risk or degraded condition requiring operator attention.
	StatusWarn = "warn"
	// StatusFail indicates a blocking pre-flight or node health failure.
	StatusFail = "fail"

	// Stable machine-readable check identifiers emitted in Report.Checks.
	CheckIDRouteHairpin     = "route_hairpin"
	CheckIDIPv4Forwarding   = "ipv4_forwarding"
	CheckIDSeedReachability = "seed_reachability"
	CheckIDBindAvailability = "bind_availability"
	CheckIDCertSANsExpiry   = "cert_sans_expiry"
	CheckIDCRLFreshness     = "crl_freshness"

	defaultSeedDialTimeout = 5 * time.Second
	certExpiryWarnWindow   = 14 * 24 * time.Hour
	crlExpiryWarnWindow    = 24 * time.Hour
)

// CheckResult represents a single structured diagnostic check outcome.
type CheckResult struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	Summary     string `json:"summary"`
	Remediation string `json:"remediation,omitempty"`
}

// Report aggregates all pre-flight and node health check results.
type Report struct {
	Checks      []CheckResult `json:"checks"`
	GeneratedAt time.Time     `json:"generated_at"`
}

// HasFailures reports whether any check in Report ended with StatusFail.
func (r Report) HasFailures() bool {
	for _, c := range r.Checks {
		if c.Status == StatusFail {
			return true
		}
	}
	return false
}

// HasWarnings reports whether any check in Report ended with StatusWarn.
func (r Report) HasWarnings() bool {
	for _, c := range r.Checks {
		if c.Status == StatusWarn {
			return true
		}
	}
	return false
}

// FindCheck looks up a check result by its ID.
func (r Report) FindCheck(id string) (CheckResult, bool) {
	for _, c := range r.Checks {
		if c.ID == id {
			return c, true
		}
	}
	return CheckResult{}, false
}

// ForwardingProbeFunc inspects whether kernel IPv4 packet forwarding is enabled on the host.
type ForwardingProbeFunc func(ifaces []netbind.InterfaceInfo) (enabled bool, detail string, err error)

// TLSProbeResult captures the negotiated TLS version and peer Subject CN from a seed reachability probe.
type TLSProbeResult struct {
	TLSVersion uint16
	PeerCN     string
}

// Options configures Run for pre-flight join diagnostics and local node health audits.
type Options struct {
	// Seeds is an optional list (or comma-separated entries) of cluster seed addresses (`host` or `host:port`).
	Seeds []string

	// BindSpecs is an optional list of exec server bind selectors checked for port availability
	// (when DaemonRunning is false) and concrete IP SAN coverage.
	BindSpecs         []string
	DefaultPort       int
	AllowPortOverride bool
	DaemonRunning     bool

	// ClusterBindSpecs is an optional list of cluster control-plane bind selectors (`--cluster-bind`).
	ClusterBindSpecs []string
	ClusterPort      int

	// PKI artifact paths for X.509 leaf SAN completeness/expiry and CRL signature/freshness checks.
	CertPath            string
	CAPath              string
	CRLPath             string
	RequirePKI          bool
	StrictInterfaceSANs bool

	// DialTimeout bounds per-seed TCP + TLS 1.3 reachability checks (defaults to 5s).
	DialTimeout time.Duration
	Now         func() time.Time

	// Injectable probes for deterministic cross-OS unit testing.
	InterfaceProvider netbind.InterfaceProvider
	RouteSourceIP     func(seedAddr string) (net.IP, error)
	ForwardingProbe   ForwardingProbeFunc
	DialTLS           func(ctx context.Context, addr string, serverName string, caPool *x509.CertPool) (TLSProbeResult, error)
	ListenProbe       func(ctx context.Context, network, addr string) (net.Listener, error)
}

// Run executes all applicable pre-flight routing, hairpin, forwarding, reachability, bind,
// X.509 SAN/expiry, and CRL freshness checks and returns a structured Report.
func Run(ctx context.Context, opts Options) Report {
	if ctx == nil {
		ctx = context.Background()
	}

	nowFn := opts.Now
	if nowFn == nil {
		nowFn = func() time.Time { return time.Now().UTC() }
	}
	now := nowFn().UTC()

	provider := opts.InterfaceProvider
	if provider == nil {
		provider = netbind.OSInterfaceProvider()
	}

	routeFn := opts.RouteSourceIP
	if routeFn == nil {
		routeFn = netbind.DiscoverUDPRouteSourceIP
	}

	fwdFn := opts.ForwardingProbe
	if fwdFn == nil {
		fwdFn = detectPlatformIPv4Forwarding
	}

	seeds, seedParseErr := normalizeSeeds(opts.Seeds)

	var checks []CheckResult

	// 1. Outbound LAN Hairpin Route Check (`tailscale --accept-routes` hijacking local physical LAN subnet).
	checks = append(checks, checkRouteHairpin(seeds, seedParseErr, provider, routeFn))

	// 2. IPv4 Forwarding / Weak-Host Asymmetric Routing Check.
	checks = append(checks, checkIPv4Forwarding(provider, fwdFn))

	// 3. Optional Seed TCP + TLS 1.3 Reachability Check.
	if len(opts.Seeds) > 0 && hasNonEmptyTokens(opts.Seeds) {
		checks = append(checks, checkSeedReachability(ctx, seeds, seedParseErr, opts, now))
	}

	// 4. Optional Bind Port Availability Check (skipped when daemon is already running).
	if !opts.DaemonRunning && (hasNonEmptyTokens(opts.BindSpecs) || hasNonEmptyTokens(opts.ClusterBindSpecs)) {
		checks = append(checks, checkBindAvailability(ctx, opts, provider))
	}

	// 5. Optional X.509 Leaf Certificate SAN Completeness & Expiry Check.
	if strings.TrimSpace(opts.CertPath) != "" {
		checks = append(checks, checkCertSANsAndExpiry(opts, provider, now))
	}

	// 6. Optional CRL Signature & Freshness Check.
	if strings.TrimSpace(opts.CRLPath) != "" {
		checks = append(checks, checkCRLFreshness(opts, now))
	}

	return Report{
		Checks:      checks,
		GeneratedAt: now,
	}
}

func checkRouteHairpin(
	seeds []string,
	seedParseErr error,
	provider netbind.InterfaceProvider,
	routeFn func(seedAddr string) (net.IP, error),
) CheckResult {
	if seedParseErr != nil {
		return CheckResult{
			ID:          CheckIDRouteHairpin,
			Status:      StatusFail,
			Summary:     fmt.Sprintf("Invalid seed address configuration: %v", seedParseErr),
			Remediation: "Pass valid host:port or IP seed addresses to --join (e.g. 100.64.0.10:8444 or 192.168.1.10:8444).",
		}
	}

	if len(seeds) > 0 {
		var summaries []string
		for _, seed := range seeds {
			finding, egressIP, err := netbind.DetectOutboundLANHairpin(seed, provider, routeFn)
			if err != nil {
				return CheckResult{
					ID:          CheckIDRouteHairpin,
					Status:      StatusFail,
					Summary:     fmt.Sprintf("UDP route lookup toward seed %s failed: %v", seed, err),
					Remediation: "Verify local network interface configuration and routing table entries toward the target seed.",
				}
			}
			if finding != nil {
				return CheckResult{
					ID:     CheckIDRouteHairpin,
					Status: StatusFail,
					Summary: fmt.Sprintf(
						"Outbound LAN hairpin detected toward seed %s: target IP %s belongs to attached physical interface %q (%s), yet kernel UDP egress selected Tailscale CGNAT IP %s",
						finding.SeedAddr, finding.SeedIP, finding.AttachedInterface, finding.AttachedSubnet, finding.SelectedEgressIP,
					),
					Remediation: "Run 'tailscale set --accept-routes=false' on this host, or connect using the seed's Tailscale 100.x address instead of its physical LAN IP.",
				}
			}
			summaries = append(summaries, fmt.Sprintf("%s via %s", seed, egressIP))
		}
		return CheckResult{
			ID:      CheckIDRouteHairpin,
			Status:  StatusPass,
			Summary: fmt.Sprintf("Verified direct non-hairpinned route egress (%s)", strings.Join(summaries, ", ")),
		}
	}

	// No explicit seeds provided: proactively probe attached physical IPv4 subnets to catch active
	// Tailscale --accept-routes LAN hijacks during standalone `agent-bridge doctor` runs.
	ifaces, err := provider.Interfaces()
	if err != nil {
		return CheckResult{
			ID:          CheckIDRouteHairpin,
			Status:      StatusWarn,
			Summary:     fmt.Sprintf("Unable to enumerate network interfaces for LAN hairpin inspection: %v", err),
			Remediation: "Check OS network interface permissions and state.",
		}
	}

	probedSubnets := 0
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if netbind.IsEphemeralBridgeInterface(iface.Name) || netbind.IsTailscaleInterface(iface) {
			continue
		}
		for _, addr := range iface.Addrs {
			probeTarget := syntheticSubnetNeighborTarget(addr)
			if probeTarget == "" {
				continue
			}
			probedSubnets++
			finding, _, routeErr := netbind.DetectOutboundLANHairpin(probeTarget, provider, routeFn)
			if routeErr == nil && finding != nil {
				return CheckResult{
					ID:     CheckIDRouteHairpin,
					Status: StatusFail,
					Summary: fmt.Sprintf(
						"Outbound LAN hairpin detected on local subnet %s (interface %q): kernel UDP egress selected Tailscale CGNAT IP %s",
						finding.AttachedSubnet, finding.AttachedInterface, finding.SelectedEgressIP,
					),
					Remediation: "Run 'tailscale set --accept-routes=false' so attached physical LAN subnets are not hijacked into Tailscale.",
				}
			}
		}
	}

	if probedSubnets > 0 {
		return CheckResult{
			ID:      CheckIDRouteHairpin,
			Status:  StatusPass,
			Summary: fmt.Sprintf("No outbound Tailscale LAN hairpin detected across %d attached physical IPv4 subnet(s)", probedSubnets),
		}
	}
	return CheckResult{
		ID:      CheckIDRouteHairpin,
		Status:  StatusPass,
		Summary: "No outbound LAN hairpin detected",
	}
}

func syntheticSubnetNeighborTarget(addr net.Addr) string {
	ipNet, ok := addr.(*net.IPNet)
	if !ok || ipNet == nil || ipNet.IP == nil || ipNet.Mask == nil {
		return ""
	}
	ip4 := ipNet.IP.To4()
	if ip4 == nil || ip4.IsLoopback() || ip4.IsUnspecified() || ip4.IsLinkLocalUnicast() || netbind.IsCGNAT(ip4) {
		return ""
	}
	ones, bits := ipNet.Mask.Size()
	if bits != 32 || ones <= 0 || ones > 30 {
		return ""
	}
	netBase := ip4.Mask(ipNet.Mask).To4()
	if netBase == nil {
		return ""
	}
	candidate := make(net.IP, 4)
	copy(candidate, netBase)
	candidate[3] |= 1
	if candidate.Equal(ip4) {
		copy(candidate, netBase)
		candidate[3] |= 2
	}
	if candidate.Equal(ip4) || !ipNet.Contains(candidate) {
		return ""
	}
	return net.JoinHostPort(candidate.String(), strconv.Itoa(config.DefaultClusterPort))
}

func checkIPv4Forwarding(provider netbind.InterfaceProvider, fwdFn ForwardingProbeFunc) CheckResult {
	ifaces, err := provider.Interfaces()
	if err != nil {
		return CheckResult{
			ID:          CheckIDIPv4Forwarding,
			Status:      StatusWarn,
			Summary:     fmt.Sprintf("Could not inspect host interfaces for asymmetric forwarding check: %v", err),
			Remediation: "Verify network interface visibility on this host.",
		}
	}

	enabled, detail, fwdErr := fwdFn(ifaces)
	if fwdErr != nil {
		return CheckResult{
			ID:          CheckIDIPv4Forwarding,
			Status:      StatusWarn,
			Summary:     fmt.Sprintf("Unable to query OS IPv4 forwarding state: %v", fwdErr),
			Remediation: "Verify kernel sysctl / registry read permissions if this node acts as a Tailscale subnet router.",
		}
	}

	hasTailscale, tsIfaces, hasPhysicalLAN, lanIfaces := classifyForwardingOverlap(ifaces)
	if !enabled {
		msg := "IPv4 packet forwarding is disabled"
		if detail != "" {
			msg = fmt.Sprintf("IPv4 packet forwarding is disabled (%s)", detail)
		}
		return CheckResult{
			ID:      CheckIDIPv4Forwarding,
			Status:  StatusPass,
			Summary: msg,
		}
	}

	if hasTailscale && hasPhysicalLAN {
		return CheckResult{
			ID:     CheckIDIPv4Forwarding,
			Status: StatusWarn,
			Summary: fmt.Sprintf(
				"IPv4 forwarding is enabled (%s) alongside both Tailscale (%s) and physical LAN (%s) interfaces; weak-host asymmetric return routing or subnet-router hairpinning can drop peer TCP handshakes",
				detail, strings.Join(tsIfaces, ", "), strings.Join(lanIfaces, ", "),
			),
			Remediation: "Bind agent-bridge explicitly to non-overlapping IPs or CIDRs (e.g. '--bind 100.64.0.0/10'), disable '--accept-routes' on peer LAN hosts, or disable IPv4 forwarding if this host is not an intentional router.",
		}
	}

	return CheckResult{
		ID:      CheckIDIPv4Forwarding,
		Status:  StatusPass,
		Summary: fmt.Sprintf("IPv4 forwarding is enabled (%s) with no overlapping Tailscale + physical LAN interface conflict", detail),
	}
}

func classifyForwardingOverlap(ifaces []netbind.InterfaceInfo) (hasTailscale bool, tsNames []string, hasPhysicalLAN bool, lanNames []string) {
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if netbind.IsEphemeralBridgeInterface(iface.Name) {
			continue
		}
		if netbind.IsTailscaleInterface(iface) {
			hasTailscale = true
			if !slices.Contains(tsNames, iface.Name) {
				tsNames = append(tsNames, iface.Name)
			}
			continue
		}
		for _, addr := range iface.Addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil {
				continue
			}
			ip4 := ip.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsUnspecified() || ip4.IsLinkLocalUnicast() || netbind.IsCGNAT(ip4) {
				continue
			}
			hasPhysicalLAN = true
			if !slices.Contains(lanNames, iface.Name) {
				lanNames = append(lanNames, iface.Name)
			}
			break
		}
	}
	return hasTailscale, tsNames, hasPhysicalLAN, lanNames
}

func checkSeedReachability(
	ctx context.Context,
	seeds []string,
	seedParseErr error,
	opts Options,
	_ time.Time,
) CheckResult {
	if seedParseErr != nil {
		return CheckResult{
			ID:          CheckIDSeedReachability,
			Status:      StatusFail,
			Summary:     fmt.Sprintf("Invalid seed peer address: %v", seedParseErr),
			Remediation: "Provide valid seed host:port addresses (e.g. 100.64.0.10:8444).",
		}
	}

	var caPool *x509.CertPool
	if caPath := strings.TrimSpace(opts.CAPath); caPath != "" {
		if _, pool, err := pki.LoadCACertPool(caPath); err == nil {
			caPool = pool
		} else if !errors.Is(err, os.ErrNotExist) {
			return CheckResult{
				ID:          CheckIDSeedReachability,
				Status:      StatusFail,
				Summary:     fmt.Sprintf("Failed to load Root CA %q for seed TLS verification: %v", caPath, err),
				Remediation: "Ensure --ca points to a valid PEM-encoded Root CA certificate.",
			}
		}
	}

	dialTimeout := opts.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = defaultSeedDialTimeout
	}

	dialFn := opts.DialTLS
	if dialFn == nil {
		dialFn = defaultTLS13SeedProbe
	}

	var reachable []string
	var failed []string
	for _, seed := range seeds {
		host, _, _ := net.SplitHostPort(seed)
		probeCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		res, err := dialFn(probeCtx, seed, host, caPool)
		cancel()
		if err != nil {
			failed = append(failed, fmt.Sprintf("%s (%v)", seed, err))
			continue
		}
		if res.TLSVersion != tls.VersionTLS13 {
			failed = append(failed, fmt.Sprintf("%s (negotiated TLS version 0x%04x, require TLS 1.3)", seed, res.TLSVersion))
			continue
		}
		if res.PeerCN != "" {
			reachable = append(reachable, fmt.Sprintf("%s [CN=%s]", seed, res.PeerCN))
		} else {
			reachable = append(reachable, seed)
		}
	}

	if len(reachable) == 0 {
		return CheckResult{
			ID:          CheckIDSeedReachability,
			Status:      StatusFail,
			Summary:     fmt.Sprintf("All %d seed peer(s) unreachable over TCP + TLS 1.3: %s", len(seeds), strings.Join(failed, "; ")),
			Remediation: "Verify the seed daemon is running with cluster mode enabled, firewall rules allow TCP port 8444, and no Tailscale LAN hairpin is active.",
		}
	}
	if len(failed) > 0 {
		return CheckResult{
			ID:          CheckIDSeedReachability,
			Status:      StatusWarn,
			Summary:     fmt.Sprintf("%d of %d seed peer(s) reachable over TLS 1.3 (%s); unreachable: %s", len(reachable), len(seeds), strings.Join(reachable, ", "), strings.Join(failed, "; ")),
			Remediation: "Check connectivity or certificate SANs on the unreachable fallback seed peer(s).",
		}
	}

	trustMode := "unverified pre-join probe"
	if caPool != nil {
		trustMode = "Root CA verified"
	}
	return CheckResult{
		ID:      CheckIDSeedReachability,
		Status:  StatusPass,
		Summary: fmt.Sprintf("Reached %d seed peer(s) over TCP + TLS 1.3 (%s): %s", len(reachable), trustMode, strings.Join(reachable, ", ")),
	}
}

func defaultTLS13SeedProbe(ctx context.Context, addr string, serverName string, caPool *x509.CertPool) (TLSProbeResult, error) {
	dialer := &net.Dialer{}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return TLSProbeResult{}, err
	}
	defer func() {
		_ = rawConn.Close()
	}()

	if deadline, ok := ctx.Deadline(); ok {
		_ = rawConn.SetDeadline(deadline)
	}

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	}
	if caPool != nil {
		tlsCfg.RootCAs = caPool
		tlsCfg.ServerName = serverName
	} else {
		// Pre-join reachability check before ca.crt has been fetched onto disk.
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // Intentional pre-bootstrap TLS 1.3 reachability probe when CAPath is absent
	}

	tlsConn := tls.Client(rawConn, tlsCfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return TLSProbeResult{}, err
	}
	state := tlsConn.ConnectionState()
	var peerCN string
	if len(state.PeerCertificates) > 0 {
		peerCN = state.PeerCertificates[0].Subject.CommonName
	}
	return TLSProbeResult{
		TLSVersion: state.Version,
		PeerCN:     peerCN,
	}, nil
}

func checkBindAvailability(ctx context.Context, opts Options, provider netbind.InterfaceProvider) CheckResult {
	listenFn := opts.ListenProbe
	if listenFn == nil {
		listenFn = func(listenCtx context.Context, network, addr string) (net.Listener, error) {
			var lc net.ListenConfig
			return lc.Listen(listenCtx, network, addr)
		}
	}

	var allTargets []netbind.BindTarget
	if hasNonEmptyTokens(opts.BindSpecs) {
		defPort := opts.DefaultPort
		if defPort <= 0 {
			defPort = protocol.DefaultPort
		}
		sels, err := netbind.ParseSpecs(opts.BindSpecs, defPort, opts.AllowPortOverride)
		if err != nil {
			return CheckResult{
				ID:          CheckIDBindAvailability,
				Status:      StatusFail,
				Summary:     fmt.Sprintf("Invalid bind selector: %v", err),
				Remediation: "Use 'all', '*', an explicit IP address, or a CIDR subnet (e.g. '100.64.0.0/10').",
			}
		}
		targets, err := netbind.ResolveTargets(sels, provider, false)
		if err != nil {
			var cidrErr *netbind.CIDRNotReadyError
			if errors.As(err, &cidrErr) {
				return CheckResult{
					ID:          CheckIDBindAvailability,
					Status:      StatusWarn,
					Summary:     fmt.Sprintf("Bind CIDR selector not currently active: %v", cidrErr),
					Remediation: "Bring up the matching network interface (e.g. Tailscale) or configure '--wait-bind 60s' for boot readiness.",
				}
			}
			return CheckResult{
				ID:          CheckIDBindAvailability,
				Status:      StatusFail,
				Summary:     fmt.Sprintf("Failed to resolve bind targets: %v", err),
				Remediation: "Verify local network interfaces and '--bind' configuration.",
			}
		}
		allTargets = append(allTargets, targets...)
	}

	if hasNonEmptyTokens(opts.ClusterBindSpecs) {
		cPort := opts.ClusterPort
		if cPort <= 0 {
			cPort = config.DefaultClusterPort
		}
		sels, err := netbind.ParseSpecs(opts.ClusterBindSpecs, cPort, true)
		if err != nil {
			return CheckResult{
				ID:          CheckIDBindAvailability,
				Status:      StatusFail,
				Summary:     fmt.Sprintf("Invalid cluster bind selector: %v", err),
				Remediation: "Use 'all:8444', an explicit IP:port, or CIDR:port in '--cluster-bind'.",
			}
		}
		targets, err := netbind.ResolveTargets(sels, provider, false)
		if err != nil {
			var cidrErr *netbind.CIDRNotReadyError
			if errors.As(err, &cidrErr) {
				return CheckResult{
					ID:          CheckIDBindAvailability,
					Status:      StatusWarn,
					Summary:     fmt.Sprintf("Cluster bind CIDR selector not currently active: %v", cidrErr),
					Remediation: "Bring up the matching network interface or configure '--wait-bind 60s' for boot readiness.",
				}
			}
			return CheckResult{
				ID:          CheckIDBindAvailability,
				Status:      StatusFail,
				Summary:     fmt.Sprintf("Failed to resolve cluster bind targets: %v", err),
				Remediation: "Verify local network interfaces and '--cluster-bind' configuration.",
			}
		}
		allTargets = append(allTargets, targets...)
	}

	var opened []net.Listener
	defer func() {
		_ = netbind.CloseListeners(opened)
	}()

	var boundAddrs []string
	for _, t := range allTargets {
		ln, err := listenFn(ctx, t.Network, t.Address)
		if err != nil {
			if t.OptionalNoIPv6 && len(opened) > 0 && isOptionalIPv6Unavailable(err) {
				continue
			}
			return CheckResult{
				ID:          CheckIDBindAvailability,
				Status:      StatusFail,
				Summary:     fmt.Sprintf("Cannot bind %s socket on %s: %v", t.Network, t.Address, err),
				Remediation: "Stop any conflicting process holding the port, verify the IP is assigned locally, or pass '--wait-bind' if waiting on boot-time interfaces.",
			}
		}
		opened = append(opened, ln)
		boundAddrs = append(boundAddrs, fmt.Sprintf("%s/%s", t.Network, ln.Addr().String()))
	}

	return CheckResult{
		ID:      CheckIDBindAvailability,
		Status:  StatusPass,
		Summary: fmt.Sprintf("Verified %d socket bind target(s) available: %s", len(boundAddrs), strings.Join(boundAddrs, ", ")),
	}
}

func isOptionalIPv6Unavailable(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "address family not supported") ||
		strings.Contains(lower, "protocol not supported") ||
		strings.Contains(lower, "cannot assign requested address") ||
		strings.Contains(lower, "can't assign requested address") ||
		strings.Contains(lower, "requested address is not valid in its context")
}

func checkCertSANsAndExpiry(opts Options, provider netbind.InterfaceProvider, now time.Time) CheckResult {
	certPath := strings.TrimSpace(opts.CertPath)
	leaf, err := pki.LoadCertificate(certPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !opts.RequirePKI {
			return CheckResult{
				ID:          CheckIDCertSANsExpiry,
				Status:      StatusWarn,
				Summary:     fmt.Sprintf("Leaf certificate %q does not exist yet (expected prior to initial cluster join)", certPath),
				Remediation: "Run 'agent-bridge run --join <seed> --join-token <token>' or 'agent-bridge pki issue' to provision node credentials.",
			}
		}
		return CheckResult{
			ID:          CheckIDCertSANsExpiry,
			Status:      StatusFail,
			Summary:     fmt.Sprintf("Failed to load leaf certificate %q: %v", certPath, err),
			Remediation: "Provision a valid X.509 certificate or re-enroll with 'agent-bridge cluster rejoin'.",
		}
	}

	if caPath := strings.TrimSpace(opts.CAPath); caPath != "" {
		caCert, _, caErr := pki.LoadCACertPool(caPath)
		if caErr != nil {
			if !errors.Is(caErr, os.ErrNotExist) || opts.RequirePKI {
				return CheckResult{
					ID:          CheckIDCertSANsExpiry,
					Status:      StatusFail,
					Summary:     fmt.Sprintf("Failed to load Root CA %q: %v", caPath, caErr),
					Remediation: "Ensure --ca points to the cluster Root CA certificate.",
				}
			}
		} else if sigErr := leaf.CheckSignatureFrom(caCert); sigErr != nil {
			return CheckResult{
				ID:          CheckIDCertSANsExpiry,
				Status:      StatusFail,
				Summary:     fmt.Sprintf("Leaf certificate %q is not signed by Root CA %q: %v", certPath, caPath, sigErr),
				Remediation: "Re-issue the certificate from the active Root CA or run 'agent-bridge cluster rejoin'.",
			}
		}
	}

	if now.Before(leaf.NotBefore) {
		return CheckResult{
			ID:          CheckIDCertSANsExpiry,
			Status:      StatusFail,
			Summary:     fmt.Sprintf("Leaf certificate (CN=%s, serial=%s) is not valid until %s (check system clock skew)", leaf.Subject.CommonName, pki.FormatSerialHex(leaf.SerialNumber), leaf.NotBefore.UTC().Format(time.RFC3339)),
			Remediation: "Synchronize system NTP clock or re-issue the node certificate with 'agent-bridge cluster rejoin'.",
		}
	}
	if !now.Before(leaf.NotAfter) {
		return CheckResult{
			ID:          CheckIDCertSANsExpiry,
			Status:      StatusFail,
			Summary:     fmt.Sprintf("Leaf certificate (CN=%s, serial=%s) expired at %s", leaf.Subject.CommonName, pki.FormatSerialHex(leaf.SerialNumber), leaf.NotAfter.UTC().Format(time.RFC3339)),
			Remediation: "Renew the node certificate with 'agent-bridge cluster rejoin' (or 'agent-bridge pki issue' on standalone/CA nodes).",
		}
	}

	// Required loopback IP SAN check (`127.0.0.1`).
	if err := leaf.VerifyHostname("127.0.0.1"); err != nil {
		return CheckResult{
			ID:          CheckIDCertSANsExpiry,
			Status:      StatusFail,
			Summary:     fmt.Sprintf("Leaf certificate (CN=%s) is missing required loopback IP SAN 127.0.0.1", leaf.Subject.CommonName),
			Remediation: "Run 'agent-bridge cluster rejoin' to re-issue the node certificate with 127.0.0.1 and active interface SANs.",
		}
	}

	// Concrete bound IP SAN checks from BindSpecs / ClusterBindSpecs.
	var concreteSpecs []string
	concreteSpecs = append(concreteSpecs, opts.BindSpecs...)
	concreteSpecs = append(concreteSpecs, opts.ClusterBindSpecs...)
	var missingBoundIPs []string
	for _, boundIP := range netbind.HarvestSelectorConcreteIPs(concreteSpecs, provider) {
		if verifyErr := leaf.VerifyHostname(boundIP); verifyErr != nil {
			missingBoundIPs = append(missingBoundIPs, boundIP)
		}
	}
	if len(missingBoundIPs) > 0 {
		return CheckResult{
			ID:          CheckIDCertSANsExpiry,
			Status:      StatusFail,
			Summary:     fmt.Sprintf("Leaf certificate (CN=%s) is missing configured bind IP SAN(s): %s", leaf.Subject.CommonName, strings.Join(missingBoundIPs, ", ")),
			Remediation: "Run 'agent-bridge cluster rejoin' so the node certificate includes all bound interface IPs.",
		}
	}

	// Active host NIC unicast IP SAN completeness check.
	activeNICIPs, _ := netbind.HarvestInterfaceIPs(provider)
	var missingNICIPs []string
	for _, nicIP := range activeNICIPs {
		if verifyErr := leaf.VerifyHostname(nicIP); verifyErr != nil {
			missingNICIPs = append(missingNICIPs, nicIP)
		}
	}
	if len(missingNICIPs) > 0 {
		status := StatusWarn
		if opts.StrictInterfaceSANs {
			status = StatusFail
		}
		return CheckResult{
			ID:          CheckIDCertSANsExpiry,
			Status:      status,
			Summary:     fmt.Sprintf("Leaf certificate (CN=%s) is missing %d active interface IP SAN(s): %s", leaf.Subject.CommonName, len(missingNICIPs), strings.Join(missingNICIPs, ", ")),
			Remediation: "Run 'agent-bridge cluster rejoin' to automatically harvest and enroll all active NIC IP SANs.",
		}
	}

	remaining := leaf.NotAfter.Sub(now)
	if remaining < certExpiryWarnWindow {
		return CheckResult{
			ID:          CheckIDCertSANsExpiry,
			Status:      StatusWarn,
			Summary:     fmt.Sprintf("Leaf certificate (CN=%s, serial=%s) expires in %d day(s) (%s)", leaf.Subject.CommonName, pki.FormatSerialHex(leaf.SerialNumber), int(remaining.Hours()/24), leaf.NotAfter.UTC().Format(time.RFC3339)),
			Remediation: "Run 'agent-bridge cluster rejoin' soon to rotate the node certificate without downtime.",
		}
	}

	return CheckResult{
		ID:     CheckIDCertSANsExpiry,
		Status: StatusPass,
		Summary: fmt.Sprintf(
			"Leaf certificate (CN=%s, serial=%s) valid until %s and covers 127.0.0.1 + %d active interface IP(s)",
			leaf.Subject.CommonName, pki.FormatSerialHex(leaf.SerialNumber), leaf.NotAfter.UTC().Format(time.RFC3339), len(activeNICIPs),
		),
	}
}

func checkCRLFreshness(opts Options, now time.Time) CheckResult {
	crlPath := strings.TrimSpace(opts.CRLPath)
	rawCRL, err := os.ReadFile(crlPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !opts.RequirePKI {
			return CheckResult{
				ID:          CheckIDCRLFreshness,
				Status:      StatusWarn,
				Summary:     fmt.Sprintf("CRL file %q does not exist yet (expected prior to initial cluster join)", crlPath),
				Remediation: "Run 'agent-bridge run --join <seed> --join-token <token>' or 'agent-bridge pki init' to initialize crl.pem.",
			}
		}
		return CheckResult{
			ID:          CheckIDCRLFreshness,
			Status:      StatusFail,
			Summary:     fmt.Sprintf("Failed to read CRL %q: %v", crlPath, err),
			Remediation: "Ensure --crl points to a readable PEM-encoded X.509 CRL file.",
		}
	}

	var crl *x509.RevocationList
	if caPath := strings.TrimSpace(opts.CAPath); caPath != "" {
		caCert, _, caErr := pki.LoadCACertPool(caPath)
		if caErr != nil {
			if !errors.Is(caErr, os.ErrNotExist) || opts.RequirePKI {
				return CheckResult{
					ID:          CheckIDCRLFreshness,
					Status:      StatusFail,
					Summary:     fmt.Sprintf("Failed to load Root CA %q for CRL verification: %v", caPath, caErr),
					Remediation: "Ensure --ca points to the matching Root CA certificate.",
				}
			}
		} else {
			verifiedCRL, verifyErr := pki.ParseAndVerifyCRL(rawCRL, caCert)
			if verifyErr != nil {
				return CheckResult{
					ID:          CheckIDCRLFreshness,
					Status:      StatusFail,
					Summary:     fmt.Sprintf("CRL %q failed signature or format verification against Root CA: %v", crlPath, verifyErr),
					Remediation: "Sync the latest cluster CRL via 'agent-bridge cluster sync' or regenerate it from the Root CA.",
				}
			}
			crl = verifiedCRL
		}
	}

	if crl == nil {
		block, _ := pem.Decode(rawCRL)
		if block == nil || block.Type != "X509 CRL" {
			return CheckResult{
				ID:          CheckIDCRLFreshness,
				Status:      StatusFail,
				Summary:     fmt.Sprintf("CRL %q does not contain a valid 'X509 CRL' PEM block", crlPath),
				Remediation: "Replace crl.pem from the cluster Root CA or run 'agent-bridge cluster sync'.",
			}
		}
		parsedCRL, parseErr := x509.ParseRevocationList(block.Bytes)
		if parseErr != nil {
			return CheckResult{
				ID:          CheckIDCRLFreshness,
				Status:      StatusFail,
				Summary:     fmt.Sprintf("Failed to parse X.509 CRL %q: %v", crlPath, parseErr),
				Remediation: "Replace crl.pem from the cluster Root CA or run 'agent-bridge cluster sync'.",
			}
		}
		crl = parsedCRL
	}

	if !crl.NextUpdate.After(now) {
		return CheckResult{
			ID:          CheckIDCRLFreshness,
			Status:      StatusFail,
			Summary:     fmt.Sprintf("CRL #%v expired at %s (NextUpdate <= now)", crl.Number, crl.NextUpdate.UTC().Format(time.RFC3339)),
			Remediation: "Refresh crl.pem on the Root CA node and propagate via 'agent-bridge cluster sync'.",
		}
	}

	rem := crl.NextUpdate.Sub(now)
	if rem < crlExpiryWarnWindow {
		return CheckResult{
			ID:          CheckIDCRLFreshness,
			Status:      StatusWarn,
			Summary:     fmt.Sprintf("CRL #%v NextUpdate expires soon (%s)", crl.Number, crl.NextUpdate.UTC().Format(time.RFC3339)),
			Remediation: "Refresh crl.pem on the Root CA node before NextUpdate elapses.",
		}
	}

	return CheckResult{
		ID:     CheckIDCRLFreshness,
		Status: StatusPass,
		Summary: fmt.Sprintf(
			"CRL #%v signature valid (%d revoked serial(s), NextUpdate %s)",
			crl.Number, len(crl.RevokedCertificateEntries), crl.NextUpdate.UTC().Format(time.RFC3339),
		),
	}
}

func normalizeSeeds(rawSeeds []string) ([]string, error) {
	var out []string
	seen := make(map[string]struct{})
	for _, entry := range rawSeeds {
		for _, tok := range strings.Split(entry, ",") {
			trimmed := strings.TrimSpace(tok)
			if trimmed == "" {
				continue
			}
			norm, _, err := config.NormalizeClusterAddr(trimmed)
			if err != nil {
				return nil, err
			}
			if _, ok := seen[norm]; !ok {
				seen[norm] = struct{}{}
				out = append(out, norm)
			}
		}
	}
	return out, nil
}

func hasNonEmptyTokens(items []string) bool {
	return len(netbind.SplitTokens(items)) > 0
}
