package doctor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/netbind"
	"github.com/kennyparsons/agent-bridge/internal/pki"
)

func mustCIDR(t *testing.T, raw string) net.Addr {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(raw)
	if err != nil {
		t.Fatalf("ParseCIDR(%s): %v", raw, err)
	}
	return &net.IPNet{IP: ip, Mask: ipNet.Mask}
}

func startTestTLS13SeedListener(t *testing.T, certPath, keyPath string) string {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	rawLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	tlsLn := tls.NewListener(rawLn, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{pair},
	})
	t.Cleanup(func() {
		_ = tlsLn.Close()
	})

	go func() {
		for {
			conn, acceptErr := tlsLn.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.SetDeadline(time.Now().Add(2 * time.Second))
					_ = tc.Handshake()
				}
			}(conn)
		}
	}()

	return rawLn.Addr().String()
}

func TestDoctorHealthyLANAndHealthyTailscale(t *testing.T) {
	caDir := filepath.Join(t.TempDir(), "ca")
	caRes, err := pki.InitCA(pki.InitCAOptions{
		OutDir:     caDir,
		CommonName: "Doctor-Test-CA",
		Org:        "AgentBridgeTest",
		Years:      5,
	})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	leafDir := filepath.Join(t.TempDir(), "leaf")
	leafRes, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:    caDir,
		OutDir:   leafDir,
		Type:     pki.TypePeer,
		Name:     "win-dc-01",
		IPs:      []string{"127.0.0.1", "192.168.1.20", "100.64.0.20", "fd7a:115c:a1e0::20"},
		DNSNames: []string{"localhost", "win-dc-01"},
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	seedAddr := startTestTLS13SeedListener(t, leafRes.CertPath, leafRes.KeyPath)

	mockIfaces := netbind.InterfaceProviderFunc(func() ([]netbind.InterfaceInfo, error) {
		return []netbind.InterfaceInfo{
			{
				Index: 2,
				Name:  "eth0",
				Flags: net.FlagUp | net.FlagBroadcast,
				Addrs: []net.Addr{mustCIDR(t, "192.168.1.20/24")},
			},
			{
				Index: 3,
				Name:  "tailscale0",
				Flags: net.FlagUp | net.FlagPointToPoint,
				Addrs: []net.Addr{
					mustCIDR(t, "100.64.0.20/10"),
					mustCIDR(t, "fd7a:115c:a1e0::20/128"),
				},
			},
			{
				Index: 4,
				Name:  "docker0",
				Flags: net.FlagUp | net.FlagBroadcast,
				Addrs: []net.Addr{mustCIDR(t, "172.17.0.1/16")},
			},
		}, nil
	})

	freeLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(free): %v", err)
	}
	freePort := freeLn.Addr().(*net.TCPAddr).Port
	_ = freeLn.Close()

	// 1. Healthy LAN route + live TLS 1.3 seed + free ephemeral bind + full SANs + fresh CRL.
	lanRep := Run(context.Background(), Options{
		Seeds:             []string{seedAddr},
		BindSpecs:         []string{"127.0.0.1"},
		DefaultPort:       freePort,
		CertPath:          leafRes.CertPath,
		CAPath:            caRes.CACertPath,
		CRLPath:           caRes.CRLPath,
		InterfaceProvider: mockIfaces,
		RouteSourceIP: func(target string) (net.IP, error) {
			if strings.HasPrefix(target, "192.168.1.") {
				return net.ParseIP("192.168.1.20").To4(), nil
			}
			return net.ParseIP("127.0.0.1").To4(), nil
		},
		ForwardingProbe: func(_ []netbind.InterfaceInfo) (bool, string, error) {
			return false, "ip_forward=0", nil
		},
	})
	if lanRep.HasFailures() || lanRep.HasWarnings() {
		raw, _ := json.MarshalIndent(lanRep, "", "  ")
		t.Fatalf("expected healthy LAN report with zero failures/warnings, got:\n%s", raw)
	}

	// Verify JSON structure round-trips cleanly.
	encoded, err := json.Marshal(lanRep)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if len(decoded.Checks) != 6 || decoded.HasFailures() {
		t.Fatalf("unexpected decoded Report: %+v", decoded)
	}

	// 2. Healthy Tailscale route (`100.64.0.20` -> `100.64.0.10:8444`).
	tsRep := Run(context.Background(), Options{
		Seeds:             []string{"100.64.0.10:8444"},
		InterfaceProvider: mockIfaces,
		RouteSourceIP: func(target string) (net.IP, error) {
			if strings.HasPrefix(target, "100.64.") {
				return net.ParseIP("100.64.0.20").To4(), nil
			}
			return net.ParseIP("192.168.1.20").To4(), nil
		},
		ForwardingProbe: func(_ []netbind.InterfaceInfo) (bool, string, error) {
			return false, "ip_forward=0", nil
		},
		DialTLS: func(_ context.Context, _ string, _ string, _ *x509.CertPool) (TLSProbeResult, error) {
			return TLSProbeResult{TLSVersion: tls.VersionTLS13, PeerCN: "node-a"}, nil
		},
	})
	if tsRep.HasFailures() || tsRep.HasWarnings() {
		t.Fatalf("expected healthy Tailscale report, got: %+v", tsRep)
	}
}

func TestDoctorDetectsTailscaleAcceptRoutesLANHairpinAndAsymmetricForwarding(t *testing.T) {
	mockIfaces := netbind.InterfaceProviderFunc(func() ([]netbind.InterfaceInfo, error) {
		return []netbind.InterfaceInfo{
			{
				Index: 2,
				Name:  "Ethernet0",
				Flags: net.FlagUp | net.FlagBroadcast,
				Addrs: []net.Addr{mustCIDR(t, "192.168.1.20/24")},
			},
			{
				Index: 5,
				Name:  "Tailscale",
				Flags: net.FlagUp | net.FlagPointToPoint,
				Addrs: []net.Addr{mustCIDR(t, "100.64.0.20/10")},
			},
		}, nil
	})

	// Simulate Tailscale `--accept-routes` hijacking local 192.168.1.0/24 traffic into 100.64.0.20
	// AND IPv4 forwarding enabled simultaneously!
	hairpinRoute := func(target string) (net.IP, error) {
		if strings.HasPrefix(target, "192.168.1.") {
			return net.ParseIP("100.64.0.20").To4(), nil
		}
		return net.ParseIP("100.64.0.20").To4(), nil
	}

	rep := Run(context.Background(), Options{
		Seeds:             []string{"192.168.1.50:8444"},
		InterfaceProvider: mockIfaces,
		RouteSourceIP:     hairpinRoute,
		ForwardingProbe: func(_ []netbind.InterfaceInfo) (bool, string, error) {
			return true, "IPEnableRouter=1", nil
		},
		DialTLS: func(_ context.Context, _ string, _ string, _ *x509.CertPool) (TLSProbeResult, error) {
			return TLSProbeResult{}, context.DeadlineExceeded
		},
	})

	if !rep.HasFailures() {
		t.Fatalf("expected HasFailures() == true on LAN hairpin, got: %+v", rep)
	}

	routeChk, ok := rep.FindCheck(CheckIDRouteHairpin)
	if !ok || routeChk.Status != StatusFail || !strings.Contains(routeChk.Remediation, "--accept-routes=false") {
		t.Fatalf("expected FAIL route_hairpin with '--accept-routes=false' remediation, got: %+v", routeChk)
	}

	fwdChk, ok := rep.FindCheck(CheckIDIPv4Forwarding)
	if !ok || fwdChk.Status != StatusWarn || !strings.Contains(fwdChk.Summary, "IPEnableRouter=1") {
		t.Fatalf("expected WARN ipv4_forwarding when forwarding enabled across Tailscale + LAN, got: %+v", fwdChk)
	}

	// Also verify standalone `doctor` (without --join Seeds) catches local subnet hairpinning!
	standaloneRep := Run(context.Background(), Options{
		InterfaceProvider: mockIfaces,
		RouteSourceIP:     hairpinRoute,
		ForwardingProbe: func(_ []netbind.InterfaceInfo) (bool, string, error) {
			return false, "IPEnableRouter=0", nil
		},
	})
	standaloneRoute, ok := standaloneRep.FindCheck(CheckIDRouteHairpin)
	if !ok || standaloneRoute.Status != StatusFail || !strings.Contains(standaloneRoute.Remediation, "--accept-routes=false") {
		t.Fatalf("expected standalone route_hairpin FAIL on hijacked attached subnet, got: %+v", standaloneRoute)
	}
}

func TestDoctorMissingSANsExpiryBindConflictAndCRLFreshness(t *testing.T) {
	caDir := filepath.Join(t.TempDir(), "ca")
	caRes, err := pki.InitCA(pki.InitCAOptions{
		OutDir:     caDir,
		CommonName: "Doctor-SAN-CA",
		Org:        "AgentBridgeTest",
		Years:      5,
	})
	if err != nil {
		t.Fatalf("InitCA: %v", err)
	}

	// Issue a certificate that ONLY includes 127.0.0.1 + 192.168.1.20 (missing Tailscale 100.64.0.20!).
	partialCert, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:    caDir,
		OutDir:   filepath.Join(t.TempDir(), "partial"),
		Type:     pki.TypePeer,
		Name:     "node-partial",
		IPs:      []string{"127.0.0.1", "192.168.1.20"},
		DNSNames: []string{"localhost"},
		Years:    1,
	})
	if err != nil {
		t.Fatalf("IssueCert(partial): %v", err)
	}

	// Issue a certificate missing 127.0.0.1 altogether.
	noLoopbackCert, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:    caDir,
		OutDir:   filepath.Join(t.TempDir(), "no-loopback"),
		Type:     pki.TypePeer,
		Name:     "node-no-loopback",
		IPs:      []string{"192.168.1.20"},
		DNSNames: []string{"localhost"},
		Years:    1,
	})
	if err != nil {
		t.Fatalf("IssueCert(no-loopback): %v", err)
	}

	mockIfaces := netbind.InterfaceProviderFunc(func() ([]netbind.InterfaceInfo, error) {
		return []netbind.InterfaceInfo{
			{
				Index: 2,
				Name:  "eth0",
				Flags: net.FlagUp | net.FlagBroadcast,
				Addrs: []net.Addr{mustCIDR(t, "192.168.1.20/24")},
			},
			{
				Index: 3,
				Name:  "tailscale0",
				Flags: net.FlagUp | net.FlagPointToPoint,
				Addrs: []net.Addr{mustCIDR(t, "100.64.0.20/10")},
			},
		}, nil
	})
	healthyRoute := func(_ string) (net.IP, error) {
		return net.ParseIP("192.168.1.20").To4(), nil
	}
	noForwarding := func(_ []netbind.InterfaceInfo) (bool, string, error) {
		return false, "0", nil
	}

	// 1. Missing active NIC SAN (`100.64.0.20`) -> WARN suggesting `agent-bridge cluster rejoin`.
	warnSANRep := Run(context.Background(), Options{
		CertPath:          partialCert.CertPath,
		CAPath:            caRes.CACertPath,
		CRLPath:           caRes.CRLPath,
		InterfaceProvider: mockIfaces,
		RouteSourceIP:     healthyRoute,
		ForwardingProbe:   noForwarding,
	})
	sanChk, ok := warnSANRep.FindCheck(CheckIDCertSANsExpiry)
	if !ok || sanChk.Status != StatusWarn || !strings.Contains(sanChk.Summary, "100.64.0.20") || !strings.Contains(sanChk.Remediation, "agent-bridge cluster rejoin") {
		t.Fatalf("expected WARN cert_sans_expiry for missing 100.64.0.20 suggesting 'agent-bridge cluster rejoin', got: %+v", sanChk)
	}

	// 2. Missing 127.0.0.1 SAN -> FAIL suggesting `agent-bridge cluster rejoin`.
	failLoopbackRep := Run(context.Background(), Options{
		CertPath:          noLoopbackCert.CertPath,
		CAPath:            caRes.CACertPath,
		InterfaceProvider: mockIfaces,
		RouteSourceIP:     healthyRoute,
		ForwardingProbe:   noForwarding,
	})
	loopChk, ok := failLoopbackRep.FindCheck(CheckIDCertSANsExpiry)
	if !ok || loopChk.Status != StatusFail || !strings.Contains(loopChk.Remediation, "agent-bridge cluster rejoin") {
		t.Fatalf("expected FAIL cert_sans_expiry when 127.0.0.1 is missing, got: %+v", loopChk)
	}

	// 3. Expired leaf certificate AND expired CRL -> both FAIL!
	futureNow := func() time.Time {
		return time.Now().UTC().Add(10 * 365 * 24 * time.Hour)
	}
	expiredRep := Run(context.Background(), Options{
		CertPath:          partialCert.CertPath,
		CAPath:            caRes.CACertPath,
		CRLPath:           caRes.CRLPath,
		Now:               futureNow,
		InterfaceProvider: mockIfaces,
		RouteSourceIP:     healthyRoute,
		ForwardingProbe:   noForwarding,
	})
	expCertChk, _ := expiredRep.FindCheck(CheckIDCertSANsExpiry)
	expCRLChk, _ := expiredRep.FindCheck(CheckIDCRLFreshness)
	if expCertChk.Status != StatusFail || expCRLChk.Status != StatusFail {
		t.Fatalf("expected expired cert and expired CRL to both FAIL, got cert=%+v crl=%+v", expCertChk, expCRLChk)
	}

	// 4. Bind port conflict (`EADDRINUSE`) -> FAIL when DaemonRunning=false, skipped when DaemonRunning=true!
	occupiedLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer func() { _ = occupiedLn.Close() }()
	occupiedPort := occupiedLn.Addr().(*net.TCPAddr).Port

	bindFailRep := Run(context.Background(), Options{
		BindSpecs:         []string{"127.0.0.1"},
		DefaultPort:       occupiedPort,
		DaemonRunning:     false,
		InterfaceProvider: mockIfaces,
		RouteSourceIP:     healthyRoute,
		ForwardingProbe:   noForwarding,
	})
	bindChk, ok := bindFailRep.FindCheck(CheckIDBindAvailability)
	if !ok || bindChk.Status != StatusFail {
		t.Fatalf("expected bind_availability FAIL on occupied port %d, got: %+v", occupiedPort, bindChk)
	}

	bindRunningRep := Run(context.Background(), Options{
		BindSpecs:         []string{"127.0.0.1"},
		DefaultPort:       occupiedPort,
		DaemonRunning:     true,
		InterfaceProvider: mockIfaces,
		RouteSourceIP:     healthyRoute,
		ForwardingProbe:   noForwarding,
	})
	if _, exists := bindRunningRep.FindCheck(CheckIDBindAvailability); exists {
		t.Fatal("expected bind_availability check to be skipped when DaemonRunning == true")
	}

	// 5. Smoke-test default OS platform forwarding probe on the current OS.
	osIfaces, _ := netbind.OSInterfaceProvider().Interfaces()
	_, _, _ = detectPlatformIPv4Forwarding(osIfaces)
}
