package netbind

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultPollInterval is the boot-readiness polling cadence used by WaitAndBind when
	// waiting for dynamic interfaces (such as tailscale0) to come up at boot.
	DefaultPollInterval = 500 * time.Millisecond
)

var (
	cgnatNet        = mustParseCIDR("100.64.0.0/10")
	tailscaleULANet = mustParseCIDR("fd7a:115c:a1e0::/48")
	ipv4LinkLocal   = mustParseCIDR("169.254.0.0/16")
	ipv6LinkLocal   = mustParseCIDR("fe80::/10")
)

func mustParseCIDR(raw string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(raw)
	if err != nil {
		panic(err)
	}
	return ipNet
}

// SelectorKind classifies a parsed bind address token.
type SelectorKind int

const (
	SelectorDualWildcard SelectorKind = iota + 1 // "all" or "*" -> tcp4 0.0.0.0 + tcp6 [::]
	SelectorIPv4Wildcard                         // "0.0.0.0" -> tcp4 0.0.0.0
	SelectorIPv6Wildcard                         // "::" or "[::]" -> tcp6 [::]
	SelectorIP                                   // Explicit IPv4 or IPv6 unicast/loopback IP
	SelectorCIDR                                 // CIDR subnet selector (e.g. 100.64.0.0/10, 192.168.1.0/24)
)

// Selector represents a validated bind selector paired with its resolved TCP port.
type Selector struct {
	Raw  string
	Kind SelectorKind
	IP   net.IP
	CIDR *net.IPNet
	Port int
}

// InterfaceInfo abstracts an OS network interface and its assigned addresses for deterministic unit testing.
type InterfaceInfo struct {
	Index int
	Name  string
	Flags net.Flags
	Addrs []net.Addr
}

// InterfaceProvider supplies the host's network interfaces.
type InterfaceProvider interface {
	Interfaces() ([]InterfaceInfo, error)
}

// InterfaceProviderFunc adapts a function to InterfaceProvider.
type InterfaceProviderFunc func() ([]InterfaceInfo, error)

// Interfaces implements InterfaceProvider.
func (f InterfaceProviderFunc) Interfaces() ([]InterfaceInfo, error) {
	return f()
}

type osInterfaceProvider struct{}

func (osInterfaceProvider) Interfaces() ([]InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	out := make([]InterfaceInfo, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, addrErr := iface.Addrs()
		if addrErr != nil {
			continue
		}
		out = append(out, InterfaceInfo{
			Index: iface.Index,
			Name:  iface.Name,
			Flags: iface.Flags,
			Addrs: addrs,
		})
	}
	return out, nil
}

// OSInterfaceProvider returns the default live OS network interface provider backed by net.Interfaces().
func OSInterfaceProvider() InterfaceProvider {
	return osInterfaceProvider{}
}

// BindTarget describes a concrete network ("tcp4" or "tcp6") and host:port socket address to bind.
type BindTarget struct {
	Network        string // "tcp4" or "tcp6"
	Address        string // Canonical host:port
	IP             net.IP
	Port           int
	OptionalNoIPv6 bool // True for the [::] leg of "all"/"*" so IPv4-only kernels still bind cleanly
}

// BindOptions configures WaitAndBindWithOptions with optional test/cluster hooks.
type BindOptions struct {
	Specs             []string
	DefaultPort       int
	AllowPortOverride bool
	WaitTimeout       time.Duration
	PollInterval      time.Duration
	AutoLoopback      bool
	InterfaceProvider InterfaceProvider
	Listen            func(ctx context.Context, network, address string) (net.Listener, error)
}

// SplitTokens splits a slice of potentially comma-separated strings into trimmed non-empty tokens.
func SplitTokens(specs []string) []string {
	var tokens []string
	for _, entry := range specs {
		for _, tok := range strings.Split(entry, ",") {
			trimmed := strings.TrimSpace(tok)
			if trimmed != "" {
				tokens = append(tokens, trimmed)
			}
		}
	}
	return tokens
}

// ContainsWildcardOrCIDR reports whether specs include "all", "*", "0.0.0.0", "::", "[::]", or a CIDR "/".
func ContainsWildcardOrCIDR(specs []string) bool {
	sels, err := ParseSpecs(specs, 1, true)
	if err != nil {
		for _, tok := range SplitTokens(specs) {
			lower := strings.ToLower(tok)
			if lower == "all" || lower == "*" || strings.Contains(lower, "/") || lower == "0.0.0.0" || lower == "::" || lower == "[::]" {
				return true
			}
		}
		return false
	}
	for _, sel := range sels {
		if sel.Kind != SelectorIP {
			return true
		}
	}
	return false
}

// ParseSpecs parses and validates comma-separated bind selectors against defaultPort.
// When allowPortOverride is true, individual tokens may include an inline `:port` suffix
// (e.g. `all:8444`, `100.64.0.10:8444`, `[fd7a:115c:a1e0::1]:8444`, `100.64.0.0/10:8444`, `:8444`).
func ParseSpecs(specs []string, defaultPort int, allowPortOverride bool) ([]Selector, error) {
	if defaultPort < 0 || defaultPort > 65535 {
		return nil, fmt.Errorf("invalid default port %d: must be between 0 and 65535", defaultPort)
	}

	tokens := SplitTokens(specs)
	if len(tokens) == 0 {
		return nil, errors.New("at least one bind address selector is required")
	}

	selectors := make([]Selector, 0, len(tokens))
	for _, rawTok := range tokens {
		sel, err := parseSingleSelector(rawTok, defaultPort, allowPortOverride)
		if err != nil {
			return nil, err
		}
		selectors = append(selectors, sel)
	}
	return selectors, nil
}

func parseSingleSelector(rawTok string, defaultPort int, allowPortOverride bool) (Selector, error) {
	working := strings.TrimSpace(rawTok)
	if working == "" {
		return Selector{}, errors.New("bind address selector cannot be empty")
	}

	if idx := strings.Index(working, "://"); idx != -1 {
		if !allowPortOverride {
			return Selector{}, fmt.Errorf("invalid bind address selector %q: URL scheme not permitted", rawTok)
		}
		scheme := strings.ToLower(strings.TrimSpace(working[:idx]))
		if scheme != "https" && scheme != "wss" {
			return Selector{}, fmt.Errorf("unsupported or insecure scheme %q in bind selector %q", scheme+"://", rawTok)
		}
		working = working[idx+3:]
		if slash := strings.IndexByte(working, '/'); slash != -1 {
			working = working[:slash]
		}
	}

	hostPart, portNum, hasInlinePort, err := splitSelectorHostPort(working, defaultPort, allowPortOverride)
	if err != nil {
		return Selector{}, err
	}
	if hasInlinePort && !allowPortOverride {
		return Selector{}, fmt.Errorf("inline port override is not allowed in bind selector %q (use --port instead)", rawTok)
	}

	lowerHost := strings.ToLower(strings.TrimSpace(hostPart))
	switch lowerHost {
	case "all", "*":
		return Selector{
			Raw:  rawTok,
			Kind: SelectorDualWildcard,
			Port: portNum,
		}, nil
	case "0.0.0.0":
		return Selector{
			Raw:  rawTok,
			Kind: SelectorIPv4Wildcard,
			IP:   net.IPv4zero,
			Port: portNum,
		}, nil
	case "::":
		return Selector{
			Raw:  rawTok,
			Kind: SelectorIPv6Wildcard,
			IP:   net.IPv6zero,
			Port: portNum,
		}, nil
	}

	if strings.Contains(hostPart, "/") {
		_, ipNet, cidrErr := net.ParseCIDR(hostPart)
		if cidrErr != nil {
			return Selector{}, fmt.Errorf("invalid CIDR bind selector %q: %w", rawTok, cidrErr)
		}
		return Selector{
			Raw:  rawTok,
			Kind: SelectorCIDR,
			CIDR: ipNet,
			Port: portNum,
		}, nil
	}

	parsedIP := net.ParseIP(hostPart)
	if parsedIP == nil {
		return Selector{}, fmt.Errorf("invalid bind address selector %q: expected 'all', '*', IP address, or CIDR subnet", rawTok)
	}
	parsedIP = canonicalIP(parsedIP)
	if parsedIP.IsUnspecified() {
		if parsedIP.To4() != nil {
			return Selector{Raw: rawTok, Kind: SelectorIPv4Wildcard, IP: net.IPv4zero, Port: portNum}, nil
		}
		return Selector{Raw: rawTok, Kind: SelectorIPv6Wildcard, IP: net.IPv6zero, Port: portNum}, nil
	}

	return Selector{
		Raw:  rawTok,
		Kind: SelectorIP,
		IP:   parsedIP,
		Port: portNum,
	}, nil
}

func splitSelectorHostPort(working string, defaultPort int, allowPortOverride bool) (host string, port int, hasInlinePort bool, err error) {
	if strings.HasPrefix(working, ":") && !strings.HasPrefix(working, "::") {
		portStr := working[1:]
		p, convErr := parsePortNumber(portStr)
		if convErr != nil {
			return "", 0, false, fmt.Errorf("invalid port in bind selector %q: %w", working, convErr)
		}
		return "0.0.0.0", p, true, nil
	}

	// Bracketed IPv6 or bracketed IPv6 CIDR: "[::]", "[fd7a:115c:a1e0::1]", "[fd7a:115c:a1e0::1]:8444", "[fd7a:115c:a1e0::/48]:8444"
	if strings.HasPrefix(working, "[") {
		if strings.HasSuffix(working, "]") {
			return working[1 : len(working)-1], defaultPort, false, nil
		}
		h, pStr, splitErr := net.SplitHostPort(working)
		if splitErr != nil {
			return "", 0, false, fmt.Errorf("invalid bracketed bind selector %q: %w", working, splitErr)
		}
		p, convErr := parsePortNumber(pStr)
		if convErr != nil {
			return "", 0, false, fmt.Errorf("invalid port %q in bind selector %q: %w", pStr, working, convErr)
		}
		return h, p, true, nil
	}

	// Unbracketed CIDR: either pure CIDR ("100.64.0.0/10", "fd7a:115c:a1e0::/48") or IPv4 CIDR with inline port ("100.64.0.0/10:8444").
	if strings.Contains(working, "/") {
		if _, _, cidrErr := net.ParseCIDR(working); cidrErr == nil {
			return working, defaultPort, false, nil
		}
		if strings.Count(working, ":") == 1 {
			idx := strings.LastIndexByte(working, ':')
			p, convErr := parsePortNumber(working[idx+1:])
			if convErr != nil {
				return "", 0, false, fmt.Errorf("invalid CIDR bind selector %q: %w", working, convErr)
			}
			return working[:idx], p, true, nil
		}
		return working, defaultPort, false, nil
	}

	// Unbracketed bare IP (must check before SplitHostPort so IPv6 literals like "fd7a:115c:a1e0::1" or "::" are not misread as host:port).
	if ip := net.ParseIP(working); ip != nil {
		return working, defaultPort, false, nil
	}

	// Single colon -> host:port (e.g. "all:8444", "*:8444", "192.0.2.10:8444", "0.0.0.0:8444").
	if strings.Count(working, ":") == 1 {
		h, pStr, splitErr := net.SplitHostPort(working)
		if splitErr != nil {
			return "", 0, false, fmt.Errorf("invalid bind selector %q: %w", working, splitErr)
		}
		p, convErr := parsePortNumber(pStr)
		if convErr != nil {
			return "", 0, false, fmt.Errorf("invalid port %q in bind selector %q: %w", pStr, working, convErr)
		}
		_ = allowPortOverride
		return h, p, true, nil
	}

	return working, defaultPort, false, nil
}

func parsePortNumber(portStr string) (int, error) {
	p, err := strconv.Atoi(strings.TrimSpace(portStr))
	if err != nil {
		return 0, err
	}
	if p < 0 || p > 65535 {
		return 0, fmt.Errorf("port %d out of range [0, 65535]", p)
	}
	return p, nil
}

// ResolveTargets expands parsed Selectors into concrete deduplicated tcp4/tcp6 BindTargets.
// If any CIDR selector matches zero active interface IPs, ResolveTargets returns a retryable
// *CIDRNotReadyError so WaitAndBind can poll until the interface comes up.
func ResolveTargets(selectors []Selector, provider InterfaceProvider, autoLoopback bool) ([]BindTarget, error) {
	if len(selectors) == 0 {
		return nil, errors.New("no bind selectors provided")
	}
	if provider == nil {
		provider = OSInterfaceProvider()
	}

	var ifaces []InterfaceInfo
	var ifacesLoaded bool
	loadIfaces := func() ([]InterfaceInfo, error) {
		if !ifacesLoaded {
			loaded, err := provider.Interfaces()
			if err != nil {
				return nil, fmt.Errorf("failed to enumerate network interfaces: %w", err)
			}
			ifaces = loaded
			ifacesLoaded = true
		}
		return ifaces, nil
	}

	wildcardV4Ports := make(map[int]bool)
	wildcardV6Ports := make(map[int]bool)
	for _, sel := range selectors {
		switch sel.Kind {
		case SelectorDualWildcard:
			wildcardV4Ports[sel.Port] = true
			wildcardV6Ports[sel.Port] = true
		case SelectorIPv4Wildcard:
			wildcardV4Ports[sel.Port] = true
		case SelectorIPv6Wildcard:
			wildcardV6Ports[sel.Port] = true
		}
	}

	var rawTargets []BindTarget
	seen := make(map[string]struct{})
	addTarget := func(t BindTarget) {
		// Suppress concrete IPs on a port already covered by a wildcard bind of the same address family
		// so combinations like "all,100.64.0.10" never trigger kernel EADDRINUSE conflicts.
		if !t.IP.IsUnspecified() {
			if t.Network == "tcp4" && wildcardV4Ports[t.Port] {
				return
			}
			if t.Network == "tcp6" && wildcardV6Ports[t.Port] {
				return
			}
		}
		key := t.Network + "|" + t.Address
		if _, exists := seen[key]; exists {
			return
		}
		seen[key] = struct{}{}
		rawTargets = append(rawTargets, t)
	}

	hasConcreteNonLoopback := false
	primaryConcretePort := 0

	for _, sel := range selectors {
		portStr := strconv.Itoa(sel.Port)
		switch sel.Kind {
		case SelectorDualWildcard:
			addTarget(BindTarget{
				Network: "tcp4",
				Address: net.JoinHostPort("0.0.0.0", portStr),
				IP:      net.IPv4zero,
				Port:    sel.Port,
			})
			addTarget(BindTarget{
				Network:        "tcp6",
				Address:        net.JoinHostPort("::", portStr),
				IP:             net.IPv6zero,
				Port:           sel.Port,
				OptionalNoIPv6: true,
			})

		case SelectorIPv4Wildcard:
			addTarget(BindTarget{
				Network: "tcp4",
				Address: net.JoinHostPort("0.0.0.0", portStr),
				IP:      net.IPv4zero,
				Port:    sel.Port,
			})

		case SelectorIPv6Wildcard:
			addTarget(BindTarget{
				Network: "tcp6",
				Address: net.JoinHostPort("::", portStr),
				IP:      net.IPv6zero,
				Port:    sel.Port,
			})

		case SelectorIP:
			netFam := ipNetworkFamily(sel.IP)
			if !sel.IP.IsLoopback() {
				hasConcreteNonLoopback = true
				if primaryConcretePort == 0 && sel.Port > 0 {
					primaryConcretePort = sel.Port
				}
			}
			addTarget(BindTarget{
				Network: netFam,
				Address: net.JoinHostPort(sel.IP.String(), portStr),
				IP:      sel.IP,
				Port:    sel.Port,
			})

		case SelectorCIDR:
			ifaceList, err := loadIfaces()
			if err != nil {
				return nil, err
			}
			matched := matchCIDRInterfaceIPs(ifaceList, sel.CIDR)
			if len(matched) == 0 {
				return nil, &CIDRNotReadyError{CIDR: sel.CIDR.String()}
			}
			for _, ip := range matched {
				netFam := ipNetworkFamily(ip)
				if !ip.IsLoopback() {
					hasConcreteNonLoopback = true
					if primaryConcretePort == 0 && sel.Port > 0 {
						primaryConcretePort = sel.Port
					}
				}
				addTarget(BindTarget{
					Network: netFam,
					Address: net.JoinHostPort(ip.String(), portStr),
					IP:      ip,
					Port:    sel.Port,
				})
			}
		}
	}

	if autoLoopback && hasConcreteNonLoopback && primaryConcretePort > 0 && !wildcardV4Ports[primaryConcretePort] {
		addTarget(BindTarget{
			Network: "tcp4",
			Address: net.JoinHostPort("127.0.0.1", strconv.Itoa(primaryConcretePort)),
			IP:      net.ParseIP("127.0.0.1").To4(),
			Port:    primaryConcretePort,
		})
	}

	if len(rawTargets) == 0 {
		return nil, errors.New("no bind targets resolved from selectors")
	}
	return rawTargets, nil
}

// CIDRNotReadyError indicates that a CIDR bind selector currently matches 0 active non-loopback interfaces.
type CIDRNotReadyError struct {
	CIDR string
}

func (e *CIDRNotReadyError) Error() string {
	return fmt.Sprintf("no active network interface IP matched CIDR selector %q", e.CIDR)
}

// WaitAndBind parses specs and binds all resolved TCP listeners atomically, optionally polling
// every 500ms up to waitTimeout when concrete interface IPs or CIDR subnets are still initializing at boot.
func WaitAndBind(
	ctx context.Context,
	specs []string,
	defaultPort int,
	allowPortOverride bool,
	waitTimeout time.Duration,
) ([]net.Listener, error) {
	return WaitAndBindWithOptions(ctx, BindOptions{
		Specs:             specs,
		DefaultPort:       defaultPort,
		AllowPortOverride: allowPortOverride,
		WaitTimeout:       waitTimeout,
	})
}

// WaitAndBindWithOptions executes WaitAndBind with injectable InterfaceProvider, Listen, PollInterval, and AutoLoopback hooks.
func WaitAndBindWithOptions(ctx context.Context, opts BindOptions) ([]net.Listener, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.WaitTimeout < 0 {
		return nil, fmt.Errorf("invalid wait-bind timeout %s: must be non-negative", opts.WaitTimeout)
	}

	selectors, err := ParseSpecs(opts.Specs, opts.DefaultPort, opts.AllowPortOverride)
	if err != nil {
		return nil, err
	}

	provider := opts.InterfaceProvider
	if provider == nil {
		provider = OSInterfaceProvider()
	}

	listenFn := opts.Listen
	if listenFn == nil {
		listenFn = func(listenCtx context.Context, network, address string) (net.Listener, error) {
			var lc net.ListenConfig
			return lc.Listen(listenCtx, network, address)
		}
	}

	pollInterval := opts.PollInterval
	if pollInterval <= 0 {
		pollInterval = DefaultPollInterval
	}

	var deadline time.Time
	if opts.WaitTimeout > 0 {
		deadline = time.Now().Add(opts.WaitTimeout)
	}

	for {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}

		listeners, retryable, bindErr := tryBindOnce(ctx, selectors, provider, listenFn, opts.AutoLoopback)
		if bindErr == nil {
			return listeners, nil
		}

		if !retryable || opts.WaitTimeout <= 0 || !time.Now().Before(deadline) {
			if opts.WaitTimeout > 0 && retryable {
				return nil, fmt.Errorf("timed out after %s waiting for network interface bind readiness: %w", opts.WaitTimeout, bindErr)
			}
			return nil, bindErr
		}

		sleepDur := pollInterval
		if rem := time.Until(deadline); rem < sleepDur {
			sleepDur = rem
		}
		if sleepDur <= 0 {
			return nil, fmt.Errorf("timed out after %s waiting for network interface bind readiness: %w", opts.WaitTimeout, bindErr)
		}

		timer := time.NewTimer(sleepDur)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func tryBindOnce(
	ctx context.Context,
	selectors []Selector,
	provider InterfaceProvider,
	listenFn func(ctx context.Context, network, address string) (net.Listener, error),
	autoLoopback bool,
) (listeners []net.Listener, retryable bool, err error) {
	targets, resolveErr := ResolveTargets(selectors, provider, autoLoopback)
	if resolveErr != nil {
		var cidrErr *CIDRNotReadyError
		if errors.As(resolveErr, &cidrErr) {
			return nil, true, resolveErr
		}
		return nil, false, resolveErr
	}

	opened := make([]net.Listener, 0, len(targets))
	closeAll := func() {
		for _, ln := range opened {
			_ = ln.Close()
		}
	}

	var resolvedDualEphemeralPort int
	for _, t := range targets {
		addr := t.Address
		// If "all" / "*" was requested with ephemeral port 0, bind tcp6 to the same ephemeral port assigned to tcp4 when possible.
		if t.OptionalNoIPv6 && t.Port == 0 && resolvedDualEphemeralPort > 0 {
			addr = net.JoinHostPort("::", strconv.Itoa(resolvedDualEphemeralPort))
		}

		ln, listenErr := listenFn(ctx, t.Network, addr)
		if listenErr != nil && t.OptionalNoIPv6 && t.Port == 0 && resolvedDualEphemeralPort > 0 && !isIPv6StackUnavailable(listenErr) {
			ln, listenErr = listenFn(ctx, t.Network, net.JoinHostPort("::", "0"))
		}
		if listenErr != nil {
			if t.OptionalNoIPv6 && isIPv6StackUnavailable(listenErr) && len(opened) > 0 {
				continue
			}
			closeAll()
			isNotAvail := !t.IP.IsUnspecified() && isAddrNotAvailError(listenErr)
			return nil, isNotAvail, fmt.Errorf("failed to bind %s listener on %s: %w", t.Network, addr, listenErr)
		}

		if t.Network == "tcp4" && t.IP.IsUnspecified() && t.Port == 0 {
			if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok && tcpAddr.Port > 0 {
				resolvedDualEphemeralPort = tcpAddr.Port
			}
		}
		opened = append(opened, ln)
	}

	if len(opened) == 0 {
		return nil, false, errors.New("failed to bind any TCP listeners")
	}
	return opened, false, nil
}

// CloseListeners closes every non-nil listener in listeners and returns the first error encountered.
func CloseListeners(listeners []net.Listener) error {
	var firstErr error
	for _, ln := range listeners {
		if ln == nil {
			continue
		}
		if err := ln.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ListenerAddrs returns the string representation of each non-nil listener's bound address.
func ListenerAddrs(listeners []net.Listener) []string {
	addrs := make([]string, 0, len(listeners))
	for _, ln := range listeners {
		if ln != nil && ln.Addr() != nil {
			addrs = append(addrs, ln.Addr().String())
		}
	}
	return addrs
}

// HarvestNodeInterfaceIPs returns canonical non-loopback, non-link-local unicast IPv4/IPv6 addresses
// from all FlagUp host interfaces, excluding ephemeral container/VM bridge interfaces.
func HarvestNodeInterfaceIPs() []string {
	ips, _ := HarvestInterfaceIPs(OSInterfaceProvider())
	return ips
}

// HarvestInterfaceIPs returns canonical non-loopback, non-link-local unicast IPv4/IPv6 addresses
// from provider's FlagUp non-loopback, non-bridge interfaces.
func HarvestInterfaceIPs(provider InterfaceProvider) ([]string, error) {
	if provider == nil {
		provider = OSInterfaceProvider()
	}
	ifaces, err := provider.Interfaces()
	if err != nil {
		return nil, err
	}

	var v4Out []string
	var v6Out []string
	seen := make(map[string]struct{})

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if IsEphemeralBridgeInterface(iface.Name) {
			continue
		}
		for _, addr := range iface.Addrs {
			ip := extractUnicastInterfaceIP(addr)
			if ip == nil {
				continue
			}
			s := ip.String()
			if _, exists := seen[s]; exists {
				continue
			}
			seen[s] = struct{}{}
			if ip.To4() != nil {
				v4Out = append(v4Out, s)
			} else {
				v6Out = append(v6Out, s)
			}
		}
	}

	return append(v4Out, v6Out...), nil
}

// HarvestSelectorConcreteIPs extracts concrete non-unspecified IP addresses referenced directly
// or via CIDR selectors in specs using provider (defaulting to OSInterfaceProvider).
func HarvestSelectorConcreteIPs(specs []string, provider InterfaceProvider) []string {
	sels, err := ParseSpecs(specs, 1, true)
	if err != nil {
		return nil
	}
	if provider == nil {
		provider = OSInterfaceProvider()
	}
	var ifaces []InterfaceInfo
	var ifacesLoaded bool

	var out []string
	seen := make(map[string]struct{})
	add := func(ip net.IP) {
		if ip == nil || ip.IsUnspecified() {
			return
		}
		c := canonicalIP(ip)
		s := c.String()
		if _, exists := seen[s]; !exists {
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}

	for _, sel := range sels {
		switch sel.Kind {
		case SelectorIP:
			add(sel.IP)
		case SelectorCIDR:
			if !ifacesLoaded {
				ifaces, _ = provider.Interfaces()
				ifacesLoaded = true
			}
			for _, ip := range matchCIDRInterfaceIPs(ifaces, sel.CIDR) {
				add(ip)
			}
		}
	}
	return out
}

// IsEphemeralBridgeInterface reports whether an interface name belongs to an ephemeral container
// or hypervisor virtual bridge (`docker*`, `br-*`, `veth*`, `cni*`, `flannel*`, `virbr*`, `vEthernet (WSL)*`).
func IsEphemeralBridgeInterface(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return false
	}
	prefixes := []string{
		"docker",
		"br-",
		"veth",
		"cni",
		"flannel",
		"virbr",
		"vethernet (wsl)",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// IsCGNAT reports whether ip belongs to RFC 6598 Carrier-Grade NAT space `100.64.0.0/10` (used by Tailscale IPv4).
func IsCGNAT(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return cgnatNet.Contains(ip4)
}

// IsTailscaleIP reports whether ip belongs to Tailscale IPv4 (`100.64.0.0/10`) or Tailscale IPv6 (`fd7a:115c:a1e0::/48`).
func IsTailscaleIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return cgnatNet.Contains(ip4)
	}
	return tailscaleULANet.Contains(ip)
}

// IsTailscaleInterface reports whether iface is a Tailscale tunnel interface by name or assigned CGNAT/ULA address.
func IsTailscaleInterface(iface InterfaceInfo) bool {
	lower := strings.ToLower(strings.TrimSpace(iface.Name))
	if strings.Contains(lower, "tailscale") {
		return true
	}
	for _, addr := range iface.Addrs {
		ip := extractUnicastInterfaceIP(addr)
		if ip != nil && IsTailscaleIP(ip) {
			return true
		}
	}
	return false
}

// AdvertiseOptions configures SelectCanonicalAdvertiseAddr.
type AdvertiseOptions struct {
	ExplicitAdvertise string
	BoundAddrs        []string
	DefaultPort       int
	SeedAddrs         []string
	InterfaceIPs      []string
	InterfaceProvider InterfaceProvider
	RouteSourceIP     func(seedAddr string) (net.IP, error)
}

// SelectCanonicalAdvertiseAddr selects a single dialable `ip:port` (or `host:port` when ExplicitAdvertise
// specifies a DNS name) to advertise to cluster peers, following strict deterministic precedence:
//  1. ExplicitAdvertise override
//  2. Seed-routed local source IP (`net.Dial("udp", seed)`)
//  3. CGNAT `100.64.0.0/10` (Tailscale IPv4)
//  4. RFC 1918 private IPv4 (`10/8`, `172.16/12`, `192.168/16`)
//  5. Global unicast (IPv4 then IPv6/ULA)
//  6. Loopback (`127.0.0.1` or `[::1]`)
func SelectCanonicalAdvertiseAddr(opts AdvertiseOptions) (string, error) {
	defaultPort := opts.DefaultPort
	if defaultPort < 0 || defaultPort > 65535 {
		return "", fmt.Errorf("invalid default advertise port %d", defaultPort)
	}

	// 1. Explicit advertise override.
	if trimmedAdv := strings.TrimSpace(opts.ExplicitAdvertise); trimmedAdv != "" {
		normAdv, err := normalizeExplicitAdvertise(trimmedAdv, defaultPort)
		if err != nil {
			return "", err
		}
		return normAdv, nil
	}

	// Inspect BoundAddrs (which may be post-Listen host:port strings OR pre-Listen bind specs).
	var (
		primaryPort    = defaultPort
		allowAnyV4     bool
		allowAnyV6     bool
		concretePortV4 = make(map[string]int)
		concretePortV6 = make(map[string]int)
		concreteOrder  []net.IP
	)

	addConcrete := func(ip net.IP, port int) {
		c := canonicalIP(ip)
		if c == nil || c.IsUnspecified() {
			return
		}
		s := c.String()
		if c.To4() != nil {
			if _, ok := concretePortV4[s]; !ok {
				concretePortV4[s] = port
				concreteOrder = append(concreteOrder, c)
			}
		} else {
			if _, ok := concretePortV6[s]; !ok {
				concretePortV6[s] = port
				concreteOrder = append(concreteOrder, c)
			}
		}
	}

	if len(opts.BoundAddrs) == 0 {
		allowAnyV4 = true
		allowAnyV6 = true
	} else {
		sels, parseErr := ParseSpecs(opts.BoundAddrs, defaultPort, true)
		if parseErr != nil {
			return "", parseErr
		}
		provider := opts.InterfaceProvider
		if provider == nil {
			provider = OSInterfaceProvider()
		}
		var cachedIfaces []InterfaceInfo
		var loadedIfaces bool

		for _, sel := range sels {
			if primaryPort == 0 && sel.Port > 0 {
				primaryPort = sel.Port
			} else if primaryPort == defaultPort && sel.Port > 0 && sel.Port != defaultPort {
				primaryPort = sel.Port
			}
			switch sel.Kind {
			case SelectorDualWildcard:
				allowAnyV4 = true
				allowAnyV6 = true
			case SelectorIPv4Wildcard:
				allowAnyV4 = true
			case SelectorIPv6Wildcard:
				allowAnyV6 = true
			case SelectorIP:
				addConcrete(sel.IP, sel.Port)
			case SelectorCIDR:
				if !loadedIfaces {
					cachedIfaces, _ = provider.Interfaces()
					loadedIfaces = true
				}
				matched := matchCIDRInterfaceIPs(cachedIfaces, sel.CIDR)
				if len(matched) == 0 {
					// Pre-bind before WaitAndBind: allow matching family from InterfaceIPs inside CIDR.
					for _, rawIP := range opts.InterfaceIPs {
						if parsed := canonicalIP(net.ParseIP(strings.TrimSpace(rawIP))); parsed != nil && sel.CIDR.Contains(parsed) {
							addConcrete(parsed, sel.Port)
						}
					}
				} else {
					for _, ip := range matched {
						addConcrete(ip, sel.Port)
					}
				}
			}
		}
	}

	var ifaceIPs []net.IP
	rawIfaceStrings := opts.InterfaceIPs
	if rawIfaceStrings == nil && (allowAnyV4 || allowAnyV6) {
		if opts.InterfaceProvider != nil {
			rawIfaceStrings, _ = HarvestInterfaceIPs(opts.InterfaceProvider)
		} else {
			rawIfaceStrings = HarvestNodeInterfaceIPs()
		}
	}
	for _, s := range rawIfaceStrings {
		if parsed := canonicalIP(net.ParseIP(strings.TrimSpace(s))); parsed != nil && !parsed.IsUnspecified() {
			ifaceIPs = append(ifaceIPs, parsed)
		}
	}

	isEligible := func(ip net.IP) (int, bool) {
		c := canonicalIP(ip)
		if c == nil || c.IsUnspecified() {
			return 0, false
		}
		s := c.String()
		if c.To4() != nil {
			if p, ok := concretePortV4[s]; ok {
				return fallbackPort(p, primaryPort), true
			}
			if allowAnyV4 {
				return primaryPort, true
			}
			return 0, false
		}
		if p, ok := concretePortV6[s]; ok {
			return fallbackPort(p, primaryPort), true
		}
		if allowAnyV6 {
			return primaryPort, true
		}
		return 0, false
	}

	// Build ordered candidate pool from concrete bound IPs + harvested active interface IPs.
	var candidates []net.IP
	candSeen := make(map[string]struct{})
	appendCandidate := func(ip net.IP) {
		c := canonicalIP(ip)
		if c == nil || c.IsUnspecified() {
			return
		}
		if _, ok := isEligible(c); !ok {
			return
		}
		s := c.String()
		if _, exists := candSeen[s]; !exists {
			candSeen[s] = struct{}{}
			candidates = append(candidates, c)
		}
	}
	for _, ip := range concreteOrder {
		appendCandidate(ip)
	}
	for _, ip := range ifaceIPs {
		appendCandidate(ip)
	}

	// 2. Seed-routed local source IP via pure-Go UDP dial lookup.
	routeFn := opts.RouteSourceIP
	if routeFn == nil {
		routeFn = DiscoverUDPRouteSourceIP
	}
	for _, seedTok := range SplitTokens(opts.SeedAddrs) {
		seedDial := normalizeSeedDialTarget(seedTok, fallbackPort(primaryPort, 8444))
		if seedDial == "" {
			continue
		}
		seedHost, _, _ := net.SplitHostPort(seedDial)
		seedIP := net.ParseIP(seedHost)
		seedIsLoopback := seedIP != nil && seedIP.IsLoopback()

		srcIP, routeErr := routeFn(seedDial)
		if routeErr != nil || srcIP == nil {
			continue
		}
		srcIP = canonicalIP(srcIP)
		if srcIP == nil || srcIP.IsUnspecified() {
			continue
		}
		if srcIP.IsLoopback() && !seedIsLoopback {
			continue
		}
		if port, ok := isEligible(srcIP); ok {
			return net.JoinHostPort(srcIP.String(), strconv.Itoa(port)), nil
		}
	}

	// 3. CGNAT 100.64.0.0/10 (Tailscale IPv4).
	for _, ip := range candidates {
		if IsCGNAT(ip) {
			port, _ := isEligible(ip)
			return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
		}
	}

	// 4. RFC 1918 Private IPv4 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
	for _, ip := range candidates {
		if ip.To4() != nil && ip.IsPrivate() {
			port, _ := isEligible(ip)
			return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
		}
	}

	// 5a. Global Unicast IPv4.
	for _, ip := range candidates {
		if ip.To4() != nil && ip.IsGlobalUnicast() && !ip.IsLoopback() {
			port, _ := isEligible(ip)
			return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
		}
	}

	// 5b. Global / ULA Unicast IPv6 (e.g. Tailscale fd7a:115c:a1e0::/48 or public IPv6).
	for _, ip := range candidates {
		if ip.To4() == nil && ip.IsGlobalUnicast() && !ip.IsLoopback() {
			port, _ := isEligible(ip)
			return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
		}
	}

	// 6. Loopback fallback (concrete bound loopback first, then 127.0.0.1 or ::1).
	for _, ip := range candidates {
		if ip.IsLoopback() {
			port, _ := isEligible(ip)
			return net.JoinHostPort(ip.String(), strconv.Itoa(port)), nil
		}
	}
	if !allowAnyV4 && (allowAnyV6 || len(concretePortV6) > 0) && len(concretePortV4) == 0 {
		return net.JoinHostPort("::1", strconv.Itoa(primaryPort)), nil
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(primaryPort)), nil
}

// DiscoverUDPRouteSourceIP performs a zero-packet kernel routing lookup via net.Dial("udp", targetAddr)
// to determine which local interface IP the OS kernel selects to reach targetAddr.
func DiscoverUDPRouteSourceIP(targetAddr string) (net.IP, error) {
	conn, err := net.Dial("udp", targetAddr)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.Close()
	}()
	udpAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || udpAddr == nil || udpAddr.IP == nil {
		return nil, fmt.Errorf("unexpected local UDP address %v for target %s", conn.LocalAddr(), targetAddr)
	}
	return canonicalIP(udpAddr.IP), nil
}

// HairpinFinding describes an outbound LAN hairpin route anomaly where a seed IP on an attached
// physical LAN subnet is hijacked into a Tailscale CGNAT tunnel (`100.64.0.0/10`) by `--accept-routes`.
type HairpinFinding struct {
	SeedAddr          string
	SeedIP            net.IP
	AttachedInterface string
	AttachedSubnet    string
	SelectedEgressIP  net.IP
}

// DetectOutboundLANHairpin checks whether kernel UDP routing toward seedAddr selects a Tailscale
// CGNAT (`100.64.0.0/10`) source IP even though seedAddr's IP belongs directly to an attached
// FlagUp physical (non-Tailscale) interface subnet.
func DetectOutboundLANHairpin(
	seedAddr string,
	provider InterfaceProvider,
	routeFn func(targetAddr string) (net.IP, error),
) (*HairpinFinding, net.IP, error) {
	dialAddr := normalizeSeedDialTarget(seedAddr, 8444)
	if dialAddr == "" {
		return nil, nil, fmt.Errorf("invalid seed address %q", seedAddr)
	}
	host, _, err := net.SplitHostPort(dialAddr)
	if err != nil {
		return nil, nil, err
	}

	if provider == nil {
		provider = OSInterfaceProvider()
	}
	if routeFn == nil {
		routeFn = DiscoverUDPRouteSourceIP
	}

	egressIP, err := routeFn(dialAddr)
	if err != nil {
		return nil, nil, err
	}
	egressIP = canonicalIP(egressIP)

	seedIP := canonicalIP(net.ParseIP(host))
	if seedIP == nil || seedIP.To4() == nil {
		return nil, egressIP, nil
	}
	if !IsCGNAT(egressIP) {
		return nil, egressIP, nil
	}

	ifaces, err := provider.Interfaces()
	if err != nil {
		return nil, egressIP, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if IsEphemeralBridgeInterface(iface.Name) || IsTailscaleInterface(iface) {
			continue
		}
		for _, addr := range iface.Addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet == nil || ipNet.IP == nil || ipNet.Mask == nil {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsUnspecified() || ipv4LinkLocal.Contains(ip4) || IsCGNAT(ip4) {
				continue
			}
			ones, bits := ipNet.Mask.Size()
			if bits != 32 || ones <= 0 || ones >= 32 {
				continue
			}
			maskedNet := &net.IPNet{
				IP:   ip4.Mask(ipNet.Mask),
				Mask: ipNet.Mask,
			}
			if maskedNet.Contains(seedIP) {
				return &HairpinFinding{
					SeedAddr:          dialAddr,
					SeedIP:            seedIP,
					AttachedInterface: iface.Name,
					AttachedSubnet:    maskedNet.String(),
					SelectedEgressIP:  egressIP,
				}, egressIP, nil
			}
		}
	}

	return nil, egressIP, nil
}

func normalizeExplicitAdvertise(raw string, defaultPort int) (string, error) {
	working := strings.TrimSpace(raw)
	if idx := strings.Index(working, "://"); idx != -1 {
		scheme := strings.ToLower(strings.TrimSpace(working[:idx]))
		if scheme != "https" && scheme != "wss" {
			return "", fmt.Errorf("unsupported or insecure scheme %q in advertise address %q", scheme+"://", raw)
		}
		working = working[idx+3:]
	}
	if slash := strings.IndexByte(working, '/'); slash != -1 {
		working = working[:slash]
	}

	var host, portStr string
	if strings.HasPrefix(working, "[") {
		if strings.HasSuffix(working, "]") {
			host = working[1 : len(working)-1]
			portStr = strconv.Itoa(defaultPort)
		} else {
			h, p, err := net.SplitHostPort(working)
			if err != nil {
				return "", fmt.Errorf("invalid advertise address %q: %w", raw, err)
			}
			host, portStr = h, p
		}
	} else if ip := net.ParseIP(working); ip != nil {
		host = canonicalIP(ip).String()
		portStr = strconv.Itoa(defaultPort)
	} else if strings.Count(working, ":") == 0 {
		host = working
		portStr = strconv.Itoa(defaultPort)
	} else {
		h, p, err := net.SplitHostPort(working)
		if err != nil {
			return "", fmt.Errorf("invalid advertise address %q: %w", raw, err)
		}
		host, portStr = h, p
	}

	host = strings.TrimSpace(host)
	lowerHost := strings.ToLower(host)
	if host == "" || lowerHost == "all" || lowerHost == "*" || strings.Contains(host, "/") {
		return "", fmt.Errorf("advertise address %q must be a concrete IP or DNS hostname, not a wildcard or CIDR", raw)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() {
			return "", fmt.Errorf("advertise address %q cannot be an unspecified wildcard IP (%s)", raw, ip.String())
		}
		host = canonicalIP(ip).String()
	}

	portNum, err := parsePortNumber(portStr)
	if err != nil {
		return "", fmt.Errorf("invalid port %q in advertise address %q: %w", portStr, raw, err)
	}
	return net.JoinHostPort(host, strconv.Itoa(portNum)), nil
}

func normalizeSeedDialTarget(raw string, defaultPort int) string {
	working := strings.TrimSpace(raw)
	if working == "" {
		return ""
	}
	if idx := strings.Index(working, "://"); idx != -1 {
		working = working[idx+3:]
	}
	if slash := strings.IndexByte(working, '/'); slash != -1 {
		working = working[:slash]
	}
	if strings.HasPrefix(working, "[") {
		if strings.HasSuffix(working, "]") {
			return net.JoinHostPort(working[1:len(working)-1], strconv.Itoa(defaultPort))
		}
		if h, p, err := net.SplitHostPort(working); err == nil {
			return net.JoinHostPort(h, p)
		}
		return ""
	}
	if ip := net.ParseIP(working); ip != nil {
		return net.JoinHostPort(canonicalIP(ip).String(), strconv.Itoa(defaultPort))
	}
	if strings.Count(working, ":") == 0 {
		return net.JoinHostPort(working, strconv.Itoa(defaultPort))
	}
	if h, p, err := net.SplitHostPort(working); err == nil {
		return net.JoinHostPort(h, p)
	}
	return ""
}

func matchCIDRInterfaceIPs(ifaces []InterfaceInfo, targetCIDR *net.IPNet) []net.IP {
	if targetCIDR == nil {
		return nil
	}
	var matched []net.IP
	seen := make(map[string]struct{})
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		for _, addr := range iface.Addrs {
			ip := extractUnicastInterfaceIP(addr)
			if ip == nil {
				continue
			}
			if !targetCIDR.Contains(ip) {
				continue
			}
			s := ip.String()
			if _, exists := seen[s]; exists {
				continue
			}
			seen[s] = struct{}{}
			matched = append(matched, ip)
		}
	}
	return matched
}

func extractUnicastInterfaceIP(addr net.Addr) net.IP {
	if addr == nil {
		return nil
	}
	var rawIP net.IP
	switch v := addr.(type) {
	case *net.IPNet:
		rawIP = v.IP
	case *net.IPAddr:
		rawIP = v.IP
	default:
		s := strings.TrimSpace(addr.String())
		if slash := strings.IndexByte(s, '/'); slash != -1 {
			s = s[:slash]
		}
		rawIP = net.ParseIP(s)
	}
	ip := canonicalIP(rawIP)
	if ip == nil || ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ipv4LinkLocal.Contains(ip4) {
			return nil
		}
		return ip4
	}
	if ipv6LinkLocal.Contains(ip) {
		return nil
	}
	if !ip.IsGlobalUnicast() {
		return nil
	}
	return ip
}

func canonicalIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}
	return ip.To16()
}

func ipNetworkFamily(ip net.IP) string {
	if ip != nil && ip.To4() != nil {
		return "tcp4"
	}
	return "tcp6"
}

func fallbackPort(port, fallback int) int {
	if port > 0 {
		return port
	}
	return fallback
}

func isAddrNotAvailError(err error) bool {
	if err == nil {
		return false
	}
	if platformIsAddrNotAvail(err) {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "cannot assign requested address") ||
		strings.Contains(lower, "can't assign requested address") ||
		strings.Contains(lower, "requested address is not valid in its context")
}

func isIPv6StackUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if platformIsIPv6Unsupported(err) || platformIsAddrNotAvail(err) {
		return true
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "address family not supported") ||
		strings.Contains(lower, "protocol not supported") ||
		strings.Contains(lower, "no suitable address found")
}
