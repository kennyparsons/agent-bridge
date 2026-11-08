package netbind

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func testCIDRAddr(t *testing.T, cidr string) net.Addr {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	return &net.IPNet{
		IP:   ip,
		Mask: ipNet.Mask,
	}
}

type fakeListener struct {
	network string
	addr    string
	closed  atomic.Bool
}

type fakeAddr struct {
	network string
	addr    string
}

func (a fakeAddr) Network() string { return a.network }
func (a fakeAddr) String() string  { return a.addr }

func (l *fakeListener) Accept() (net.Conn, error) { return nil, errors.New("closed") }
func (l *fakeListener) Close() error {
	l.closed.Store(true)
	return nil
}
func (l *fakeListener) Addr() net.Addr {
	return fakeAddr{network: l.network, addr: l.addr}
}

func TestParseSpecsAndResolveTargets(t *testing.T) {
	mockProvider := InterfaceProviderFunc(func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{
				Name:  "lo",
				Flags: net.FlagUp | net.FlagLoopback,
				Addrs: []net.Addr{testCIDRAddr(t, "127.0.0.1/8")},
			},
			{
				Name:  "eth0",
				Flags: net.FlagUp,
				Addrs: []net.Addr{
					testCIDRAddr(t, "192.168.1.25/24"),
					testCIDRAddr(t, "169.254.12.34/16"),
					testCIDRAddr(t, "fe80::1234/64"),
				},
			},
			{
				Name:  "tailscale0",
				Flags: net.FlagUp,
				Addrs: []net.Addr{
					testCIDRAddr(t, "100.64.0.10/32"),
					testCIDRAddr(t, "fd7a:115c:a1e0::10/128"),
				},
			},
			{
				Name:  "eth1-down",
				Flags: 0,
				Addrs: []net.Addr{testCIDRAddr(t, "192.168.1.99/24")},
			},
		}, nil
	})

	t.Run("dual-stack all and asterisk", func(t *testing.T) {
		for _, spec := range []string{"all", "*"} {
			sels, err := ParseSpecs([]string{spec}, 8443, false)
			if err != nil {
				t.Fatalf("ParseSpecs(%q) failed: %v", spec, err)
			}
			targets, err := ResolveTargets(sels, mockProvider, false)
			if err != nil {
				t.Fatalf("ResolveTargets(%q) failed: %v", spec, err)
			}
			if len(targets) != 2 {
				t.Fatalf("len(targets) = %d, want 2: %+v", len(targets), targets)
			}
			if targets[0].Network != "tcp4" || targets[0].Address != "0.0.0.0:8443" || targets[0].OptionalNoIPv6 {
				t.Fatalf("unexpected tcp4 target: %+v", targets[0])
			}
			if targets[1].Network != "tcp6" || targets[1].Address != "[::]:8443" || !targets[1].OptionalNoIPv6 {
				t.Fatalf("unexpected tcp6 target: %+v", targets[1])
			}
		}
	})

	t.Run("explicit v4 and v6 wildcards", func(t *testing.T) {
		selsV4, err := ParseSpecs([]string{"0.0.0.0"}, 8443, false)
		if err != nil {
			t.Fatalf("ParseSpecs(0.0.0.0): %v", err)
		}
		tV4, err := ResolveTargets(selsV4, mockProvider, false)
		if err != nil || len(tV4) != 1 || tV4[0].Network != "tcp4" || tV4[0].Address != "0.0.0.0:8443" {
			t.Fatalf("unexpected 0.0.0.0 targets: %+v (err=%v)", tV4, err)
		}

		for _, v6Spec := range []string{"::", "[::]"} {
			selsV6, err := ParseSpecs([]string{v6Spec}, 8443, false)
			if err != nil {
				t.Fatalf("ParseSpecs(%q): %v", v6Spec, err)
			}
			tV6, err := ResolveTargets(selsV6, mockProvider, false)
			if err != nil || len(tV6) != 1 || tV6[0].Network != "tcp6" || tV6[0].Address != "[::]:8443" {
				t.Fatalf("unexpected %s targets: %+v (err=%v)", v6Spec, tV6, err)
			}
		}
	})

	t.Run("explicit IPs deduplicated in canonical form", func(t *testing.T) {
		sels, err := ParseSpecs([]string{
			"192.0.2.10, 100.64.0.10, 192.0.2.10",
			"fd7a:115c:a1e0::1, [fd7a:115c:a1e0:0:0:0:0:1]",
		}, 8443, false)
		if err != nil {
			t.Fatalf("ParseSpecs failed: %v", err)
		}
		targets, err := ResolveTargets(sels, mockProvider, false)
		if err != nil {
			t.Fatalf("ResolveTargets failed: %v", err)
		}
		var got []string
		for _, tg := range targets {
			got = append(got, tg.Network+"/"+tg.Address)
		}
		want := []string{
			"tcp4/192.0.2.10:8443",
			"tcp4/100.64.0.10:8443",
			"tcp6/[fd7a:115c:a1e0::1]:8443",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("targets = %v, want %v", got, want)
		}
	})

	t.Run("CIDR selectors skip down loopback and link-local and support auto-loopback", func(t *testing.T) {
		sels, err := ParseSpecs([]string{"192.168.1.0/24,100.64.0.0/10,169.254.0.0/16"}, 8444, true)
		if err != nil {
			t.Fatalf("ParseSpecs failed: %v", err)
		}
		// Remove 169.254.0.0/16 to test matching CIDRs cleanly, and separately verify 169.254.0.0/16 yields CIDRNotReadyError.
		selsValid, err := ParseSpecs([]string{"192.168.1.0/24,100.64.0.0/10:9444"}, 8444, true)
		if err != nil {
			t.Fatalf("ParseSpecs valid CIDRs failed: %v", err)
		}
		targets, err := ResolveTargets(selsValid, mockProvider, true)
		if err != nil {
			t.Fatalf("ResolveTargets failed: %v", err)
		}
		var got []string
		for _, tg := range targets {
			got = append(got, tg.Network+"/"+tg.Address)
		}
		want := []string{
			"tcp4/192.168.1.25:8444",
			"tcp4/100.64.0.10:9444",
			"tcp4/127.0.0.1:8444",
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("CIDR + autoLoopback targets = %v, want %v", got, want)
		}

		// Link-local 169.254.0.0/16 is skipped even when assigned on FlagUp eth0.
		_, linkLocalErr := ResolveTargets(sels, mockProvider, false)
		var notReady *CIDRNotReadyError
		if !errors.As(linkLocalErr, &notReady) || notReady.CIDR != "169.254.0.0/16" {
			t.Fatalf("expected CIDRNotReadyError on link-local CIDR, got %v", linkLocalErr)
		}
	})

	t.Run("inline port override gating and invalid selectors", func(t *testing.T) {
		if _, err := ParseSpecs([]string{"192.0.2.10:9000"}, 8443, false); err == nil {
			t.Fatal("expected error when inline port is passed with allowPortOverride=false")
		}
		sels, err := ParseSpecs([]string{"all:8444, [fd7a:115c:a1e0::1]:8445, :8446, https://192.0.2.10:8447"}, 8444, true)
		if err != nil {
			t.Fatalf("ParseSpecs with allowPortOverride=true failed: %v", err)
		}
		if len(sels) != 4 || sels[0].Port != 8444 || sels[1].Port != 8445 || sels[2].Port != 8446 || sels[3].Port != 8447 {
			t.Fatalf("unexpected parsed ports: %+v", sels)
		}

		for _, bad := range []string{"", "not-an-ip", "http://192.0.2.10:8444", "192.0.2.0/99", "192.0.2.10:99999"} {
			if _, err := ParseSpecs([]string{bad}, 8444, true); err == nil {
				t.Fatalf("expected ParseSpecs(%q) to fail", bad)
			}
		}
	})
}

func TestWaitAndBindDualStackKernelAndBootReadiness(t *testing.T) {
	t.Run("live OS kernel dual-stack all bind without EADDRINUSE", func(t *testing.T) {
		probe, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("probe listen failed: %v", err)
		}
		port := probe.Addr().(*net.TCPAddr).Port
		_ = probe.Close()

		listeners, err := WaitAndBind(context.Background(), []string{"all"}, port, false, 0)
		if err != nil {
			// Retry once with ephemeral port 0 in case another test grabbed port between close and bind.
			listeners, err = WaitAndBind(context.Background(), []string{"all"}, 0, false, 0)
			if err != nil {
				t.Fatalf("WaitAndBind(all) failed: %v", err)
			}
		}
		defer func() { _ = CloseListeners(listeners) }()

		if len(listeners) < 1 || len(listeners) > 2 {
			t.Fatalf("expected 1 or 2 listeners for dual-stack all, got %d (%v)", len(listeners), ListenerAddrs(listeners))
		}
	})

	t.Run("skips tcp6 gracefully when IPv6 stack is unavailable", func(t *testing.T) {
		listeners, err := WaitAndBindWithOptions(context.Background(), BindOptions{
			Specs:       []string{"all"},
			DefaultPort: 8443,
			Listen: func(_ context.Context, network, address string) (net.Listener, error) {
				if network == "tcp6" {
					return nil, syscall.EAFNOSUPPORT
				}
				return &fakeListener{network: network, addr: address}, nil
			},
		})
		if err != nil {
			t.Fatalf("expected graceful IPv6 fallback, got: %v", err)
		}
		defer func() { _ = CloseListeners(listeners) }()
		if len(listeners) != 1 || listeners[0].Addr().String() != "0.0.0.0:8443" {
			t.Fatalf("unexpected listeners: %v", ListenerAddrs(listeners))
		}
	})

	t.Run("polls until CIDR and EADDRNOTAVAIL become ready then binds atomically", func(t *testing.T) {
		var pollCount atomic.Int32
		provider := InterfaceProviderFunc(func() ([]InterfaceInfo, error) {
			n := pollCount.Add(1)
			if n < 3 {
				return []InterfaceInfo{}, nil
			}
			return []InterfaceInfo{
				{
					Name:  "tailscale0",
					Flags: net.FlagUp,
					Addrs: []net.Addr{testCIDRAddr(t, "100.64.0.10/32")},
				},
			}, nil
		})

		var listenAttempts atomic.Int32
		listeners, err := WaitAndBindWithOptions(context.Background(), BindOptions{
			Specs:             []string{"100.64.0.0/10, 192.0.2.10"},
			DefaultPort:       8443,
			WaitTimeout:       2 * time.Second,
			PollInterval:      20 * time.Millisecond,
			InterfaceProvider: provider,
			Listen: func(_ context.Context, network, address string) (net.Listener, error) {
				if address == "192.0.2.10:8443" && listenAttempts.Add(1) < 2 {
					return nil, syscall.EADDRNOTAVAIL
				}
				return &fakeListener{network: network, addr: address}, nil
			},
		})
		if err != nil {
			t.Fatalf("WaitAndBindWithOptions failed: %v", err)
		}
		defer func() { _ = CloseListeners(listeners) }()

		got := ListenerAddrs(listeners)
		want := []string{"100.64.0.10:8443", "192.0.2.10:8443"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("bound addrs = %v, want %v", got, want)
		}
	})

	t.Run("closes already-opened listeners if subsequent bind fails", func(t *testing.T) {
		var mu sync.Mutex
		var created []*fakeListener

		_, err := WaitAndBindWithOptions(context.Background(), BindOptions{
			Specs:       []string{"192.0.2.10, 192.0.2.11"},
			DefaultPort: 8443,
			Listen: func(_ context.Context, network, address string) (net.Listener, error) {
				if address == "192.0.2.11:8443" {
					return nil, syscall.EADDRINUSE
				}
				ln := &fakeListener{network: network, addr: address}
				mu.Lock()
				created = append(created, ln)
				mu.Unlock()
				return ln, nil
			},
		})
		if err == nil {
			t.Fatal("expected bind error when second listener fails with EADDRINUSE")
		}
		if len(created) != 1 || !created[0].closed.Load() {
			t.Fatalf("expected first listener to be closed on rollback (count=%d)", len(created))
		}
	})

	t.Run("honors context cancellation during wait loop", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Millisecond)
		defer cancel()

		_, err := WaitAndBindWithOptions(ctx, BindOptions{
			Specs:        []string{"100.64.0.0/10"},
			DefaultPort:  8443,
			WaitTimeout:  5 * time.Second,
			PollInterval: 15 * time.Millisecond,
			InterfaceProvider: InterfaceProviderFunc(func() ([]InterfaceInfo, error) {
				return nil, nil
			}),
		})
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected context.DeadlineExceeded, got %v", err)
		}
	})
}

func TestHarvestInterfaceIPsFiltersVirtualBridges(t *testing.T) {
	provider := InterfaceProviderFunc(func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{Name: "lo", Flags: net.FlagUp | net.FlagLoopback, Addrs: []net.Addr{testCIDRAddr(t, "127.0.0.1/8")}},
			{Name: "docker0", Flags: net.FlagUp, Addrs: []net.Addr{testCIDRAddr(t, "172.17.0.1/16")}},
			{Name: "br-9a8b7c", Flags: net.FlagUp, Addrs: []net.Addr{testCIDRAddr(t, "172.18.0.1/16")}},
			{Name: "veth12ab34", Flags: net.FlagUp, Addrs: []net.Addr{testCIDRAddr(t, "10.244.0.5/24")}},
			{Name: "cni0", Flags: net.FlagUp, Addrs: []net.Addr{testCIDRAddr(t, "10.88.0.1/16")}},
			{Name: "flannel.1", Flags: net.FlagUp, Addrs: []net.Addr{testCIDRAddr(t, "10.244.0.0/32")}},
			{Name: "virbr0", Flags: net.FlagUp, Addrs: []net.Addr{testCIDRAddr(t, "192.168.122.1/24")}},
			{Name: "vEthernet (WSL (Hyper-V firewall))", Flags: net.FlagUp, Addrs: []net.Addr{testCIDRAddr(t, "172.25.160.1/20")}},
			{Name: "eth0", Flags: net.FlagUp, Addrs: []net.Addr{
				testCIDRAddr(t, "192.168.1.20/24"),
				testCIDRAddr(t, "169.254.1.2/16"),
				testCIDRAddr(t, "fe80::1/64"),
			}},
			{Name: "Tailscale", Flags: net.FlagUp, Addrs: []net.Addr{
				testCIDRAddr(t, "100.64.0.20/32"),
				testCIDRAddr(t, "fd7a:115c:a1e0::20/128"),
			}},
		}, nil
	})

	got, err := HarvestInterfaceIPs(provider)
	if err != nil {
		t.Fatalf("HarvestInterfaceIPs failed: %v", err)
	}
	want := []string{"192.168.1.20", "100.64.0.20", "fd7a:115c:a1e0::20"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("HarvestInterfaceIPs = %v, want %v", got, want)
	}
}

func TestSelectCanonicalAdvertiseAddrPrecedence(t *testing.T) {
	noRoute := func(string) (net.IP, error) {
		return nil, errors.New("no route")
	}

	t.Run("explicit advertise wins and rejects wildcards", func(t *testing.T) {
		got, err := SelectCanonicalAdvertiseAddr(AdvertiseOptions{
			ExplicitAdvertise: "win-dc-01.example.internal",
			BoundAddrs:        []string{"0.0.0.0:8444"},
			DefaultPort:       8444,
			RouteSourceIP:     noRoute,
		})
		if err != nil || got != "win-dc-01.example.internal:8444" {
			t.Fatalf("got %q (err=%v), want win-dc-01.example.internal:8444", got, err)
		}

		if _, err := SelectCanonicalAdvertiseAddr(AdvertiseOptions{
			ExplicitAdvertise: "0.0.0.0:8444",
			DefaultPort:       8444,
		}); err == nil {
			t.Fatal("expected wildcard explicit advertise address to be rejected")
		}
	})

	t.Run("seed-routed local IP outranks CGNAT and RFC1918", func(t *testing.T) {
		got, err := SelectCanonicalAdvertiseAddr(AdvertiseOptions{
			BoundAddrs:   []string{"0.0.0.0:8444", "[::]:8444"},
			DefaultPort:  8444,
			SeedAddrs:    []string{"192.168.1.10:8444"},
			InterfaceIPs: []string{"100.64.0.20", "192.168.1.20", "203.0.113.20"},
			RouteSourceIP: func(seed string) (net.IP, error) {
				if seed == "192.168.1.10:8444" {
					return net.ParseIP("192.168.1.20"), nil
				}
				return nil, errors.New("unexpected seed")
			},
		})
		if err != nil || got != "192.168.1.20:8444" {
			t.Fatalf("got %q (err=%v), want 192.168.1.20:8444", got, err)
		}
	})

	t.Run("CGNAT -> RFC1918 -> Global Unicast -> 127.0.0.1 fallback chain", func(t *testing.T) {
		// CGNAT wins over RFC 1918 and Global Unicast.
		gotCGNAT, err := SelectCanonicalAdvertiseAddr(AdvertiseOptions{
			BoundAddrs:    []string{"all:8444"},
			DefaultPort:   8444,
			InterfaceIPs:  []string{"203.0.113.20", "192.168.1.20", "100.64.0.20"},
			RouteSourceIP: noRoute,
		})
		if err != nil || gotCGNAT != "100.64.0.20:8444" {
			t.Fatalf("CGNAT got %q (err=%v), want 100.64.0.20:8444", gotCGNAT, err)
		}

		// RFC 1918 wins over Global Unicast and IPv6 ULA.
		gotRFC1918, err := SelectCanonicalAdvertiseAddr(AdvertiseOptions{
			BoundAddrs:    []string{"all:8444"},
			DefaultPort:   8444,
			InterfaceIPs:  []string{"fd7a:115c:a1e0::20", "203.0.113.20", "10.10.0.5"},
			RouteSourceIP: noRoute,
		})
		if err != nil || gotRFC1918 != "10.10.0.5:8444" {
			t.Fatalf("RFC1918 got %q (err=%v), want 10.10.0.5:8444", gotRFC1918, err)
		}

		// Global unicast wins over loopback.
		gotGlobal, err := SelectCanonicalAdvertiseAddr(AdvertiseOptions{
			BoundAddrs:    []string{"all:8444"},
			DefaultPort:   8444,
			InterfaceIPs:  []string{"203.0.113.20"},
			RouteSourceIP: noRoute,
		})
		if err != nil || gotGlobal != "203.0.113.20:8444" {
			t.Fatalf("Global got %q (err=%v), want 203.0.113.20:8444", gotGlobal, err)
		}

		// Loopback fallback when no active interfaces exist.
		gotLoopback, err := SelectCanonicalAdvertiseAddr(AdvertiseOptions{
			BoundAddrs:    []string{"0.0.0.0:8444"},
			DefaultPort:   8444,
			InterfaceIPs:  []string{},
			RouteSourceIP: noRoute,
		})
		if err != nil || gotLoopback != "127.0.0.1:8444" {
			t.Fatalf("Loopback got %q (err=%v), want 127.0.0.1:8444", gotLoopback, err)
		}
	})

	t.Run("concrete bound IPs restrict advertise candidates", func(t *testing.T) {
		got, err := SelectCanonicalAdvertiseAddr(AdvertiseOptions{
			BoundAddrs:    []string{"192.168.1.20:8444", "127.0.0.1:8444"},
			DefaultPort:   8444,
			InterfaceIPs:  []string{"100.64.0.20", "192.168.1.20"},
			RouteSourceIP: noRoute,
		})
		if err != nil || got != "192.168.1.20:8444" {
			t.Fatalf("expected bound 192.168.1.20:8444 (not unbound 100.64.0.20), got %q (err=%v)", got, err)
		}

		// Single concrete loopback bound IP (like unit test 127.0.0.1:54321) stays 127.0.0.1:54321.
		gotLoop, err := SelectCanonicalAdvertiseAddr(AdvertiseOptions{
			BoundAddrs:    []string{"127.0.0.1:" + strconv.Itoa(54321)},
			DefaultPort:   8444,
			InterfaceIPs:  []string{"100.64.0.20"},
			RouteSourceIP: noRoute,
		})
		if err != nil || gotLoop != "127.0.0.1:54321" {
			t.Fatalf("expected 127.0.0.1:54321, got %q (err=%v)", gotLoop, err)
		}
	})
}

func TestDetectOutboundLANHairpin(t *testing.T) {
	provider := InterfaceProviderFunc(func() ([]InterfaceInfo, error) {
		return []InterfaceInfo{
			{
				Name:  "eth0",
				Flags: net.FlagUp,
				Addrs: []net.Addr{testCIDRAddr(t, "192.168.1.20/24")},
			},
			{
				Name:  "tailscale0",
				Flags: net.FlagUp,
				Addrs: []net.Addr{testCIDRAddr(t, "100.64.0.20/32")},
			},
		}, nil
	})

	// 1. Healthy LAN route: 192.168.1.10 uses 192.168.1.20.
	finding, egress, err := DetectOutboundLANHairpin("192.168.1.10:8444", provider, func(string) (net.IP, error) {
		return net.ParseIP("192.168.1.20"), nil
	})
	if err != nil || finding != nil || !egress.Equal(net.ParseIP("192.168.1.20")) {
		t.Fatalf("expected healthy LAN route, got finding=%+v egress=%v err=%v", finding, egress, err)
	}

	// 2. Healthy Tailscale route: 100.64.0.10 uses 100.64.0.20.
	finding, egress, err = DetectOutboundLANHairpin("100.64.0.10:8444", provider, func(string) (net.IP, error) {
		return net.ParseIP("100.64.0.20"), nil
	})
	if err != nil || finding != nil || !egress.Equal(net.ParseIP("100.64.0.20")) {
		t.Fatalf("expected healthy Tailscale route, got finding=%+v egress=%v err=%v", finding, egress, err)
	}

	// 3. Outbound LAN hairpin: 192.168.1.10 hijacked via 100.64.0.20!
	finding, _, err = DetectOutboundLANHairpin("192.168.1.10:8444", provider, func(string) (net.IP, error) {
		return net.ParseIP("100.64.0.20"), nil
	})
	if err != nil || finding == nil {
		t.Fatalf("expected hairpin finding, got finding=%+v err=%v", finding, err)
	}
	if finding.AttachedInterface != "eth0" || !strings.Contains(finding.AttachedSubnet, "192.168.1.0/24") {
		t.Fatalf("unexpected hairpin metadata: %+v", finding)
	}
}
