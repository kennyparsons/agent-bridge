package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennyparsons/agent-bridge/cluster"
	"github.com/kennyparsons/agent-bridge/internal/acl"
	"github.com/kennyparsons/agent-bridge/internal/doctor"
	"github.com/kennyparsons/agent-bridge/internal/pki"
	"github.com/kennyparsons/agent-bridge/internal/runner"
	"github.com/kennyparsons/agent-bridge/internal/service"
	"github.com/kennyparsons/agent-bridge/internal/upgrade"
)

type mockServiceManager struct {
	mu          sync.Mutex
	installed   bool
	running     bool
	name        string
	binaryPath  string
	configPath  string
	logPath     string
	installOpts service.InstallOptions
	restarts    int
	starts      int
	stops       int
	uninstalls  int
}

func (m *mockServiceManager) Install(_ context.Context, opts service.InstallOptions) (*service.InstallResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.installOpts = opts
	m.installed = true
	m.running = opts.StartNow
	m.name = opts.Name
	m.binaryPath = opts.BinaryPath
	m.configPath = opts.ConfigPath
	if opts.Config != nil {
		m.logPath = opts.Config.LogPath
	}
	return &service.InstallResult{
		Name:        opts.Name,
		ServiceType: "mock",
		BinaryPath:  opts.BinaryPath,
		ConfigPath:  opts.ConfigPath,
		LogPath:     m.logPath,
		Started:     opts.StartNow,
	}, nil
}

func (m *mockServiceManager) Uninstall(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.uninstalls++
	m.installed = false
	m.running = false
	m.name = name
	return nil
}

func (m *mockServiceManager) Start(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.starts++
	m.running = true
	m.name = name
	return nil
}

func (m *mockServiceManager) Stop(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stops++
	m.running = false
	m.name = name
	return nil
}

func (m *mockServiceManager) Restart(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.restarts++
	m.running = true
	m.name = name
	return nil
}

func (m *mockServiceManager) Status(_ context.Context, name string) (*service.ServiceStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	state := "not-installed"
	if m.installed {
		if m.running {
			state = "running"
		} else {
			state = "stopped"
		}
	}
	n := m.name
	if n == "" {
		n = name
	}
	return &service.ServiceStatus{
		Name:        n,
		Installed:   m.installed,
		Running:     m.running,
		State:       state,
		PID:         4242,
		BinaryPath:  m.binaryPath,
		ConfigPath:  m.configPath,
		LogPath:     m.logPath,
		ServiceType: "mock",
	}, nil
}

func (m *mockServiceManager) IsManagedServiceProcess() bool {
	return false
}

func (m *mockServiceManager) RunManagedService(_ string, runFn func(ctx context.Context) int) (int, error) {
	return runFn(context.Background()), nil
}

func hasIPv6Loopback() bool {
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	_ = ln.Close()
	return true
}

type bgCLIServer struct {
	out      syncBuffer
	err      syncBuffer
	stopOnce sync.Once
	cancel   context.CancelFunc
	done     chan int
	exitCode int
}

// startBackgroundCLIServer launches `runContext` in a background goroutine and registers an
// idempotent LIFO `t.Cleanup` handler so all listeners, CRL watchers, cluster engines, and
// rotating log files are guaranteed closed BEFORE an earlier `t.TempDir()` runs `os.RemoveAll`
// (critical on Windows where open handles fail directory removal).
func startBackgroundCLIServer(t *testing.T, args []string) *bgCLIServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	srv := &bgCLIServer{
		cancel: cancel,
		done:   make(chan int, 1),
	}
	go func() {
		srv.done <- runContext(ctx, args, &srv.out, &srv.err)
	}()
	t.Cleanup(func() {
		_ = srv.stop()
	})
	return srv
}

func (s *bgCLIServer) stop() int {
	s.stopOnce.Do(func() {
		s.cancel()
		s.exitCode = <-s.done
	})
	return s.exitCode
}

func TestV020CLIHelpUsageAndVersionJSON(t *testing.T) {
	// Verify `version --json`.
	{
		var out, errBuf bytes.Buffer
		code := run([]string{"version", "--json"}, &out, &errBuf)
		if code != exitOK {
			t.Fatalf("version --json failed (code=%d): %s", code, errBuf.String())
		}
		var payload map[string]string
		if err := json.Unmarshal(out.Bytes(), &payload); err != nil {
			t.Fatalf("version --json invalid JSON: %v (%s)", err, out.String())
		}
		if payload["version"] != version {
			t.Fatalf("version --json = %q, want %q", payload["version"], version)
		}
	}

	helpCases := [][]string{
		{"service", "--help"},
		{"service", "install", "--help"},
		{"service", "uninstall", "--help"},
		{"service", "start", "--help"},
		{"service", "stop", "--help"},
		{"service", "restart", "--help"},
		{"service", "status", "--help"},
		{"service", "logs", "--help"},
		{"doctor", "--help"},
		{"ca", "bundle", "--help"},
		{"client", "--help"},
		{"client", "init", "--help"},
		{"client", "verify", "--help"},
		{"cluster", "join", "--help"},
		{"cluster", "rejoin", "--help"},
		{"health", "--help"},
		{"host", "--help"},
		{"host", "list", "--help"},
		{"host", "add", "--help"},
		{"host", "remove", "--help"},
		{"host", "set-default", "--help"},
		{"selfupgrade", "--help"},
	}
	for _, args := range helpCases {
		var out, errBuf bytes.Buffer
		code := run(args, &out, &errBuf)
		if code != exitOK {
			t.Fatalf("run(%v) exit code = %d, want 0 (stderr=%q)", args, code, errBuf.String())
		}
		if !strings.Contains(out.String(), "Usage: agent-bridge") {
			t.Fatalf("run(%v) stdout missing Usage header: %q", args, out.String())
		}
		if errBuf.Len() != 0 {
			t.Fatalf("run(%v) unexpected stderr: %q", args, errBuf.String())
		}
	}

	usageErrCases := [][]string{
		{"service"},
		{"service", "unknown"},
		{"ca", "bundle"},
		{"client"},
		{"client", "unknown"},
		{"client", "init"},
		{"cluster", "join"},
		{"host"},
		{"host", "unknown"},
		{"host", "add"},
		{"host", "remove"},
		{"host", "set-default"},
		{"selfupgrade", "--channel", "invalid-channel"},
	}
	for _, args := range usageErrCases {
		var out, errBuf bytes.Buffer
		code := run(args, &out, &errBuf)
		if code != exitUsage {
			t.Fatalf("run(%v) exit code = %d, want %d (stderr=%q)", args, code, exitUsage, errBuf.String())
		}
	}
}

func TestV020MultiBindAutoSANsBundleClientInitVerifyHostAndExec(t *testing.T) {
	tmp := t.TempDir()
	caDir := filepath.Join(tmp, "node-a-pki")
	bundleEncPath := filepath.Join(tmp, "workstation-01.enc.abbundle")
	bundlePlainPath := filepath.Join(tmp, "workstation-01.plain.abbundle")
	clientPemDir := filepath.Join(tmp, "client-pems")
	clientCfgDir := filepath.Join(tmp, "client-cfg")
	clientCfgPath := filepath.Join(clientCfgDir, "config.json")

	// 1. ca init with auto-SANs + explicit RFC 5737 SANs -> verifies initial server.crt & peer.crt.
	caInitRaw := mustRunCLI(t, []string{
		"ca", "init",
		"--out-dir", caDir,
		"--san-ip", "198.51.100.10",
		"--san-dns", "node-a.example.internal",
		"--json",
	})
	var caInitRes caInitOutput
	if err := json.Unmarshal([]byte(caInitRaw), &caInitRes); err != nil {
		t.Fatalf("unmarshal ca init --json: %v (%s)", err, caInitRaw)
	}
	if caInitRes.ServerCertPath == "" || caInitRes.PeerCertPath == "" {
		t.Fatalf("expected ca init to issue initial server.crt and peer.crt: %+v", caInitRes)
	}
	if st, err := acl.AuditPathACL(caDir, true); err != nil || !st.Secure {
		t.Fatalf("expected caDir ACL to be locked down: status=%+v err=%v", st, err)
	}
	if st, err := acl.AuditPathACL(caInitRes.ServerKeyPath, false); err != nil || !st.Secure {
		t.Fatalf("expected server.key ACL to be locked down: status=%+v err=%v", st, err)
	}

	// 2. Start multi-address server using the auto-SAN server.crt generated by `ca init`.
	execPort := freeLoopbackPort(t)
	bindSpec := "127.0.0.1"
	hasV6 := hasIPv6Loopback()
	if hasV6 {
		bindSpec = "127.0.0.1,::1"
	}
	execV4 := net.JoinHostPort("127.0.0.1", strconv.Itoa(execPort))
	execV6 := net.JoinHostPort("::1", strconv.Itoa(execPort))

	srv := startBackgroundCLIServer(t, []string{
		"server",
		"--bind", bindSpec,
		"--port", strconv.Itoa(execPort),
		"--data-dir", caDir,
	})
	waitForTCPPort(t, execV4, 5*time.Second)
	if hasV6 {
		waitForTCPPort(t, execV6, 5*time.Second)
	}

	// 3. Issue encrypted `.abbundle` + PEMs via `ca issue --bundle-out --passphrase-env`.
	t.Setenv("AB_TEST_BUNDLE_PASS", "correct-horse-battery-staple-v020")
	hostsCSV := "node-a=" + execV4
	if hasV6 {
		hostsCSV += ",node-a-v6=" + execV6
	}
	mustRunCLI(t, []string{
		"ca", "issue",
		"--ca-dir", caDir,
		"--type", "client",
		"--name", "workstation-01",
		"--out-dir", clientPemDir,
		"--bundle-out", bundleEncPath,
		"--passphrase-env", "AB_TEST_BUNDLE_PASS",
		"--hosts", hostsCSV,
		"--default-host", "node-a",
		"--json",
	})

	// Also verify `ca bundle` packages existing PEMs cleanly.
	mustRunCLI(t, []string{
		"ca", "bundle",
		"--ca", filepath.Join(caDir, pki.CACertFilename),
		"--cert", filepath.Join(clientPemDir, pki.ClientCertFilename),
		"--key", filepath.Join(clientPemDir, pki.ClientKeyFilename),
		"--out", bundlePlainPath,
		"--hosts", hostsCSV,
		"--default-host", "node-a",
		"--json",
	})

	// 4. Unpack encrypted `.abbundle` via `client init --bundle --verify --json`.
	initOutRaw := mustRunCLI(t, []string{
		"client", "init",
		"--bundle", bundleEncPath,
		"--passphrase-env", "AB_TEST_BUNDLE_PASS",
		"--config-dir", clientCfgDir,
		"--verify",
		"--json",
	})
	var initOut clientInitOutput
	if err := json.Unmarshal([]byte(initOutRaw), &initOut); err != nil {
		t.Fatalf("unmarshal client init --json: %v (%s)", err, initOutRaw)
	}
	if !initOut.Verified || !initOut.Healthy {
		t.Fatalf("expected client init --verify to report healthy: %+v", initOut)
	}
	if st, err := acl.AuditPathACL(filepath.Join(clientCfgDir, pki.ClientKeyFilename), true); err != nil || !st.Secure {
		t.Fatalf("expected installed client.key ACL to be locked down: status=%+v err=%v", st, err)
	}

	// 5. Run standalone `client verify --all --json` and `health --json` (including RFC 5737 SNI check!).
	verifyRaw := mustRunCLI(t, []string{
		"client", "verify",
		"--config", clientCfgPath,
		"--all",
		"--server-name", "198.51.100.10",
		"--json",
	})
	var verifyRep clientVerifyReport
	if err := json.Unmarshal([]byte(verifyRaw), &verifyRep); err != nil {
		t.Fatalf("unmarshal client verify --json: %v (%s)", err, verifyRaw)
	}
	if !verifyRep.Healthy || len(verifyRep.Hosts) == 0 {
		t.Fatalf("expected client verify healthy across bound endpoints: %+v", verifyRep)
	}

	mustRunCLI(t, []string{
		"health",
		"--config", clientCfgPath,
		"--host", "node-a",
		"--json",
	})

	// Negative `client verify` against an unreachable port must return non-zero.
	deadPort := freeLoopbackPort(t)
	{
		var out, errBuf bytes.Buffer
		rc := run([]string{
			"client", "verify",
			"--config", clientCfgPath,
			"--endpoint", net.JoinHostPort("127.0.0.1", strconv.Itoa(deadPort)),
			"--timeout", "2s",
			"--json",
		}, &out, &errBuf)
		if rc == exitOK {
			t.Fatalf("expected client verify against closed port to fail, got exit 0: %s", out.String())
		}
	}

	// 6. Test `host add`, `host list`, `host set-default`, `host remove`, and `exec --config`.
	mustRunCLI(t, []string{
		"host", "add", "node-alias",
		"--endpoint", execV4,
		"--timeout", "30s",
		"--config", clientCfgPath,
		"--json",
	})
	mustRunCLI(t, []string{
		"host", "set-default", "node-alias",
		"--config", clientCfgPath,
		"--json",
	})
	hostListRaw := mustRunCLI(t, []string{
		"host", "list",
		"--config", clientCfgPath,
		"--json",
	})
	if !strings.Contains(hostListRaw, `"default_host": "node-alias"`) {
		t.Fatalf("expected default_host node-alias in host list: %s", hostListRaw)
	}

	echoCmd := "echo v020-multibind-ok"
	execOut := mustRunCLI(t, []string{
		"exec",
		"--config", clientCfgPath,
		"--host", "node-alias",
		echoCmd,
	})
	if !strings.Contains(execOut, "v020-multibind-ok") {
		t.Fatalf("unexpected exec stdout: %q", execOut)
	}
	if hasV6 {
		execOutV6 := mustRunCLI(t, []string{
			"exec",
			"--config", clientCfgPath,
			"--host", "node-a-v6",
			echoCmd,
		})
		if !strings.Contains(execOutV6, "v020-multibind-ok") {
			t.Fatalf("unexpected IPv6 exec stdout: %q", execOutV6)
		}
	}

	mustRunCLI(t, []string{
		"host", "remove", "node-alias",
		"--config", clientCfgPath,
		"--json",
	})

	if code := srv.stop(); code != exitOK {
		t.Fatalf("server exited with %d: stderr=%s", code, srv.err.String())
	}
}

func TestV020ClusterJoinStatusRejoinTokenlessSANRotationAndRevokeSync(t *testing.T) {
	tmp := t.TempDir()
	nodeADir := filepath.Join(tmp, "node-a")
	nodeBDir := filepath.Join(tmp, "node-b")
	cli1Dir := filepath.Join(tmp, "client-1")
	cli2Dir := filepath.Join(tmp, "client-2")

	// 1. Initialize CA + seed node-a credentials.
	mustRunCLI(t, []string{
		"ca", "init",
		"--out-dir", nodeADir,
		"--common-name", "Cluster-Root-CA",
	})
	mustRunCLI(t, []string{
		"ca", "issue",
		"--ca-dir", nodeADir,
		"--type", "client",
		"--name", "workstation-01",
		"--out-dir", cli1Dir,
	})
	mustRunCLI(t, []string{
		"ca", "issue",
		"--ca-dir", nodeADir,
		"--type", "client",
		"--name", "workstation-02",
		"--out-dir", cli2Dir,
	})

	execPortA := freeLoopbackPort(t)
	clusterPortA := freeLoopbackPort(t)
	execAddrA := net.JoinHostPort("127.0.0.1", strconv.Itoa(execPortA))
	clusterAddrA := net.JoinHostPort("127.0.0.1", strconv.Itoa(clusterPortA))

	// Save server.json in nodeADir so zero-flag `cluster status` / `cluster token-create --data-dir` resolves clusterAddrA!
	nodeACfgPath := filepath.Join(nodeADir, "server.json")
	if err := service.SaveServerDaemonConfig(nodeACfgPath, &service.ServerDaemonConfig{
		DataDir:          nodeADir,
		NodeID:           "node-a",
		BindSpecs:        []string{"127.0.0.1"},
		Port:             execPortA,
		ClusterEnabled:   true,
		ClusterBindSpecs: []string{clusterAddrA},
		ClusterAdvertise: clusterAddrA,
	}); err != nil {
		t.Fatalf("SaveServerDaemonConfig(node-a): %v", err)
	}

	_ = startBackgroundCLIServer(t, []string{
		"server",
		"--service-config", nodeACfgPath,
	})
	waitForTCPPort(t, execAddrA, 5*time.Second)

	// 2. Verify server-local fallback (`--data-dir` without `--cluster-addr`, `--cert`, `--key`, `--ca`).
	statusRaw := mustRunCLI(t, []string{
		"cluster", "status",
		"--data-dir", nodeADir,
		"--json",
	})
	if !strings.Contains(statusRaw, `"node_id": "node-a"`) {
		t.Fatalf("unexpected server-local cluster status: %s", statusRaw)
	}

	joinToken := strings.TrimSpace(mustRunCLI(t, []string{
		"cluster", "token-create",
		"--data-dir", nodeADir,
		"--node-id", "node-b",
		"-q",
	}))
	if !strings.HasPrefix(joinToken, "abjt1.") {
		t.Fatalf("expected abjt1 join token, got %q", joinToken)
	}

	// 3. Enroll node-b via one-shot `cluster join` (without starting daemon yet).
	execPortB := freeLoopbackPort(t)
	clusterPortB := freeLoopbackPort(t)
	execAddrB := net.JoinHostPort("127.0.0.1", strconv.Itoa(execPortB))
	clusterAddrB := net.JoinHostPort("127.0.0.1", strconv.Itoa(clusterPortB))

	joinOutRaw := mustRunCLI(t, []string{
		"cluster", "join",
		"--join", clusterAddrA,
		"--join-token", joinToken,
		"--data-dir", nodeBDir,
		"--node-id", "node-b",
		"--bind", "127.0.0.1",
		"--port", strconv.Itoa(execPortB),
		"--cluster-bind", clusterAddrB,
		"--no-auto-sans",
		"--json",
	})
	var initialJoin cluster.BootstrapJoinResult
	if err := json.Unmarshal([]byte(joinOutRaw), &initialJoin); err != nil {
		t.Fatalf("unmarshal cluster join --json: %v (%s)", err, joinOutRaw)
	}

	startNodeB := func() *bgCLIServer {
		srvB := startBackgroundCLIServer(t, []string{
			"server",
			"--bind", "127.0.0.1",
			"--port", strconv.Itoa(execPortB),
			"--cluster-bind", clusterAddrB,
			"--seed", clusterAddrA,
			"--node-id", "node-b",
			"--data-dir", nodeBDir,
		})
		waitForTCPPort(t, execAddrB, 5*time.Second)
		return srvB
	}

	srvB1 := startNodeB()

	// Verify TLS handshake asserting new IP SAN 198.51.100.25 FAILS prior to `cluster rejoin`.
	{
		var out, errBuf bytes.Buffer
		rc := run([]string{
			"client", "verify",
			"--endpoint", execAddrB,
			"--ca", filepath.Join(nodeADir, pki.CACertFilename),
			"--cert", filepath.Join(cli1Dir, pki.ClientCertFilename),
			"--key", filepath.Join(cli1Dir, pki.ClientKeyFilename),
			"--server-name", "198.51.100.25",
			"--timeout", "3s",
		}, &out, &errBuf)
		if rc == exitOK {
			t.Fatal("expected TLS verification for unprovisioned SAN 198.51.100.25 to fail before cluster rejoin")
		}
	}

	// 4. Execute live tokenless `cluster rejoin` (`POST /cluster/v1/renew`) adding `--san-ip 198.51.100.25 --revoke-old`.
	rejoinRaw := mustRunCLI(t, []string{
		"cluster", "rejoin",
		"--data-dir", nodeBDir,
		"--seed", clusterAddrA,
		"--node-id", "node-b",
		"--bind", "127.0.0.1",
		"--port", strconv.Itoa(execPortB),
		"--cluster-bind", clusterAddrB,
		"--san-ip", "198.51.100.25",
		"--revoke-old",
		"--no-restart",
		"--json",
	})
	var rejoinRes clusterRejoinOutput
	if err := json.Unmarshal([]byte(rejoinRaw), &rejoinRes); err != nil {
		t.Fatalf("unmarshal cluster rejoin --json: %v (%s)", err, rejoinRaw)
	}
	if rejoinRes.Method != "mtls-renew" {
		t.Fatalf("rejoin method = %q, want mtls-renew", rejoinRes.Method)
	}
	if rejoinRes.CertSerialHex == initialJoin.CertSerialHex {
		t.Fatalf("expected rotated certificate serial to differ from %s", initialJoin.CertSerialHex)
	}
	if !rejoinRes.OldSerialRevoked {
		t.Fatalf("expected --revoke-old to revoke old serial %s", rejoinRes.OldCertSerialHex)
	}

	// Restart node-b so it loads the rotated server.crt with 198.51.100.25 SAN.
	_ = srvB1.stop()
	_ = startNodeB()

	// 5. Verify direct TLS 1.3 handshake + `client verify` against newly added IP SAN 198.51.100.25 SUCCEEDS!
	cliTLSCert, err := tls.LoadX509KeyPair(
		filepath.Join(cli1Dir, pki.ClientCertFilename),
		filepath.Join(cli1Dir, pki.ClientKeyFilename),
	)
	if err != nil {
		t.Fatalf("LoadX509KeyPair: %v", err)
	}
	_, caPool, err := pki.LoadCACertPool(filepath.Join(nodeADir, pki.CACertFilename))
	if err != nil {
		t.Fatalf("LoadCACertPool: %v", err)
	}
	tlsConn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", execAddrB, &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      caPool,
		Certificates: []tls.Certificate{cliTLSCert},
		ServerName:   "198.51.100.25",
	})
	if err != nil {
		t.Fatalf("TLS 1.3 handshake verifying rotated SAN 198.51.100.25 failed: %v", err)
	}
	_ = tlsConn.Close()

	mustRunCLI(t, []string{
		"client", "verify",
		"--endpoint", execAddrB,
		"--ca", filepath.Join(nodeADir, pki.CACertFilename),
		"--cert", filepath.Join(cli1Dir, pki.ClientCertFilename),
		"--key", filepath.Join(cli1Dir, pki.ClientKeyFilename),
		"--server-name", "198.51.100.25",
		"--json",
	})

	// 6. Verify `ca revoke --cert <client2.crt> --sync` immediately propagates CRL to node-b.
	mustRunCLI(t, []string{
		"client", "verify",
		"--endpoint", execAddrB,
		"--ca", filepath.Join(nodeADir, pki.CACertFilename),
		"--cert", filepath.Join(cli2Dir, pki.ClientCertFilename),
		"--key", filepath.Join(cli2Dir, pki.ClientKeyFilename),
	})

	revokeRaw := mustRunCLI(t, []string{
		"ca", "revoke",
		"--ca-dir", nodeADir,
		"--cert", filepath.Join(cli2Dir, pki.ClientCertFilename),
		"--sync",
		"--data-dir", nodeADir,
		"--json",
	})
	var revokeRes caRevokeOutput
	if err := json.Unmarshal([]byte(revokeRaw), &revokeRes); err != nil {
		t.Fatalf("unmarshal ca revoke --json: %v (%s)", err, revokeRaw)
	}
	if !revokeRes.ClusterSynced {
		t.Fatalf("expected ca revoke --sync to push CRL across cluster: %+v", revokeRes)
	}

	{
		var out, errBuf bytes.Buffer
		rc := run([]string{
			"client", "verify",
			"--endpoint", execAddrB,
			"--ca", filepath.Join(nodeADir, pki.CACertFilename),
			"--cert", filepath.Join(cli2Dir, pki.ClientCertFilename),
			"--key", filepath.Join(cli2Dir, pki.ClientKeyFilename),
			"--timeout", "3s",
		}, &out, &errBuf)
		if rc == exitOK {
			t.Fatal("expected node-b to immediately reject revoked client-2 certificate after ca revoke --sync")
		}
	}
}

func TestV020DoctorPassFailAndACLAudit(t *testing.T) {
	tmp := t.TempDir()
	goodDir := filepath.Join(tmp, "good-pki")
	missingDir := filepath.Join(tmp, "missing-pki")

	mustRunCLI(t, []string{
		"ca", "init",
		"--out-dir", goodDir,
	})

	// 1. Passing `doctor --json` with locked-down PKI.
	docRaw := mustRunCLI(t, []string{
		"doctor",
		"--data-dir", goodDir,
		"--daemon-running",
		"--require-pki",
		"--json",
	})
	var rep doctor.Report
	if err := json.Unmarshal([]byte(docRaw), &rep); err != nil {
		t.Fatalf("unmarshal doctor --json: %v (%s)", err, docRaw)
	}
	if rep.HasFailures() {
		t.Fatalf("expected healthy doctor report, got: %s", docRaw)
	}
	foundACL := false
	for _, c := range rep.Checks {
		if c.ID == checkIDACLPermissions {
			foundACL = true
			if c.Status != doctor.StatusPass {
				t.Fatalf("expected acl_permissions pass, got %s (%s)", c.Status, c.Summary)
			}
		}
	}
	if !foundACL {
		t.Fatalf("doctor report missing %q check: %s", checkIDACLPermissions, docRaw)
	}

	// 2. Failing `doctor --require-pki --json` when PKI files are missing.
	{
		var out, errBuf bytes.Buffer
		rc := run([]string{
			"doctor",
			"--data-dir", missingDir,
			"--daemon-running",
			"--require-pki",
			"--json",
		}, &out, &errBuf)
		if rc == exitOK {
			t.Fatalf("expected doctor --require-pki on empty dir to fail, got exit 0: %s", out.String())
		}
	}

	// 3. On POSIX, loosening directory permissions to 0755 must fail `acl_permissions`.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(goodDir, 0o755); err != nil {
			t.Fatalf("os.Chmod(0755): %v", err)
		}
		defer func() { _ = os.Chmod(goodDir, 0o700) }()

		var out, errBuf bytes.Buffer
		rc := run([]string{
			"doctor",
			"--data-dir", goodDir,
			"--daemon-running",
			"--json",
		}, &out, &errBuf)
		if rc == exitOK {
			t.Fatalf("expected doctor to fail when data-dir is world-readable 0755: %s", out.String())
		}
		var badRep doctor.Report
		if err := json.Unmarshal(out.Bytes(), &badRep); err != nil {
			t.Fatalf("unmarshal failing doctor JSON: %v (%s)", err, out.String())
		}
		if !badRep.HasFailures() {
			t.Fatalf("expected HasFailures()=true on 0755 data-dir: %+v", badRep)
		}
	}
}

func TestV020ServiceInstallSecretFreeConfigMergeLogsAndDetachedRestart(t *testing.T) {
	mockMgr := &mockServiceManager{}
	origMgrFn := newServiceManager
	origDetachedFn := spawnDetachedRestartFn
	newServiceManager = func() service.Manager { return mockMgr }
	var detachedCalls int
	var detachedSvcName string
	spawnDetachedRestartFn = func(_ string, svcName string, _ string, _ time.Duration) error {
		detachedCalls++
		detachedSvcName = svcName
		return nil
	}
	t.Cleanup(func() {
		newServiceManager = origMgrFn
		spawnDetachedRestartFn = origDetachedFn
	})

	tmp := t.TempDir()
	seedDir := filepath.Join(tmp, "seed-node")
	svcDir := filepath.Join(tmp, "svc-node")
	logPath := filepath.Join(svcDir, "agent-bridge-server.log")

	mustRunCLI(t, []string{"ca", "init", "--out-dir", seedDir})

	seedExecPort := freeLoopbackPort(t)
	seedClusterPort := freeLoopbackPort(t)
	seedClusterAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(seedClusterPort))
	seedCfgPath := filepath.Join(seedDir, "server.json")
	if err := service.SaveServerDaemonConfig(seedCfgPath, &service.ServerDaemonConfig{
		DataDir:          seedDir,
		NodeID:           "node-a",
		BindSpecs:        []string{"127.0.0.1"},
		Port:             seedExecPort,
		ClusterEnabled:   true,
		ClusterBindSpecs: []string{seedClusterAddr},
		ClusterAdvertise: seedClusterAddr,
	}); err != nil {
		t.Fatalf("SaveServerDaemonConfig(seed): %v", err)
	}

	_ = startBackgroundCLIServer(t, []string{
		"server",
		"--service-config", seedCfgPath,
	})
	waitForTCPPort(t, seedClusterAddr, 5*time.Second)

	secretJoinToken := strings.TrimSpace(mustRunCLI(t, []string{
		"cluster", "token-create",
		"--data-dir", seedDir,
		"--node-id", "node-b",
		"-q",
	}))

	// 1. Run `service install` with `--join` + `--join-token` and verify `join_token` NEVER touches server.json!
	svcExecPort := freeLoopbackPort(t)
	svcClusterPort := freeLoopbackPort(t)
	svcClusterAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(svcClusterPort))

	mustRunCLI(t, []string{
		"service", "install",
		"--name", "agent-bridge",
		"--data-dir", svcDir,
		"--node-id", "node-b",
		"--bind", "127.0.0.1",
		"--port", strconv.Itoa(svcExecPort),
		"--cluster-bind", svcClusterAddr,
		"--join", seedClusterAddr,
		"--join-token", secretJoinToken,
		"--log-file", logPath,
		"--skip-preflight",
		"--json",
	})

	cfgPath := filepath.Join(svcDir, "server.json")
	rawServerJSON, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", cfgPath, err)
	}
	if strings.Contains(string(rawServerJSON), secretJoinToken) || strings.Contains(strings.ToLower(string(rawServerJSON)), "join_token") {
		t.Fatalf("SECURITY VIOLATION: join token persisted to server.json:\n%s", string(rawServerJSON))
	}

	loadedCfg, err := service.LoadServerDaemonConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadServerDaemonConfig: %v", err)
	}
	if !loadedCfg.ClusterEnabled || len(loadedCfg.SeedPeers) == 0 {
		t.Fatalf("expected ClusterEnabled=true and populated SeedPeers in server.json: %+v", loadedCfg)
	}

	// 2. Verify `server --service-config <cfgPath>` loads defaults AND allows explicit `--port` CLI flag override.
	overrideExecPort := freeLoopbackPort(t)
	overrideExecAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(overrideExecPort))

	srvSvc := startBackgroundCLIServer(t, []string{
		"server",
		"--service-config", cfgPath,
		"--port", strconv.Itoa(overrideExecPort),
	})
	waitForTCPPort(t, overrideExecAddr, 5*time.Second)

	if code := srvSvc.stop(); code != exitOK {
		t.Fatalf("service-config server exited with %d: stderr=%s", code, srvSvc.err.String())
	}

	// 3. Verify `service logs` reads the rotating daemon log written by `server --service-config`.
	logsOut := mustRunCLI(t, []string{
		"service", "logs",
		"--log-file", logPath,
		"--lines", "50",
	})
	if !strings.Contains(logsOut, "listening on") {
		t.Fatalf("expected daemon log output from `service logs`, got: %q", logsOut)
	}

	// 4. Verify `service status` and `service restart` under `AGENT_BRIDGE_IN_EXEC=1` (auto-detached!).
	statusOut := mustRunCLI(t, []string{
		"service", "status",
		"--name", "agent-bridge",
		"--data-dir", svcDir,
		"--json",
	})
	if !strings.Contains(statusOut, `"running": true`) {
		t.Fatalf("unexpected service status JSON: %s", statusOut)
	}

	t.Setenv(runner.EnvInExec, "1")
	restartOut := mustRunCLI(t, []string{
		"service", "restart",
		"--name", "agent-bridge",
		"--json",
	})
	if detachedCalls != 1 || detachedSvcName != "agent-bridge" {
		t.Fatalf("expected AGENT_BRIDGE_IN_EXEC=1 to trigger detached restart once, got calls=%d name=%q out=%s",
			detachedCalls, detachedSvcName, restartOut)
	}
	if mockMgr.restarts != 0 {
		t.Fatalf("expected synchronous mgr.Restart NOT to run when AGENT_BRIDGE_IN_EXEC=1, got %d", mockMgr.restarts)
	}
}

func TestV020SelfUpgradeCheckSignedSwapAndStartupSweep(t *testing.T) {
	for _, k := range []string{
		"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy",
		"AGENT_BRIDGE_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", runner.EnvInExec,
	} {
		t.Setenv(k, "")
	}

	mockMgr := &mockServiceManager{installed: false, running: false}
	origMgrFn := newServiceManager
	newServiceManager = func() service.Manager { return mockMgr }
	t.Cleanup(func() { newServiceManager = origMgrFn })

	tmp := t.TempDir()

	// Build two tiny static Go binaries simulating v0.1.0 and v0.2.0 so `<staged> version` smoke test passes.
	srcPath := filepath.Join(tmp, "dummy_ver.go")
	srcCode := `package main
import "os"
var ver = "v0.0.0"
func main() { _, _ = os.Stdout.WriteString("agent-bridge " + ver + "\n") }
`
	if err := os.WriteFile(srcPath, []byte(srcCode), 0o600); err != nil {
		t.Fatalf("WriteFile(dummy_ver.go): %v", err)
	}
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	buildDummy := func(name, verStr string) []byte {
		outBin := filepath.Join(tmp, name+ext)
		cmd := exec.Command("go", "build", "-ldflags=-X main.ver="+verStr, "-o", outBin, srcPath)
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %s failed: %v (%s)", name, err, string(out))
		}
		b, err := os.ReadFile(outBin)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", outBin, err)
		}
		return b
	}
	binV010 := buildDummy("build-v010", "v0.1.0")
	binV020 := buildDummy("build-v020", "v0.2.0")

	targetDir := filepath.Join(tmp, "install")
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	targetExe := filepath.Join(targetDir, "agent-bridge"+ext)
	if err := os.WriteFile(targetExe, binV010, 0o755); err != nil {
		t.Fatalf("WriteFile(targetExe): %v", err)
	}

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	pubHex := hex.EncodeToString(pubKey)

	assetName, err := upgrade.AssetNameForPlatform(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatalf("AssetNameForPlatform: %v", err)
	}
	sum256 := sha256.Sum256(binV020)
	checksumsBody := fmt.Sprintf("%s  %s\n", hex.EncodeToString(sum256[:]), assetName)
	sigHex := hex.EncodeToString(ed25519.Sign(privKey, []byte(checksumsBody))) + "\n"

	var tamperSig bool
	var relSrv *httptest.Server
	relSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/kennyparsons/agent-bridge/releases/latest",
			"/repos/kennyparsons/agent-bridge/releases/tags/v0.2.0":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name":     "v0.2.0",
				"name":         "v0.2.0",
				"prerelease":   false,
				"published_at": "2026-11-08T00:00:00Z",
				"html_url":     relSrv.URL + "/releases/v0.2.0",
				"assets": []map[string]any{
					{
						"name":                 assetName,
						"url":                  relSrv.URL + "/dl/" + assetName,
						"browser_download_url": relSrv.URL + "/dl/" + assetName,
						"size":                 len(binV020),
					},
					{
						"name":                 upgrade.ChecksumsAssetName,
						"url":                  relSrv.URL + "/dl/" + upgrade.ChecksumsAssetName,
						"browser_download_url": relSrv.URL + "/dl/" + upgrade.ChecksumsAssetName,
						"size":                 len(checksumsBody),
					},
					{
						"name":                 upgrade.SignatureAssetName,
						"url":                  relSrv.URL + "/dl/" + upgrade.SignatureAssetName,
						"browser_download_url": relSrv.URL + "/dl/" + upgrade.SignatureAssetName,
						"size":                 len(sigHex),
					},
				},
			})
		case "/dl/" + assetName:
			_, _ = w.Write(binV020)
		case "/dl/" + upgrade.ChecksumsAssetName:
			if tamperSig {
				_, _ = w.Write([]byte(checksumsBody + "# tampered\n"))
				return
			}
			_, _ = w.Write([]byte(checksumsBody))
		case "/dl/" + upgrade.SignatureAssetName:
			_, _ = w.Write([]byte(sigHex))
		default:
			http.NotFound(w, r)
		}
	}))
	defer relSrv.Close()

	// 1. `selfupgrade --check --json` verifies Ed25519 signature without modifying targetExe.
	checkRaw := mustRunCLI(t, []string{
		"selfupgrade",
		"--check",
		"--api-url", relSrv.URL,
		"--public-key", pubHex,
		"--json",
	})
	var checkRes upgrade.CheckResult
	if err := json.Unmarshal([]byte(checkRaw), &checkRes); err != nil {
		t.Fatalf("unmarshal selfupgrade --check --json: %v (%s)", err, checkRaw)
	}
	if !checkRes.UpdateAvailable || !checkRes.SignatureVerified || checkRes.TargetVersion != "v0.2.0" {
		t.Fatalf("unexpected selfupgrade --check result: %+v", checkRes)
	}

	// 2. Tampered checksums/signature MUST be rejected and leave v0.1.0 untouched.
	tamperSig = true
	{
		var out, errBuf bytes.Buffer
		rc := run([]string{
			"selfupgrade",
			"--yes",
			"--force",
			"--api-url", relSrv.URL,
			"--public-key", pubHex,
			"--exe", targetExe,
			"--no-restart",
		}, &out, &errBuf)
		if rc == exitOK {
			t.Fatal("expected tampered Ed25519 release payload to fail selfupgrade")
		}
		verOut, err := exec.Command(targetExe, "version").CombinedOutput()
		if err != nil || !strings.Contains(string(verOut), "agent-bridge v0.1.0") {
			t.Fatalf("expected targetExe to remain v0.1.0 after rejected tamper, got %q (err=%v)", string(verOut), err)
		}
	}

	// 3. Valid Ed25519-signed `selfupgrade --yes` atomically swaps v0.1.0 -> v0.2.0!
	tamperSig = false
	upgRaw := mustRunCLI(t, []string{
		"selfupgrade",
		"--yes",
		"--force",
		"--api-url", relSrv.URL,
		"--public-key", pubHex,
		"--exe", targetExe,
		"--no-restart",
		"--json",
	})
	var upgRes upgrade.Result
	if err := json.Unmarshal([]byte(upgRaw), &upgRes); err != nil {
		t.Fatalf("unmarshal selfupgrade --json: %v (%s)", err, upgRaw)
	}
	if !upgRes.Upgraded || !upgRes.SignatureVerified || upgRes.TargetVersion != "v0.2.0" {
		t.Fatalf("unexpected selfupgrade result: %+v", upgRes)
	}

	verOut, err := exec.Command(targetExe, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("executing upgraded binary failed: %v (%s)", err, string(verOut))
	}
	if strings.TrimSpace(string(verOut)) != "agent-bridge v0.2.0" {
		t.Fatalf("upgraded binary output = %q, want %q", strings.TrimSpace(string(verOut)), "agent-bridge v0.2.0")
	}

	// 4. Verify SweepOldExecutables cleans `.old` backups cleanly.
	staleOld := targetExe + ".old"
	if err := os.WriteFile(staleOld, []byte("stale"), 0o600); err != nil {
		t.Fatalf("WriteFile(staleOld): %v", err)
	}
	upgrade.SweepOldExecutables(targetExe)
	if _, statErr := os.Stat(staleOld); !os.IsNotExist(statErr) {
		t.Fatalf("expected %s to be swept, stat err=%v", staleOld, statErr)
	}
}
