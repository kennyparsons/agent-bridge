package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/netbind"
	"github.com/kennyparsons/agent-bridge/internal/pki"
	"github.com/kennyparsons/agent-bridge/internal/protocol"
)

const (
	testGossipInterval     = 80 * time.Millisecond
	testSuspectTimeout     = 240 * time.Millisecond
	testUnreachableTimeout = 480 * time.Millisecond
)

type testPKIFixture struct {
	caDir      string
	caRes      *pki.InitCAResult
	adminCert  *pki.IssueCertResult
	wrongCADir string
	wrongCARes *pki.InitCAResult
}

func newTestPKIFixture(t *testing.T) *testPKIFixture {
	t.Helper()
	root := t.TempDir()

	caDir := filepath.Join(root, "ca")
	caRes, err := pki.InitCA(pki.InitCAOptions{
		OutDir:     caDir,
		CommonName: "Test-Cluster-Root-CA",
		Org:        "AgentBridgeTest",
		Years:      5,
	})
	if err != nil {
		t.Fatalf("InitCA failed: %v", err)
	}

	adminDir := filepath.Join(root, "admin-client")
	adminCert, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  caDir,
		OutDir: adminDir,
		Type:   pki.TypeClient,
		Name:   "cluster-admin",
	})
	if err != nil {
		t.Fatalf("IssueCert(admin) failed: %v", err)
	}

	wrongCADir := filepath.Join(root, "wrong-ca")
	wrongCARes, err := pki.InitCA(pki.InitCAOptions{
		OutDir:     wrongCADir,
		CommonName: "Untrusted-Root-CA",
		Org:        "RogueOrg",
		Years:      5,
	})
	if err != nil {
		t.Fatalf("InitCA(wrong) failed: %v", err)
	}

	return &testPKIFixture{
		caDir:      caDir,
		caRes:      caRes,
		adminCert:  adminCert,
		wrongCADir: wrongCADir,
		wrongCARes: wrongCARes,
	}
}

type testNodeHarness struct {
	nodeID     string
	dir        string
	certPath   string
	keyPath    string
	caPath     string
	crlPath    string
	statePath  string
	certSerial string
	watcher    *pki.CRLWatcher
	engine     *Engine
}

func copyFileForTest(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", src, err)
	}
	if err := pki.WriteFileAtomic(dst, data, mode); err != nil {
		t.Fatalf("WriteFileAtomic(%s): %v", dst, err)
	}
}

func startPreIssuedTestNode(
	t *testing.T,
	fix *testPKIFixture,
	nodeID string,
	withCAKey bool,
	seedPeers []string,
) *testNodeHarness {
	t.Helper()
	nodeDir := filepath.Join(t.TempDir(), nodeID)
	if err := os.MkdirAll(nodeDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	issued, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:    fix.caDir,
		OutDir:   nodeDir,
		Type:     pki.TypePeer,
		Name:     nodeID,
		IPs:      []string{"127.0.0.1"},
		DNSNames: []string{"localhost", nodeID},
	})
	if err != nil {
		t.Fatalf("IssueCert(%s): %v", nodeID, err)
	}

	caPath := filepath.Join(nodeDir, pki.CACertFilename)
	crlPath := filepath.Join(nodeDir, pki.CRLFilename)
	statePath := filepath.Join(nodeDir, "cluster-state.json")
	copyFileForTest(t, fix.caRes.CACertPath, caPath, 0o644)
	copyFileForTest(t, fix.caRes.CRLPath, crlPath, 0o644)

	caCert, _, err := pki.LoadCACertPool(caPath)
	if err != nil {
		t.Fatalf("LoadCACertPool: %v", err)
	}
	watcher, err := pki.NewCRLWatcher(crlPath, caCert, nil, nil)
	if err != nil {
		t.Fatalf("NewCRLWatcher: %v", err)
	}

	var caKeyPath string
	if withCAKey {
		caKeyPath = fix.caRes.CAKeyPath
	}

	eng, err := NewEngine(Config{
		NodeID:             nodeID,
		ClusterBindAddr:    "127.0.0.1:0",
		ExecAddr:           "127.0.0.1:8443",
		CertPath:           issued.CertPath,
		KeyPath:            issued.KeyPath,
		CAPath:             caPath,
		CAKeyPath:          caKeyPath,
		StatePath:          statePath,
		SeedPeers:          seedPeers,
		CRLWatcher:         watcher,
		GossipInterval:     testGossipInterval,
		SuspectTimeout:     testSuspectTimeout,
		UnreachableTimeout: testUnreachableTimeout,
		Logger:             log.New(io.Discard, "", 0),
	})
	if err != nil {
		_ = watcher.Close()
		t.Fatalf("NewEngine(%s): %v", nodeID, err)
	}

	if err := eng.Start(context.Background()); err != nil {
		_ = eng.Close()
		_ = watcher.Close()
		t.Fatalf("Engine.Start(%s): %v", nodeID, err)
	}
	<-eng.Ready()

	h := &testNodeHarness{
		nodeID:     nodeID,
		dir:        nodeDir,
		certPath:   issued.CertPath,
		keyPath:    issued.KeyPath,
		caPath:     caPath,
		crlPath:    crlPath,
		statePath:  statePath,
		certSerial: issued.SerialHex,
		watcher:    watcher,
		engine:     eng,
	}
	t.Cleanup(func() {
		_ = h.engine.Close()
		_ = h.watcher.Close()
	})
	return h
}

func startBootstrappedNodeEngine(
	t *testing.T,
	nodeID string,
	certPath, keyPath, caPath, crlPath, statePath string,
	withCAKeyPath string,
	seedPeers []string,
) *testNodeHarness {
	t.Helper()
	caCert, _, err := pki.LoadCACertPool(caPath)
	if err != nil {
		t.Fatalf("LoadCACertPool(%s): %v", nodeID, err)
	}
	leafCert, err := pki.LoadCertificate(certPath)
	if err != nil {
		t.Fatalf("LoadCertificate(%s): %v", nodeID, err)
	}
	watcher, err := pki.NewCRLWatcher(crlPath, caCert, nil, nil)
	if err != nil {
		t.Fatalf("NewCRLWatcher(%s): %v", nodeID, err)
	}

	eng, err := NewEngine(Config{
		NodeID:             nodeID,
		ClusterBindAddr:    "127.0.0.1:0",
		ExecAddr:           "127.0.0.1:8443",
		CertPath:           certPath,
		KeyPath:            keyPath,
		CAPath:             caPath,
		CAKeyPath:          withCAKeyPath,
		StatePath:          statePath,
		SeedPeers:          seedPeers,
		CRLWatcher:         watcher,
		GossipInterval:     testGossipInterval,
		SuspectTimeout:     testSuspectTimeout,
		UnreachableTimeout: testUnreachableTimeout,
		Logger:             log.New(io.Discard, "", 0),
	})
	if err != nil {
		_ = watcher.Close()
		t.Fatalf("NewEngine(%s): %v", nodeID, err)
	}
	if err := eng.Start(context.Background()); err != nil {
		_ = eng.Close()
		_ = watcher.Close()
		t.Fatalf("Start(%s): %v", nodeID, err)
	}
	<-eng.Ready()

	h := &testNodeHarness{
		nodeID:     nodeID,
		dir:        filepath.Dir(certPath),
		certPath:   certPath,
		keyPath:    keyPath,
		caPath:     caPath,
		crlPath:    crlPath,
		statePath:  statePath,
		certSerial: pki.FormatSerialHex(leafCert.SerialNumber),
		watcher:    watcher,
		engine:     eng,
	}
	t.Cleanup(func() {
		_ = h.engine.Close()
		_ = h.watcher.Close()
	})
	return h
}

func waitForCondition(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timed out after %s waiting for: %s", timeout, desc)
}

// 1. N=1 Standalone Cluster Mode
func TestSingleNodeStandaloneMode(t *testing.T) {
	fix := newTestPKIFixture(t)
	n1 := startPreIssuedTestNode(t, fix, "dc01", true, nil)

	st := n1.engine.Status()
	if st.Topology != TopologySingleNode {
		t.Fatalf("expected topology %q, got %q", TopologySingleNode, st.Topology)
	}
	if st.QuorumState != QuorumHealthy {
		t.Fatalf("expected quorum_state %q, got %q", QuorumHealthy, st.QuorumState)
	}
	if !st.HasQuorum || !st.IsLeader {
		t.Fatalf("expected HasQuorum=true and IsLeader=true, got HasQuorum=%v IsLeader=%v", st.HasQuorum, st.IsLeader)
	}
	if st.LeaderID != "dc01" || st.TotalNodes != 1 || st.AliveNodes != 1 || st.QuorumRequired != 1 {
		t.Fatalf("unexpected standalone status: %+v", st)
	}
	if !st.HasCAKey {
		t.Fatal("expected HasCAKey=true on authority standalone node")
	}

	tok, exp, err := n1.engine.CreateJoinToken(10*time.Minute, "dc02")
	if err != nil {
		t.Fatalf("CreateJoinToken failed: %v", err)
	}
	parsedTok, err := ParseJoinToken(tok)
	if err != nil {
		t.Fatalf("ParseJoinToken failed: %v", err)
	}
	if exp.Before(time.Now().Add(9 * time.Minute)) {
		t.Fatalf("unexpected token expiration: %v", exp)
	}

	// Verify plaintext token secret is NEVER written to StatePath on disk.
	rawStateBytes, err := os.ReadFile(n1.statePath)
	if err != nil {
		t.Fatalf("ReadFile(statePath): %v", err)
	}
	if strings.Contains(string(rawStateBytes), parsedTok.SecretHex) {
		t.Fatal("security violation: plaintext token secret found in persisted state file")
	}

	// Update ExecutionPolicy and verify lock-free ExecutionPolicy() read.
	syncRes, err := n1.engine.Sync(context.Background(), SyncRequest{
		PolicyUpdate: &protocol.ExecutionPolicy{
			DefaultTimeoutSeconds: 45,
			MaxTimeoutSeconds:     300,
			DefaultShell:          "pwsh",
			EnforceClientACL:      true,
			AllowedClients:        []string{"cluster-admin", "ops-runner"},
		},
	})
	if err != nil {
		t.Fatalf("Sync(PolicyUpdate) failed: %v", err)
	}
	if !syncRes.PolicyUpdated || syncRes.PolicyVersion != 1 {
		t.Fatalf("expected PolicyUpdated=true and version=1, got %+v", syncRes)
	}

	activePol := n1.engine.ExecutionPolicy()
	if activePol.Version != 1 || activePol.DefaultTimeoutSeconds != 45 || !activePol.EnforceClientACL {
		t.Fatalf("unexpected active ExecutionPolicy: %+v", activePol)
	}
	if !activePol.IsClientAllowed("cluster-admin", "") || activePol.IsClientAllowed("unauthorized-client", "") {
		t.Fatalf("unexpected ACL evaluation on active policy: %+v", activePol)
	}
}

// 2. Zero-Touch CSR Join (N=1 -> N=2), Token Single-Use Enforcement, Wrong Token/CA Rejection & Idempotent Restart
func TestZeroTouchCSRJoinAndTokenSecurity(t *testing.T) {
	fix := newTestPKIFixture(t)
	n1 := startPreIssuedTestNode(t, fix, "node-1", true, nil)

	// Set an initial policy on node-1 before node-2 joins so we verify JoinResponse policy bootstrap.
	if _, err := n1.engine.Sync(context.Background(), SyncRequest{
		PolicyUpdate: &protocol.ExecutionPolicy{
			DefaultTimeoutSeconds: 35,
			MaxTimeoutSeconds:     180,
			EnforceClientACL:      true,
			AllowedClients:        []string{"cluster-admin"},
		},
	}); err != nil {
		t.Fatalf("initial policy sync failed: %v", err)
	}

	tok, _, err := n1.engine.CreateJoinToken(5*time.Minute, "")
	if err != nil {
		t.Fatalf("CreateJoinToken: %v", err)
	}
	parsedTok, err := ParseJoinToken(tok)
	if err != nil {
		t.Fatalf("ParseJoinToken: %v", err)
	}

	// 2a. Wrong CA fingerprint in token must be rejected during TLS pin verification before anything is issued.
	badCADir := t.TempDir()
	wrongCAFP := pki.CertFingerprintSHA256(fix.wrongCARes.Certificate)
	forgedCAToken := JoinTokenVersionPrefix + "." + wrongCAFP + "." + parsedTok.TokenID + "." + parsedTok.SecretHex
	_, err = BootstrapJoin(context.Background(), BootstrapJoinOptions{
		JoinAddr:        n1.engine.Addr(),
		JoinToken:       forgedCAToken,
		NodeID:          "bad-ca-node",
		ClusterBindAddr: "127.0.0.1:0",
		CertPath:        filepath.Join(badCADir, "server.crt"),
		KeyPath:         filepath.Join(badCADir, "server.key"),
		CAPath:          filepath.Join(badCADir, "ca.crt"),
		CRLPath:         filepath.Join(badCADir, "crl.pem"),
	})
	if err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("expected CA fingerprint mismatch error, got: %v", err)
	}

	// 2b. Wrong secret (with valid TokenID and valid CA hash) must be rejected without consuming the valid token.
	wrongSecretDir := t.TempDir()
	wrongSecret := strings.Repeat("f", 64)
	if wrongSecret == parsedTok.SecretHex {
		wrongSecret = strings.Repeat("e", 64)
	}
	badSecretToken := JoinTokenVersionPrefix + "." + parsedTok.CAFingerprint + "." + parsedTok.TokenID + "." + wrongSecret
	_, err = BootstrapJoin(context.Background(), BootstrapJoinOptions{
		JoinAddr:        n1.engine.Addr(),
		JoinToken:       badSecretToken,
		NodeID:          "bad-secret-node",
		ClusterBindAddr: "127.0.0.1:0",
		CertPath:        filepath.Join(wrongSecretDir, "server.crt"),
		KeyPath:         filepath.Join(wrongSecretDir, "server.key"),
		CAPath:          filepath.Join(wrongSecretDir, "ca.crt"),
		CRLPath:         filepath.Join(wrongSecretDir, "crl.pem"),
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "invalid join token") {
		t.Fatalf("expected invalid join token error, got: %v", err)
	}

	// 2c. Valid Mode A Zero-Touch CSR Join for node-2 (with NO pre-existing certs on disk).
	n2Dir := filepath.Join(t.TempDir(), "node-2")
	n2Cert := filepath.Join(n2Dir, "server.crt")
	n2Key := filepath.Join(n2Dir, "server.key")
	n2CA := filepath.Join(n2Dir, "ca.crt")
	n2CRL := filepath.Join(n2Dir, "crl.pem")
	n2State := filepath.Join(n2Dir, "cluster-state.json")

	joinRes, err := BootstrapJoin(context.Background(), BootstrapJoinOptions{
		JoinAddr:        n1.engine.Addr(),
		JoinToken:       tok,
		NodeID:          "node-2",
		ClusterBindAddr: "127.0.0.1:0",
		ExecBindAddr:    "127.0.0.1:8443",
		CertPath:        n2Cert,
		KeyPath:         n2Key,
		CAPath:          n2CA,
		CRLPath:         n2CRL,
		StatePath:       n2State,
	})
	if err != nil {
		t.Fatalf("BootstrapJoin(node-2) failed: %v", err)
	}
	if joinRes.AlreadyBootstrapped || joinRes.Mode != "csr-issued" {
		t.Fatalf("unexpected join result: %+v", joinRes)
	}
	if joinRes.Policy.Version != 1 || joinRes.Policy.DefaultTimeoutSeconds != 35 {
		t.Fatalf("expected bootstrapped policy version 1, got: %+v", joinRes.Policy)
	}

	// Start node-2 Engine using the newly issued PKI artifacts.
	n2 := startBootstrappedNodeEngine(t, "node-2", n2Cert, n2Key, n2CA, n2CRL, n2State, "", []string{n1.engine.Addr()})

	waitForCondition(t, 3*time.Second, "2-node healthy convergence", func() bool {
		s1 := n1.engine.Status()
		s2 := n2.engine.Status()
		return s1.Topology == TopologyTwoNode &&
			s1.QuorumState == QuorumHealthy &&
			s1.AliveNodes == 2 &&
			s2.Topology == TopologyTwoNode &&
			s2.QuorumState == QuorumHealthy &&
			s2.AliveNodes == 2 &&
			s1.LeaderID == "node-1" &&
			s2.LeaderID == "node-1"
	})

	// 2d. Replaying the exact same single-use join token from a new node must fail immediately.
	replayDir := t.TempDir()
	_, err = BootstrapJoin(context.Background(), BootstrapJoinOptions{
		JoinAddr:        n1.engine.Addr(),
		JoinToken:       tok,
		NodeID:          "node-replay",
		ClusterBindAddr: "127.0.0.1:0",
		CertPath:        filepath.Join(replayDir, "server.crt"),
		KeyPath:         filepath.Join(replayDir, "server.key"),
		CAPath:          filepath.Join(replayDir, "ca.crt"),
		CRLPath:         filepath.Join(replayDir, "crl.pem"),
	})
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "already been used") {
		t.Fatalf("expected single-use replay rejection, got: %v", err)
	}

	// Replaying the same token against node-2 must ALSO fail (token consumption replicated!).
	waitForCondition(t, 2*time.Second, "token consumption replicated to node-2", func() bool {
		_, replayErr := BootstrapJoin(context.Background(), BootstrapJoinOptions{
			JoinAddr:        n2.engine.Addr(),
			JoinToken:       tok,
			NodeID:          "node-replay-via-2",
			ClusterBindAddr: "127.0.0.1:0",
			CertPath:        filepath.Join(t.TempDir(), "server.crt"),
			KeyPath:         filepath.Join(t.TempDir(), "server.key"),
			CAPath:          filepath.Join(t.TempDir(), "ca.crt"),
			CRLPath:         filepath.Join(t.TempDir(), "crl.pem"),
		})
		return replayErr != nil && strings.Contains(strings.ToLower(replayErr.Error()), "already been used")
	})

	// 2e. Idempotent restart of node-2 with StatePath + existing PKI files skips consuming --join-token.
	restartRes, err := BootstrapJoin(context.Background(), BootstrapJoinOptions{
		JoinAddr:        n1.engine.Addr(),
		JoinToken:       tok, // Already consumed token left in service unit flags!
		NodeID:          "node-2",
		ClusterBindAddr: "127.0.0.1:0",
		CertPath:        n2Cert,
		KeyPath:         n2Key,
		CAPath:          n2CA,
		CRLPath:         n2CRL,
		StatePath:       n2State,
	})
	if err != nil {
		t.Fatalf("expected idempotent restart BootstrapJoin to succeed, got: %v", err)
	}
	if !restartRes.AlreadyBootstrapped || restartRes.Mode != "already-bootstrapped" {
		t.Fatalf("expected AlreadyBootstrapped=true, got: %+v", restartRes)
	}
}

// 3. Offline-CA Pre-Issued Cert Join + CA-Signer Forwarding Across Non-CA Peer
func TestOfflinePreIssuedJoinAndCASignerForwarding(t *testing.T) {
	fix := newTestPKIFixture(t)

	// Part A: Offline-CA mode where NO cluster node holds ca.key!
	offlineSeed := startPreIssuedTestNode(t, fix, "offline-node-1", false, nil)
	if offlineSeed.engine.Status().HasCAKey {
		t.Fatal("expected HasCAKey=false on offline-CA node")
	}

	// Verify Mode A CSR join fails with actionable operator guidance when no node holds ca.key.
	tokCSR, _, err := offlineSeed.engine.CreateJoinToken(5*time.Minute, "")
	if err != nil {
		t.Fatalf("CreateJoinToken: %v", err)
	}
	csrFailDir := t.TempDir()
	_, err = BootstrapJoin(context.Background(), BootstrapJoinOptions{
		JoinAddr:        offlineSeed.engine.Addr(),
		JoinToken:       tokCSR,
		NodeID:          "csr-without-ca-key",
		ClusterBindAddr: "127.0.0.1:0",
		CertPath:        filepath.Join(csrFailDir, "server.crt"),
		KeyPath:         filepath.Join(csrFailDir, "server.key"),
		CAPath:          filepath.Join(csrFailDir, "ca.crt"),
		CRLPath:         filepath.Join(csrFailDir, "crl.pem"),
	})
	if err == nil || !strings.Contains(err.Error(), "--ca-key") || !strings.Contains(err.Error(), "agent-bridge ca issue") {
		t.Fatalf("expected actionable missing --ca-key guidance, got: %v", err)
	}

	// Pre-issue a TypeServer certificate offline using pki.IssueCert, then join offlineSeed (HasCAKey=false)!
	preIssuedDir := filepath.Join(t.TempDir(), "offline-node-2")
	issuedSrv, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:    fix.caDir,
		OutDir:   preIssuedDir,
		Type:     pki.TypeServer,
		Name:     "offline-node-2",
		IPs:      []string{"127.0.0.1"},
		DNSNames: []string{"localhost"},
	})
	if err != nil {
		t.Fatalf("IssueCert(TypeServer): %v", err)
	}

	tokPre, _, err := offlineSeed.engine.CreateJoinToken(5*time.Minute, "offline-node-2")
	if err != nil {
		t.Fatalf("CreateJoinToken(pre-issued): %v", err)
	}

	preCA := filepath.Join(preIssuedDir, "ca.crt")
	preCRL := filepath.Join(preIssuedDir, "crl.pem")
	preState := filepath.Join(preIssuedDir, "cluster-state.json")

	preRes, err := BootstrapJoin(context.Background(), BootstrapJoinOptions{
		JoinAddr:        offlineSeed.engine.Addr(),
		JoinToken:       tokPre,
		NodeID:          "offline-node-2",
		ClusterBindAddr: "127.0.0.1:0",
		CertPath:        issuedSrv.CertPath,
		KeyPath:         issuedSrv.KeyPath,
		CAPath:          preCA,
		CRLPath:         preCRL,
		StatePath:       preState,
	})
	if err != nil {
		t.Fatalf("Mode B pre-issued BootstrapJoin failed: %v", err)
	}
	if preRes.Mode != "pre-issued" || preRes.CertSerialHex != issuedSrv.SerialHex {
		t.Fatalf("unexpected Mode B result: %+v", preRes)
	}

	offlineNode2 := startBootstrappedNodeEngine(
		t,
		"offline-node-2",
		issuedSrv.CertPath,
		issuedSrv.KeyPath,
		preCA,
		preCRL,
		preState,
		"",
		[]string{offlineSeed.engine.Addr()},
	)

	waitForCondition(t, 3*time.Second, "offline-CA 2-node cluster healthy", func() bool {
		return offlineSeed.engine.Status().AliveNodes == 2 && offlineNode2.engine.Status().AliveNodes == 2
	})

	// Part B: CA-Signer Forwarding!
	// authNode1 HAS ca.key (HasCAKey: true); relayNode2 does NOT have ca.key (HasCAKey: false).
	// Mint token ON relayNode2, and have joinerNode3 call BootstrapJoin (Mode A CSR) against relayNode2!
	authNode1 := startPreIssuedTestNode(t, fix, "auth-node-1", true, nil)
	relayNode2 := startPreIssuedTestNode(t, fix, "relay-node-2", false, []string{authNode1.engine.Addr()})

	waitForCondition(t, 3*time.Second, "authNode1 and relayNode2 mesh ready", func() bool {
		return relayNode2.engine.Status().AliveNodes == 2 && authNode1.engine.Status().AliveNodes == 2
	})

	// Mint token directly on relayNode2 (which does NOT hold ca.key!) and immediately join via relayNode2!
	forwardedTok, _, err := relayNode2.engine.CreateJoinToken(5*time.Minute, "csr-forwarded-node-3")
	if err != nil {
		t.Fatalf("relayNode2.CreateJoinToken: %v", err)
	}

	n3Dir := filepath.Join(t.TempDir(), "csr-forwarded-node-3")
	n3Cert := filepath.Join(n3Dir, "server.crt")
	n3Key := filepath.Join(n3Dir, "server.key")
	n3CA := filepath.Join(n3Dir, "ca.crt")
	n3CRL := filepath.Join(n3Dir, "crl.pem")
	n3State := filepath.Join(n3Dir, "cluster-state.json")

	fwdRes, err := BootstrapJoin(context.Background(), BootstrapJoinOptions{
		JoinAddr:        relayNode2.engine.Addr(), // Contacting non-CA node!
		JoinToken:       forwardedTok,
		NodeID:          "csr-forwarded-node-3",
		ClusterBindAddr: "127.0.0.1:0",
		CertPath:        n3Cert,
		KeyPath:         n3Key,
		CAPath:          n3CA,
		CRLPath:         n3CRL,
		StatePath:       n3State,
	})
	if err != nil {
		t.Fatalf("CSR forwarding BootstrapJoin via relayNode2 failed: %v", err)
	}
	if fwdRes.Mode != "csr-issued" || fwdRes.CertSerialHex == "" {
		t.Fatalf("unexpected forwarded CSR join result: %+v", fwdRes)
	}

	n3 := startBootstrappedNodeEngine(
		t,
		"csr-forwarded-node-3",
		n3Cert,
		n3Key,
		n3CA,
		n3CRL,
		n3State,
		"",
		[]string{relayNode2.engine.Addr()},
	)

	waitForCondition(t, 3*time.Second, "all 3 nodes alive after forwarded CSR join", func() bool {
		return authNode1.engine.Status().AliveNodes == 3 &&
			relayNode2.engine.Status().AliveNodes == 3 &&
			n3.engine.Status().AliveNodes == 3
	})
}

// 4. N=2 Deadlock-Free Failover & Automatic Reconvergence
func TestTwoNodeDeadlockFreeFailoverAndReconvergence(t *testing.T) {
	fix := newTestPKIFixture(t)
	n1 := startPreIssuedTestNode(t, fix, "win-dc-01", true, nil)
	n2 := startPreIssuedTestNode(t, fix, "win-dc-02", false, []string{n1.engine.Addr()})

	waitForCondition(t, 3*time.Second, "2-node initial healthy state", func() bool {
		s1 := n1.engine.Status()
		s2 := n2.engine.Status()
		return s1.QuorumState == QuorumHealthy &&
			s2.QuorumState == QuorumHealthy &&
			s1.LeaderID == "win-dc-01" &&
			s2.LeaderID == "win-dc-01"
	})

	// Issue a client cert that we will revoke while win-dc-01 is offline.
	victimCert, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  fix.caDir,
		OutDir: filepath.Join(t.TempDir(), "victim"),
		Type:   pki.TypeClient,
		Name:   "compromised-laptop",
	})
	if err != nil {
		t.Fatalf("IssueCert(victim): %v", err)
	}

	// Shut down Node 1 (win-dc-01)!
	if err := n1.engine.Close(); err != nil {
		t.Fatalf("n1.Close(): %v", err)
	}

	// Verify Node 2 (win-dc-02) transitions to degraded-two-node-failover with HasQuorum=true & IsLeader=true (zero deadlock!).
	waitForCondition(t, 3*time.Second, "win-dc-02 enters degraded-two-node-failover as leader", func() bool {
		s2 := n2.engine.Status()
		return s2.Topology == TopologyTwoNode &&
			s2.QuorumState == QuorumDegradedTwoNodeFailover &&
			s2.HasQuorum &&
			s2.IsLeader &&
			s2.LeaderID == "win-dc-02" &&
			s2.TotalNodes == 2 &&
			s2.AliveNodes == 1
	})

	// Verify Node 2 can still mint join tokens AND update ExecutionPolicy while Node 1 is down!
	if _, _, err := n2.engine.CreateJoinToken(5*time.Minute, ""); err != nil {
		t.Fatalf("expected CreateJoinToken to succeed in degraded-two-node-failover, got: %v", err)
	}
	if _, err := n2.engine.Sync(context.Background(), SyncRequest{
		PolicyUpdate: &protocol.ExecutionPolicy{
			DefaultTimeoutSeconds: 25,
			DefaultShell:          "powershell",
		},
	}); err != nil {
		t.Fatalf("expected PolicyUpdate to succeed on surviving N=2 node, got: %v", err)
	}

	// Revoke victimCert and apply updated CRL to Node 2 while Node 1 is offline.
	revRes, err := pki.RevokeCert(pki.RevokeCertOptions{
		CADir:        fix.caDir,
		SerialNumber: victimCert.Serial,
		CRLOut:       n2.crlPath,
	})
	if err != nil {
		t.Fatalf("RevokeCert on n2 CRL: %v", err)
	}
	if err := n2.watcher.ReloadNow(); err != nil {
		t.Fatalf("n2.watcher.ReloadNow: %v", err)
	}
	if !n2.watcher.IsRevoked(victimCert.Serial) {
		t.Fatal("expected victimCert to be revoked on n2")
	}

	// Restart Node 1 (win-dc-01) from its persisted state and old CRL!
	n1Restarted := startBootstrappedNodeEngine(
		t,
		"win-dc-01",
		n1.certPath,
		n1.keyPath,
		n1.caPath,
		n1.crlPath,
		n1.statePath,
		fix.caRes.CAKeyPath,
		[]string{n2.engine.Addr()},
	)

	// Verify automatic reconvergence back to 2/2 healthy + CRL + ExecutionPolicy convergence on restarted Node 1!
	waitForCondition(t, 3*time.Second, "2-node reconvergence after win-dc-01 restart", func() bool {
		s1 := n1Restarted.engine.Status()
		s2 := n2.engine.Status()
		return s1.QuorumState == QuorumHealthy &&
			s2.QuorumState == QuorumHealthy &&
			s1.AliveNodes == 2 &&
			s2.AliveNodes == 2 &&
			s1.LeaderID == "win-dc-01" &&
			s2.LeaderID == "win-dc-01" &&
			n1Restarted.watcher.IsRevoked(victimCert.Serial) &&
			s1.CRLNumber == revRes.CRLNumber.String() &&
			n1Restarted.engine.ExecutionPolicy().DefaultTimeoutSeconds == 25
	})
}

// 5. N=3 Dynamic Quorum, Leader Failover & Minority Partition Step-Down
func TestThreeNodeDynamicQuorumFailoverAndMinorityStepDown(t *testing.T) {
	fix := newTestPKIFixture(t)

	n1 := startPreIssuedTestNode(t, fix, "node-a", true, nil)
	n2 := startPreIssuedTestNode(t, fix, "node-b", false, []string{n1.engine.Addr()})
	n3 := startPreIssuedTestNode(t, fix, "node-c", false, []string{n1.engine.Addr(), n2.engine.Addr()})

	waitForCondition(t, 3*time.Second, "3-node cluster healthy with node-a as leader", func() bool {
		s1 := n1.engine.Status()
		s2 := n2.engine.Status()
		s3 := n3.engine.Status()
		return s1.Topology == TopologyMultiNodeQuorum &&
			s1.QuorumState == QuorumHealthy &&
			s1.TotalNodes == 3 &&
			s1.AliveNodes == 3 &&
			s1.QuorumRequired == 2 &&
			s1.LeaderID == "node-a" &&
			s2.LeaderID == "node-a" &&
			s3.LeaderID == "node-a"
	})

	// Replicate a baseline ExecutionPolicy across all 3 nodes before inducing failures.
	if _, err := n1.engine.Sync(context.Background(), SyncRequest{
		PolicyUpdate: &protocol.ExecutionPolicy{
			DefaultTimeoutSeconds: 50,
			EnforceClientACL:      true,
			AllowedClients:        []string{"cluster-admin"},
		},
	}); err != nil {
		t.Fatalf("baseline policy sync: %v", err)
	}
	waitForCondition(t, 2*time.Second, "baseline policy replicated to node-c", func() bool {
		return n3.engine.ExecutionPolicy().Version == 1
	})

	// Stop leader node-a -> remaining 2 nodes (2/3 >= 2 quorum) enter degraded-quorum and elect new leader!
	if err := n1.engine.Close(); err != nil {
		t.Fatalf("n1.Close: %v", err)
	}

	waitForCondition(t, 3*time.Second, "2/3 majority elects new leader in degraded-quorum", func() bool {
		s2 := n2.engine.Status()
		s3 := n3.engine.Status()
		return s2.QuorumState == QuorumDegradedQuorum &&
			s3.QuorumState == QuorumDegradedQuorum &&
			s2.HasQuorum &&
			s3.HasQuorum &&
			s2.AliveNodes == 2 &&
			s3.AliveNodes == 2 &&
			s2.LeaderID != "" &&
			s2.LeaderID != "node-a" &&
			s2.LeaderID == s3.LeaderID
	})

	// Majority partition (2/3) can still create tokens and update policy.
	if _, _, err := n2.engine.CreateJoinToken(5*time.Minute, ""); err != nil {
		t.Fatalf("expected 2/3 majority to allow CreateJoinToken, got: %v", err)
	}

	// Stop 2nd node (node-b) -> isolated node-c (1/3 < 2) must step down into minority-partition!
	if err := n2.engine.Close(); err != nil {
		t.Fatalf("n2.Close: %v", err)
	}

	waitForCondition(t, 3*time.Second, "isolated 1/3 node enters minority-partition", func() bool {
		s3 := n3.engine.Status()
		return s3.Topology == TopologyMultiNodeQuorum &&
			s3.QuorumState == QuorumMinorityPartition &&
			!s3.HasQuorum &&
			!s3.IsLeader &&
			s3.LeaderID == "" &&
			s3.TotalNodes == 3 &&
			s3.AliveNodes == 1 &&
			s3.QuorumRequired == 2
	})

	// Minority node MUST reject CreateJoinToken and PolicyUpdate mutations with ErrNoQuorum!
	if _, _, err := n3.engine.CreateJoinToken(5*time.Minute, ""); !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("expected ErrNoQuorum on CreateJoinToken in minority-partition, got: %v", err)
	}
	if _, err := n3.engine.Sync(context.Background(), SyncRequest{
		PolicyUpdate: &protocol.ExecutionPolicy{DefaultTimeoutSeconds: 99},
	}); !errors.Is(err, ErrNoQuorum) {
		t.Fatalf("expected ErrNoQuorum on PolicyUpdate in minority-partition, got: %v", err)
	}

	// Crucially, local ExecutionPolicy() and CRLWatcher remain 100% operational for /ws/exec!
	cachedPol := n3.engine.ExecutionPolicy()
	if cachedPol.Version != 1 || cachedPol.DefaultTimeoutSeconds != 50 || !cachedPol.IsClientAllowed("cluster-admin", "") {
		t.Fatalf("minority node lost cached ExecutionPolicy: %+v", cachedPol)
	}

	localRevokedCert, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  fix.caDir,
		OutDir: filepath.Join(t.TempDir(), "local-rev"),
		Type:   pki.TypeClient,
		Name:   "revoked-client",
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	if _, err := pki.RevokeCert(pki.RevokeCertOptions{
		CADir:        fix.caDir,
		SerialNumber: localRevokedCert.Serial,
		CRLOut:       n3.crlPath,
	}); err != nil {
		t.Fatalf("RevokeCert: %v", err)
	}
	waitForCondition(t, time.Second, "minority node local CRLWatcher still enforces revocations", func() bool {
		return n3.watcher.IsRevoked(localRevokedCert.Serial)
	})
}

// 6. Live CRL Revocation Propagation (< 500ms) & Compromised Peer Expulsion
func TestLiveCRLPropagationAndCompromisedPeerExpulsion(t *testing.T) {
	fix := newTestPKIFixture(t)

	n1 := startPreIssuedTestNode(t, fix, "peer-1", true, nil)
	n2 := startPreIssuedTestNode(t, fix, "peer-2", false, []string{n1.engine.Addr()})
	n3 := startPreIssuedTestNode(t, fix, "peer-3", false, []string{n1.engine.Addr(), n2.engine.Addr()})

	waitForCondition(t, 3*time.Second, "3-node mesh healthy", func() bool {
		return n1.engine.Status().AliveNodes == 3 &&
			n2.engine.Status().AliveNodes == 3 &&
			n3.engine.Status().AliveNodes == 3
	})

	// Establish an active mTLS Client using peer-3's own certificate BEFORE revocation (pooling an HTTP/2 keep-alive conn!).
	peer3Client, err := NewClient(&config.ResolvedClusterConfig{
		ClusterAddr: n1.engine.Addr(),
		CertPath:    n3.certPath,
		KeyPath:     n3.keyPath,
		CAPath:      n3.caPath,
		Timeout:     5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient(peer3): %v", err)
	}
	defer peer3Client.Close()

	if _, err := peer3Client.Status(context.Background()); err != nil {
		t.Fatalf("expected unrevoked peer-3 client Status() to succeed, got: %v", err)
	}

	// 6a. Issue & revoke a leaf client serial on Node 1's crl.pem and verify < 500ms propagation to Node 2 & Node 3!
	leafClient, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  fix.caDir,
		OutDir: filepath.Join(t.TempDir(), "client-x"),
		Type:   pki.TypeClient,
		Name:   "client-x",
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}

	startRevoke := time.Now()
	if _, err := pki.RevokeCert(pki.RevokeCertOptions{
		CADir:        fix.caDir,
		SerialNumber: leafClient.Serial,
		CRLOut:       n1.crlPath,
	}); err != nil {
		t.Fatalf("RevokeCert(leafClient): %v", err)
	}

	waitForCondition(t, 450*time.Millisecond, "automatic CRL broadcast to node-2 and node-3 within < 500ms", func() bool {
		return n2.watcher.IsRevoked(leafClient.Serial) && n3.watcher.IsRevoked(leafClient.Serial)
	})
	t.Logf("CRL propagated across 3 nodes via AddReloadListener in %s", time.Since(startRevoke))

	// 6b. Now revoke compromised peer-3's OWN server/peer certificate serial on Node 1!
	peer3Serial, err := pki.ParseSerialHex(n3.certSerial)
	if err != nil {
		t.Fatalf("ParseSerialHex(peer-3): %v", err)
	}
	if _, err := pki.RevokeCert(pki.RevokeCertOptions{
		CADir:        fix.caDir,
		SerialNumber: peer3Serial,
		CRLOut:       n1.crlPath,
	}); err != nil {
		t.Fatalf("RevokeCert(peer-3): %v", err)
	}

	waitForCondition(t, 450*time.Millisecond, "peer-3 revocation propagated to node-1 and node-2", func() bool {
		return n1.watcher.IsRevoked(peer3Serial) && n2.watcher.IsRevoked(peer3Serial)
	})

	// Existing pooled HTTP/2 connection from peer3Client MUST be cut off immediately!
	if _, err := peer3Client.Status(context.Background()); err == nil || !strings.Contains(err.Error(), "Revoked") {
		t.Fatalf("expected pooled HTTP/2 connection from revoked peer-3 to be rejected as Revoked, got: %v", err)
	}

	// Brand-new TLS 1.3 handshake from peer-3's certificate to Node 2 MUST be rejected at TLS handshake (TLS alert bad certificate)!
	peer3FreshClient, err := NewClient(&config.ResolvedClusterConfig{
		ClusterAddr: n2.engine.Addr(),
		CertPath:    n3.certPath,
		KeyPath:     n3.keyPath,
		CAPath:      n3.caPath,
		Timeout:     5 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient(peer3Fresh): %v", err)
	}
	defer peer3FreshClient.Close()

	_, freshErr := peer3FreshClient.Peers(context.Background())
	if freshErr == nil || (!strings.Contains(freshErr.Error(), "bad certificate") &&
		!strings.Contains(freshErr.Error(), "certificate revoked") &&
		!strings.Contains(freshErr.Error(), "Revoked")) {
		t.Fatalf("expected fresh TLS 1.3 handshake from revoked peer-3 to Node 2 to fail TLS handshake, got: %v", freshErr)
	}

	// Outbound peer-to-peer dial from Node 2 to compromised peer-3 MUST also reject peer-3's server cert locally as Revoked!
	outboundErr := n2.engine.pushPullWithAddr(context.Background(), n3.engine.Addr(), false)
	if outboundErr == nil || !strings.Contains(outboundErr.Error(), "Revoked") {
		t.Fatalf("expected outbound TLS 1.3 dial from Node 2 to revoked peer-3 to fail with Revoked, got: %v", outboundErr)
	}

	// Verify peer-3 is evicted to PeerUnreachable on Node 1 and Node 2 while Node 1 + Node 2 retain 2/3 majority quorum!
	waitForCondition(t, time.Second, "revoked peer-3 marked unreachable on node-1 and node-2", func() bool {
		s1 := n1.engine.Status()
		s2 := n2.engine.Status()
		return s1.HasQuorum && s2.HasQuorum && s1.AliveNodes == 2 && s2.AliveNodes == 2 && s1.QuorumState == QuorumDegradedQuorum
	})
}

// 7. Cluster Admin Client (Status, Peers, CreateToken, Sync with ExecutionPolicy) & Tamper Rejection
func TestClusterAdminClientAndSignedPolicyTamperRejection(t *testing.T) {
	fix := newTestPKIFixture(t)

	n1 := startPreIssuedTestNode(t, fix, "admin-target-1", true, nil)
	n2 := startPreIssuedTestNode(t, fix, "admin-target-2", false, []string{n1.engine.Addr()})

	waitForCondition(t, 3*time.Second, "2-node cluster ready for admin client", func() bool {
		return n1.engine.Status().AliveNodes == 2 && n2.engine.Status().AliveNodes == 2
	})

	cli1, err := NewClient(&config.ResolvedClusterConfig{
		ClusterAddr: n1.engine.Addr(),
		CertPath:    fix.adminCert.CertPath,
		KeyPath:     fix.adminCert.KeyPath,
		CAPath:      fix.caRes.CACertPath,
		Timeout:     10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient(cli1): %v", err)
	}
	defer cli1.Close()

	cli2, err := NewClient(&config.ResolvedClusterConfig{
		ClusterAddr: n2.engine.Addr(),
		CertPath:    fix.adminCert.CertPath,
		KeyPath:     fix.adminCert.KeyPath,
		CAPath:      fix.caRes.CACertPath,
		Timeout:     10 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient(cli2): %v", err)
	}
	defer cli2.Close()

	// Verify wrong-CA client is rejected by cluster mTLS listener.
	wrongAdmin, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  fix.wrongCADir,
		OutDir: filepath.Join(t.TempDir(), "wrong-admin"),
		Type:   pki.TypeClient,
		Name:   "rogue-admin",
	})
	if err != nil {
		t.Fatalf("IssueCert(wrongAdmin): %v", err)
	}
	rogueCli, err := NewClient(&config.ResolvedClusterConfig{
		ClusterAddr: n1.engine.Addr(),
		CertPath:    wrongAdmin.CertPath,
		KeyPath:     wrongAdmin.KeyPath,
		CAPath:      fix.caRes.CACertPath,
		Timeout:     3 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewClient(rogue): %v", err)
	}
	defer rogueCli.Close()
	if _, err := rogueCli.Status(context.Background()); err == nil {
		t.Fatal("expected rogue wrong-CA admin client to fail mTLS handshake")
	}

	// Admin Status & Peers
	st, err := cli1.Status(context.Background())
	if err != nil {
		t.Fatalf("cli1.Status: %v", err)
	}
	if st.TotalNodes != 2 || st.AliveNodes != 2 || !st.HasQuorum {
		t.Fatalf("unexpected Status from cli1: %+v", st)
	}

	peers, err := cli2.Peers(context.Background())
	if err != nil {
		t.Fatalf("cli2.Peers: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("expected 2 peers from cli2.Peers, got %d", len(peers))
	}

	// Admin CreateToken on node-1 -> verify node-3 can BootstrapJoin via node-2!
	tokResp, err := cli1.CreateToken(context.Background(), 10*time.Minute, "admin-joined-3")
	if err != nil {
		t.Fatalf("cli1.CreateToken: %v", err)
	}
	if tokResp.Token == "" || tokResp.BoundNodeID != "admin-joined-3" {
		t.Fatalf("unexpected TokenCreateResponse: %+v", tokResp)
	}

	// Trigger Sync so token is immediately guaranteed on node-2 before join.
	if _, err := cli1.Sync(context.Background(), SyncRequest{}); err != nil {
		t.Fatalf("cli1.Sync: %v", err)
	}

	n3Dir := filepath.Join(t.TempDir(), "admin-joined-3")
	if _, err := BootstrapJoin(context.Background(), BootstrapJoinOptions{
		JoinAddr:        n2.engine.Addr(),
		JoinToken:       tokResp.Token,
		NodeID:          "admin-joined-3",
		ClusterBindAddr: "127.0.0.1:0",
		CertPath:        filepath.Join(n3Dir, "server.crt"),
		KeyPath:         filepath.Join(n3Dir, "server.key"),
		CAPath:          filepath.Join(n3Dir, "ca.crt"),
		CRLPath:         filepath.Join(n3Dir, "crl.pem"),
		StatePath:       filepath.Join(n3Dir, "cluster-state.json"),
	}); err != nil {
		t.Fatalf("BootstrapJoin(admin-joined-3 via node-2) failed: %v", err)
	}

	n3 := startBootstrappedNodeEngine(
		t,
		"admin-joined-3",
		filepath.Join(n3Dir, "server.crt"),
		filepath.Join(n3Dir, "server.key"),
		filepath.Join(n3Dir, "ca.crt"),
		filepath.Join(n3Dir, "crl.pem"),
		filepath.Join(n3Dir, "cluster-state.json"),
		"",
		[]string{n2.engine.Addr()},
	)

	waitForCondition(t, 3*time.Second, "3-node cluster converged", func() bool {
		return n1.engine.Status().AliveNodes == 3 && n3.engine.Status().AliveNodes == 3
	})

	// Admin Sync with ExecutionPolicy update on cli2 (non-CA node signing with its dual-EKU peer cert!)
	syncRes, err := cli2.Sync(context.Background(), SyncRequest{
		PolicyUpdate: &protocol.ExecutionPolicy{
			DefaultTimeoutSeconds: 42,
			MaxTimeoutSeconds:     240,
			DefaultShell:          "sh",
			EnforceClientACL:      true,
			AllowedClients:        []string{"cluster-admin", "ci-bot"},
		},
	})
	if err != nil {
		t.Fatalf("cli2.Sync(PolicyUpdate): %v", err)
	}
	if !syncRes.PolicyUpdated || syncRes.PolicyVersion != 1 {
		t.Fatalf("unexpected SyncResult: %+v", syncRes)
	}

	waitForCondition(t, 2*time.Second, "ExecutionPolicy replicated across all 3 nodes", func() bool {
		p1 := n1.engine.ExecutionPolicy()
		p2 := n2.engine.ExecutionPolicy()
		p3 := n3.engine.ExecutionPolicy()
		return p1.Version == 1 && p2.Version == 1 && p3.Version == 1 &&
			p1.DefaultTimeoutSeconds == 42 && p3.DefaultTimeoutSeconds == 42
	})

	// Tampered SignedPolicyEnvelope verification tests:
	caCert, caPool, err := pki.LoadCACertPool(fix.caRes.CACertPath)
	if err != nil {
		t.Fatalf("LoadCACertPool: %v", err)
	}
	_, caKey, err := pki.LoadCAKeyPair(fix.caRes.CACertPath, fix.caRes.CAKeyPath)
	if err != nil {
		t.Fatalf("LoadCAKeyPair: %v", err)
	}

	validEnv, err := SignPolicyEnvelope(
		protocol.ExecutionPolicy{
			Version:               99,
			UpdatedAtUnix:         time.Now().UTC().Unix(),
			DefaultTimeoutSeconds: 10,
			EnforceClientACL:      false,
		},
		"attacker-node",
		caCert,
		caKey,
	)
	if err != nil {
		t.Fatalf("SignPolicyEnvelope: %v", err)
	}
	if err := validEnv.Verify(caCert, caPool, n1.watcher); err != nil {
		t.Fatalf("expected untampered envelope to pass Verify, got: %v", err)
	}

	// Tamper with DefaultTimeoutSeconds while keeping version=99 & original signature!
	tamperedEnv := validEnv.Clone()
	tamperedEnv.Policy.DefaultTimeoutSeconds = 600
	if err := tamperedEnv.Verify(caCert, caPool, n1.watcher); err == nil {
		t.Fatal("expected tampered policy envelope to fail Verify")
	}

	// Attempt to inject tampered higher-version policy (Version=99) into n1 via gossip merge -> MUST be rejected!
	n1.engine.mergeGossipPayload(context.Background(), GossipPayload{
		SignedPolicy: tamperedEnv,
	}, "admin-target-2", false)

	if got := n1.engine.ExecutionPolicy(); got.Version != 1 || got.DefaultTimeoutSeconds != 42 {
		raw, _ := json.Marshal(got)
		t.Fatalf("security failure: tampered policy overwrote active policy: %s", raw)
	}

	// Also verify a policy signed by a wrong-CA key is rejected!
	_, wrongCAKey, err := pki.LoadCAKeyPair(fix.wrongCARes.CACertPath, fix.wrongCARes.CAKeyPath)
	if err != nil {
		t.Fatalf("LoadCAKeyPair(wrong): %v", err)
	}
	wrongCAEnv, err := SignPolicyEnvelope(
		protocol.ExecutionPolicy{Version: 100, DefaultTimeoutSeconds: 5},
		"rogue",
		fix.wrongCARes.Certificate,
		wrongCAKey,
	)
	if err != nil {
		t.Fatalf("SignPolicyEnvelope(wrongCA): %v", err)
	}
	if err := wrongCAEnv.Verify(caCert, caPool, n1.watcher); err == nil {
		t.Fatal("expected wrong-CA signed policy envelope to fail Verify")
	}
}

func TestQuorumEvaluationMatrix(t *testing.T) {
	// N=1
	q1 := EvaluateQuorum("node-1", []PeerInfo{
		{NodeID: "node-1", ClusterAddr: "10.0.0.1:8444", State: PeerAlive, JoinedAtUnix: 100},
	})
	if q1.Topology != TopologySingleNode || q1.QuorumState != QuorumHealthy || !q1.HasQuorum || !q1.IsLeader || q1.LeaderID != "node-1" {
		t.Fatalf("unexpected N=1 quorum: %+v", q1)
	}

	// N=2: HasCAKey priority beats earlier JoinedAtUnix and smaller NodeID
	q2Healthy := EvaluateQuorum("node-1", []PeerInfo{
		{NodeID: "node-1", ClusterAddr: "10.0.0.1:8444", HasCAKey: false, JoinedAtUnix: 100, State: PeerAlive},
		{NodeID: "node-2", ClusterAddr: "10.0.0.2:8444", HasCAKey: true, JoinedAtUnix: 200, State: PeerAlive},
	})
	if q2Healthy.Topology != TopologyTwoNode || q2Healthy.QuorumState != QuorumHealthy || !q2Healthy.HasQuorum || q2Healthy.LeaderID != "node-2" || q2Healthy.IsLeader {
		t.Fatalf("unexpected N=2 healthy quorum: %+v", q2Healthy)
	}

	// N=2 failover: 1/2 alive -> degraded-two-node-failover, survivor becomes leader
	q2Failover := EvaluateQuorum("node-1", []PeerInfo{
		{NodeID: "node-1", ClusterAddr: "10.0.0.1:8444", HasCAKey: false, JoinedAtUnix: 200, State: PeerAlive},
		{NodeID: "node-2", ClusterAddr: "10.0.0.2:8444", HasCAKey: true, JoinedAtUnix: 100, State: PeerUnreachable},
	})
	if q2Failover.QuorumState != QuorumDegradedTwoNodeFailover || !q2Failover.HasQuorum || !q2Failover.IsLeader || q2Failover.LeaderID != "node-1" {
		t.Fatalf("unexpected N=2 failover quorum: %+v", q2Failover)
	}

	// N=5: QuorumRequired == 3; 3/5 -> degraded-quorum; 2/5 -> minority-partition
	peers5 := []PeerInfo{
		{NodeID: "n1", JoinedAtUnix: 500, State: PeerAlive},
		{NodeID: "n2", JoinedAtUnix: 100, State: PeerAlive},
		{NodeID: "n3", JoinedAtUnix: 100, State: PeerAlive},
		{NodeID: "n4", JoinedAtUnix: 50, State: PeerUnreachable},
		{NodeID: "n5", JoinedAtUnix: 60, State: PeerSuspect},
	}
	q5Maj := EvaluateQuorum("n1", peers5)
	if q5Maj.Topology != TopologyMultiNodeQuorum || q5Maj.QuorumRequired != 3 || !q5Maj.HasQuorum || q5Maj.QuorumState != QuorumDegradedQuorum || q5Maj.LeaderID != "n2" {
		t.Fatalf("unexpected N=5 3/5 quorum (tie broken by JoinedAtUnix=100 then smallest NodeID=n2): %+v", q5Maj)
	}

	peers5[2].State = PeerUnreachable
	q5Min := EvaluateQuorum("n1", peers5)
	if q5Min.HasQuorum || q5Min.QuorumState != QuorumMinorityPartition || q5Min.LeaderID != "" || q5Min.IsLeader {
		t.Fatalf("unexpected N=5 2/5 minority quorum: %+v", q5Min)
	}
}

func TestSignedPolicyMonotonicComparisonAndRevokedSigner(t *testing.T) {
	fix := newTestPKIFixture(t)
	caCert, caPool, err := pki.LoadCACertPool(fix.caRes.CACertPath)
	if err != nil {
		t.Fatalf("LoadCACertPool: %v", err)
	}
	watcher, err := pki.NewCRLWatcher(fix.caRes.CRLPath, caCert, nil, nil)
	if err != nil {
		t.Fatalf("NewCRLWatcher: %v", err)
	}
	defer watcher.Close()

	signerRes, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  fix.caDir,
		OutDir: filepath.Join(t.TempDir(), "signer"),
		Type:   pki.TypePeer,
		Name:   "signer-peer",
	})
	if err != nil {
		t.Fatalf("IssueCert(signer): %v", err)
	}
	signerKey, err := pki.LoadPrivateKey(signerRes.KeyPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey: %v", err)
	}

	envA, err := SignPolicyEnvelope(protocol.ExecutionPolicy{Version: 2, UpdatedAtUnix: 1000}, "node-a", signerRes.Certificate, signerKey)
	if err != nil {
		t.Fatalf("SignPolicyEnvelope(envA): %v", err)
	}
	envB, err := SignPolicyEnvelope(protocol.ExecutionPolicy{Version: 2, UpdatedAtUnix: 1001}, "node-a", signerRes.Certificate, signerKey)
	if err != nil {
		t.Fatalf("SignPolicyEnvelope(envB): %v", err)
	}
	envC, err := SignPolicyEnvelope(protocol.ExecutionPolicy{Version: 2, UpdatedAtUnix: 1001}, "node-z", signerRes.Certificate, signerKey)
	if err != nil {
		t.Fatalf("SignPolicyEnvelope(envC): %v", err)
	}

	if !envB.IsNewerThan(envA) || envA.IsNewerThan(envB) {
		t.Fatal("expected UpdatedAtUnix tie-break to favor envB over envA")
	}
	if !envC.IsNewerThan(envB) || envB.IsNewerThan(envC) {
		t.Fatal("expected SignerNodeID tie-break to be strict and antisymmetric")
	}
	if envC.IsNewerThan(envC.Clone()) {
		t.Fatal("identical policy envelope must not report IsNewerThan=true")
	}

	if err := envC.Verify(caCert, caPool, watcher); err != nil {
		t.Fatalf("expected unrevoked signer envelope to verify: %v", err)
	}

	// Revoke signer-peer and confirm Verify rejects policies signed by the revoked certificate!
	if _, err := pki.RevokeCert(pki.RevokeCertOptions{
		CADir:        fix.caDir,
		SerialNumber: signerRes.Serial,
		CRLOut:       fix.caRes.CRLPath,
	}); err != nil {
		t.Fatalf("RevokeCert(signer): %v", err)
	}
	if err := watcher.ReloadNow(); err != nil {
		t.Fatalf("ReloadNow: %v", err)
	}
	if err := envC.Verify(caCert, caPool, watcher); err == nil || !strings.Contains(err.Error(), "Revoked") {
		t.Fatalf("expected revoked policy signer to fail Verify with Revoked, got: %v", err)
	}
}

func newRawMTLSHTTPClientForTest(t *testing.T, certPath, keyPath, caPath string) *http.Client {
	t.Helper()
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair(%s): %v", certPath, err)
	}
	_, caPool, err := pki.LoadCACertPool(caPath)
	if err != nil {
		t.Fatalf("LoadCACertPool(%s): %v", caPath, err)
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: []tls.Certificate{pair},
			RootCAs:      caPool,
		},
		ForceAttemptHTTP2: true,
	}
	t.Cleanup(func() {
		tr.CloseIdleConnections()
	})
	return &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}
}

func doJSONRequestForTest(
	t *testing.T,
	httpCli *http.Client,
	method string,
	url string,
	body any,
) (int, string) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("json.Marshal: %v", err)
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, reader)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := httpCli.Do(req)
	if err != nil {
		t.Fatalf("%s %s transport error: %v", method, url, err)
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	return resp.StatusCode, string(respBytes)
}

// PoC 1A Regression: EnforceClientACL restricts ClientAuth-only certificates on all operator/admin
// routes (/sync, /tokens, /status, /peers) while admitting authorized AllowedClients and ServerAuth peer certs.
func TestAdversarialPoC1AClientACLEnforcementOnAdminRoutes(t *testing.T) {
	fix := newTestPKIFixture(t)
	n1 := startPreIssuedTestNode(t, fix, "acl-node-1", true, nil)

	adminC2, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  fix.caDir,
		OutDir: filepath.Join(t.TempDir(), "admin-c2"),
		Type:   pki.TypeClient,
		Name:   "admin-c2",
	})
	if err != nil {
		t.Fatalf("IssueCert(admin-c2): %v", err)
	}

	restrictedC3, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  fix.caDir,
		OutDir: filepath.Join(t.TempDir(), "restricted-c3"),
		Type:   pki.TypeClient,
		Name:   "restricted-c3",
	})
	if err != nil {
		t.Fatalf("IssueCert(restricted-c3): %v", err)
	}

	// Activate ExecutionPolicy with EnforceClientACL=true allowing ONLY "admin-c2".
	if _, err := n1.engine.Sync(context.Background(), SyncRequest{
		PolicyUpdate: &protocol.ExecutionPolicy{
			DefaultTimeoutSeconds: 30,
			MaxTimeoutSeconds:     120,
			EnforceClientACL:      true,
			AllowedClients:        []string{"admin-c2"},
		},
	}); err != nil {
		t.Fatalf("n1.engine.Sync(PolicyUpdate): %v", err)
	}

	baseURL := "https://" + n1.engine.Addr()
	restrictedHTTP := newRawMTLSHTTPClientForTest(t, restrictedC3.CertPath, restrictedC3.KeyPath, fix.caRes.CACertPath)
	adminHTTP := newRawMTLSHTTPClientForTest(t, adminC2.CertPath, adminC2.KeyPath, fix.caRes.CACertPath)
	nodeServerHTTP := newRawMTLSHTTPClientForTest(t, n1.certPath, n1.keyPath, fix.caRes.CACertPath)

	// 1. restricted-c3 (--type client NOT in AllowedClients) MUST get HTTP 403 on all 4 admin routes,
	// including an attempt to self-escalate by posting EnforceClientACL=false to /cluster/v1/sync!
	code, body := doJSONRequestForTest(t, restrictedHTTP, http.MethodPost, baseURL+pathClusterSync, SyncRequest{
		PolicyUpdate: &protocol.ExecutionPolicy{
			EnforceClientACL: false,
		},
	})
	if code != http.StatusForbidden || !strings.Contains(body, "not authorized by cluster execution policy") {
		t.Fatalf("expected HTTP 403 for restricted-c3 on %s, got %d: %s", pathClusterSync, code, body)
	}
	if pol := n1.engine.ExecutionPolicy(); !pol.EnforceClientACL || pol.Version != 1 {
		t.Fatalf("security failure: restricted-c3 mutated cluster ExecutionPolicy: %+v", pol)
	}

	code, body = doJSONRequestForTest(t, restrictedHTTP, http.MethodPost, baseURL+pathClusterTokens, TokenCreateRequest{TTLSeconds: 300})
	if code != http.StatusForbidden || !strings.Contains(body, "not authorized by cluster execution policy") {
		t.Fatalf("expected HTTP 403 for restricted-c3 on %s, got %d: %s", pathClusterTokens, code, body)
	}

	code, body = doJSONRequestForTest(t, restrictedHTTP, http.MethodGet, baseURL+pathClusterStatus, nil)
	if code != http.StatusForbidden || !strings.Contains(body, "not authorized by cluster execution policy") {
		t.Fatalf("expected HTTP 403 for restricted-c3 on %s, got %d: %s", pathClusterStatus, code, body)
	}

	code, body = doJSONRequestForTest(t, restrictedHTTP, http.MethodGet, baseURL+pathClusterPeers, nil)
	if code != http.StatusForbidden || !strings.Contains(body, "not authorized by cluster execution policy") {
		t.Fatalf("expected HTTP 403 for restricted-c3 on %s, got %d: %s", pathClusterPeers, code, body)
	}

	// 2. admin-c2 (--type client listed in AllowedClients) MUST succeed on all 4 admin routes!
	for _, tc := range []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, pathClusterStatus, nil},
		{http.MethodGet, pathClusterPeers, nil},
		{http.MethodPost, pathClusterTokens, TokenCreateRequest{TTLSeconds: 300}},
		{http.MethodPost, pathClusterSync, SyncRequest{}},
	} {
		gotCode, gotBody := doJSONRequestForTest(t, adminHTTP, tc.method, baseURL+tc.path, tc.body)
		if gotCode != http.StatusOK {
			t.Fatalf("expected HTTP 200 for authorized admin-c2 on %s, got %d: %s", tc.path, gotCode, gotBody)
		}
	}

	// 3. Node 1's own ServerAuth certificate MUST succeed on all 4 admin routes regardless of AllowedClients!
	for _, tc := range []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, pathClusterStatus, nil},
		{http.MethodGet, pathClusterPeers, nil},
		{http.MethodPost, pathClusterTokens, TokenCreateRequest{TTLSeconds: 300}},
		{http.MethodPost, pathClusterSync, SyncRequest{}},
	} {
		gotCode, gotBody := doJSONRequestForTest(t, nodeServerHTTP, tc.method, baseURL+tc.path, tc.body)
		if gotCode != http.StatusOK {
			t.Fatalf("expected HTTP 200 for ServerAuth node cert on %s, got %d: %s", tc.path, gotCode, gotBody)
		}
	}
}

// PoC 1B Regression: ANY --type client certificate (even an authorized admin-c2 in AllowedClients)
// MUST be rejected with HTTP 403 on internal peer mesh routes (/sign-join, /sync-push, /sync-pull).
func TestAdversarialPoC1BPeerMeshServerAuthEKUBoundary(t *testing.T) {
	fix := newTestPKIFixture(t)
	n1 := startPreIssuedTestNode(t, fix, "mesh-node-1", true, nil)

	adminC2, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  fix.caDir,
		OutDir: filepath.Join(t.TempDir(), "admin-c2"),
		Type:   pki.TypeClient,
		Name:   "admin-c2",
	})
	if err != nil {
		t.Fatalf("IssueCert(admin-c2): %v", err)
	}

	if _, err := n1.engine.Sync(context.Background(), SyncRequest{
		PolicyUpdate: &protocol.ExecutionPolicy{
			EnforceClientACL: true,
			AllowedClients:   []string{"admin-c2"},
		},
	}); err != nil {
		t.Fatalf("n1.engine.Sync: %v", err)
	}

	baseURL := "https://" + n1.engine.Addr()
	adminHTTP := newRawMTLSHTTPClientForTest(t, adminC2.CertPath, adminC2.KeyPath, fix.caRes.CACertPath)

	// Generate a CSR and forged TokenRecord attempting PoC 1B direct /cluster/v1/sign-join minting!
	_, _, csrPEM, err := pki.GenerateKeyAndCSR("forged-peer", []string{"127.0.0.1"}, []string{"localhost"})
	if err != nil {
		t.Fatalf("GenerateKeyAndCSR: %v", err)
	}
	rawTok, forgedRec, _, err := GenerateJoinToken(fix.caRes.Certificate, "admin-c2", "forged-peer", 5*time.Minute, time.Now().UTC())
	if err != nil {
		t.Fatalf("GenerateJoinToken: %v", err)
	}

	code, body := doJSONRequestForTest(t, adminHTTP, http.MethodPost, baseURL+pathClusterSignJoin, signJoinForwardRequest{
		JoinRequest: JoinRequest{
			Token:       rawTok,
			NodeID:      "forged-peer",
			ClusterAddr: "127.0.0.1:18444",
			CSRPEM:      string(csrPEM),
		},
		ObservedRemoteIP: "127.0.0.1",
		TokenRecord:      &forgedRec,
	})
	if code != http.StatusForbidden || !strings.Contains(body, "cluster peer certificate with ServerAuth EKU required") {
		t.Fatalf("expected HTTP 403 on %s for --type client cert, got %d: %s", pathClusterSignJoin, code, body)
	}

	code, body = doJSONRequestForTest(t, adminHTTP, http.MethodPost, baseURL+pathClusterSyncPush, GossipPayload{
		Sender: PeerInfo{NodeID: "admin-c2", ClusterAddr: "127.0.0.1:18445", State: PeerAlive},
	})
	if code != http.StatusForbidden || !strings.Contains(body, "cluster peer certificate with ServerAuth EKU required") {
		t.Fatalf("expected HTTP 403 on %s for --type client cert, got %d: %s", pathClusterSyncPush, code, body)
	}

	code, body = doJSONRequestForTest(t, adminHTTP, http.MethodGet, baseURL+pathClusterSyncPull, nil)
	if code != http.StatusForbidden || !strings.Contains(body, "cluster peer certificate with ServerAuth EKU required") {
		t.Fatalf("expected HTTP 403 on %s for --type client cert, got %d: %s", pathClusterSyncPull, code, body)
	}
}

// Policy Signer EKU Regression: A valid, unrevoked --type client leaf certificate MUST NEVER pass
// SignedPolicyEnvelope.Verify or overwrite ExecutionPolicy via gossip.
func TestAdversarialPolicySignerRequiresServerAuthEKU(t *testing.T) {
	fix := newTestPKIFixture(t)
	n1 := startPreIssuedTestNode(t, fix, "pol-eku-node-1", true, nil)

	caCert, caPool, err := pki.LoadCACertPool(fix.caRes.CACertPath)
	if err != nil {
		t.Fatalf("LoadCACertPool: %v", err)
	}

	clientCertRes, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  fix.caDir,
		OutDir: filepath.Join(t.TempDir(), "client-signer"),
		Type:   pki.TypeClient,
		Name:   "client-signer",
	})
	if err != nil {
		t.Fatalf("IssueCert(client-signer): %v", err)
	}
	clientKey, err := pki.LoadPrivateKey(clientCertRes.KeyPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey(client-signer): %v", err)
	}

	forgedEnv, err := SignPolicyEnvelope(
		protocol.ExecutionPolicy{
			Version:               9999,
			UpdatedAtUnix:         time.Now().UTC().Unix(),
			DefaultTimeoutSeconds: 600,
			EnforceClientACL:      false,
		},
		"client-signer",
		clientCertRes.Certificate,
		clientKey,
	)
	if err != nil {
		t.Fatalf("SignPolicyEnvelope(client-signer): %v", err)
	}

	verifyErr := forgedEnv.Verify(caCert, caPool, n1.watcher)
	if verifyErr == nil || !strings.Contains(verifyErr.Error(), "ServerAuth") {
		t.Fatalf("expected SignedPolicyEnvelope.Verify to reject --type client signer for missing ServerAuth EKU, got: %v", verifyErr)
	}

	// Ensure gossip merge also rejects the Version=9999 client-signed policy envelope.
	n1.engine.mergeGossipPayload(context.Background(), GossipPayload{
		SignedPolicy: forgedEnv,
	}, "external-peer", false)
	if got := n1.engine.ExecutionPolicy(); got.Version != 0 {
		t.Fatalf("security failure: client-signed policy envelope was accepted into Engine state: %+v", got)
	}
}

// [POLISH-1] Regression: Persisted cluster-state.json containing a SignedPolicy signed by a node
// certificate that has since been revoked in crl.pem MUST be rejected by NewEngine at startup.
func TestStartupRejectsPersistedPolicyFromRevokedSigner(t *testing.T) {
	fix := newTestPKIFixture(t)

	// Issue a peer certificate for compromised-node-2 and sign a policy envelope with its key (NOT CA key).
	compPeer, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:    fix.caDir,
		OutDir:   filepath.Join(t.TempDir(), "comp-peer"),
		Type:     pki.TypePeer,
		Name:     "comp-peer",
		IPs:      []string{"127.0.0.1"},
		DNSNames: []string{"localhost"},
	})
	if err != nil {
		t.Fatalf("IssueCert(comp-peer): %v", err)
	}
	compKey, err := pki.LoadPrivateKey(compPeer.KeyPath)
	if err != nil {
		t.Fatalf("LoadPrivateKey(comp-peer): %v", err)
	}

	signedByComp, err := SignPolicyEnvelope(
		protocol.ExecutionPolicy{
			Version:               77,
			UpdatedAtUnix:         time.Now().UTC().Unix(),
			DefaultTimeoutSeconds: 123,
			EnforceClientACL:      false,
		},
		"comp-peer",
		compPeer.Certificate,
		compKey,
	)
	if err != nil {
		t.Fatalf("SignPolicyEnvelope(comp-peer): %v", err)
	}

	// Prepare survivor-node-1's directory, persist cluster-state.json with signedByComp, THEN revoke comp-peer in crl.pem!
	n1Dir := filepath.Join(t.TempDir(), "survivor-node-1")
	n1Issued, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:    fix.caDir,
		OutDir:   n1Dir,
		Type:     pki.TypePeer,
		Name:     "survivor-node-1",
		IPs:      []string{"127.0.0.1"},
		DNSNames: []string{"localhost"},
	})
	if err != nil {
		t.Fatalf("IssueCert(survivor-node-1): %v", err)
	}
	caPath := filepath.Join(n1Dir, pki.CACertFilename)
	crlPath := filepath.Join(n1Dir, pki.CRLFilename)
	statePath := filepath.Join(n1Dir, "cluster-state.json")
	copyFileForTest(t, fix.caRes.CACertPath, caPath, 0o644)

	if err := savePersistedState(statePath, &persistedClusterState{
		SchemaVersion: currentStateSchemaVersion,
		Bootstrapped:  true,
		NodeID:        "survivor-node-1",
		Incarnation:   3,
		JoinedAtUnix:  time.Now().UTC().Add(-time.Hour).Unix(),
		SignedPolicy:  signedByComp,
	}); err != nil {
		t.Fatalf("savePersistedState: %v", err)
	}

	// Revoke comp-peer in survivor-node-1's CRL before starting NewEngine!
	if _, err := pki.RevokeCert(pki.RevokeCertOptions{
		CADir:        fix.caDir,
		SerialNumber: compPeer.Serial,
		CRLOut:       crlPath,
	}); err != nil {
		t.Fatalf("RevokeCert(comp-peer): %v", err)
	}

	caCert, _, err := pki.LoadCACertPool(caPath)
	if err != nil {
		t.Fatalf("LoadCACertPool: %v", err)
	}
	watcher, err := pki.NewCRLWatcher(crlPath, caCert, nil, nil)
	if err != nil {
		t.Fatalf("NewCRLWatcher: %v", err)
	}
	defer watcher.Close()

	eng, err := NewEngine(Config{
		NodeID:          "survivor-node-1",
		ClusterBindAddr: "127.0.0.1:0",
		CertPath:        n1Issued.CertPath,
		KeyPath:         n1Issued.KeyPath,
		CAPath:          caPath,
		StatePath:       statePath,
		CRLWatcher:      watcher,
		Logger:          log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("NewEngine(survivor-node-1): %v", err)
	}
	defer eng.Close()

	if got := eng.ExecutionPolicy(); got.Version != 0 || got.DefaultTimeoutSeconds != 0 {
		t.Fatalf("expected persisted policy signed by revoked cert to be rejected on startup, got: %+v", got)
	}
}

// [POLISH-4] Regression: Prevent peer certificates from spoofing self or another peer's NodeID in
// gossip while preserving legitimate re-enrollment with a fresh certificate for the matching CN.
func TestGossipSenderIdentitySpoofingAndReEnrollment(t *testing.T) {
	fix := newTestPKIFixture(t)

	n1 := startPreIssuedTestNode(t, fix, "spoof-guard-1", true, nil)
	n2 := startPreIssuedTestNode(t, fix, "spoof-guard-2", false, []string{n1.engine.Addr()})
	n3 := startPreIssuedTestNode(t, fix, "spoof-guard-3", false, []string{n1.engine.Addr(), n2.engine.Addr()})

	waitForCondition(t, 3*time.Second, "3-node cluster converged", func() bool {
		return n1.engine.Status().AliveNodes == 3 &&
			n2.engine.Status().AliveNodes == 3 &&
			n3.engine.Status().AliveNodes == 3
	})

	n2PeerHTTP := newRawMTLSHTTPClientForTest(t, n2.certPath, n2.keyPath, fix.caRes.CACertPath)
	n1BaseURL := "https://" + n1.engine.Addr()

	// 1. Node 2 claiming to be target self ("spoof-guard-1") MUST be rejected with HTTP 403!
	code, body := doJSONRequestForTest(t, n2PeerHTTP, http.MethodPost, n1BaseURL+pathClusterSyncPush, GossipPayload{
		Sender: PeerInfo{
			NodeID:       "spoof-guard-1",
			ClusterAddr:  "127.0.0.1:29991",
			Incarnation:  999,
			State:        PeerAlive,
			JoinedAtUnix: time.Now().UTC().Add(time.Hour).Unix(),
		},
	})
	if code != http.StatusForbidden || !strings.Contains(body, "cannot claim local engine node_id") {
		t.Fatalf("expected HTTP 403 when node-2 claims self node_id spoof-guard-1, got %d: %s", code, body)
	}

	// 2. Node 2 (CN=spoof-guard-2) claiming Sender.NodeID="spoof-guard-3" (even with higher JoinedAtUnix!)
	// MUST be rejected with HTTP 403 because CN != "spoof-guard-3"!
	code, body = doJSONRequestForTest(t, n2PeerHTTP, http.MethodPost, n1BaseURL+pathClusterSyncPush, GossipPayload{
		Sender: PeerInfo{
			NodeID:       "spoof-guard-3",
			ClusterAddr:  "127.0.0.1:29993",
			Incarnation:  999,
			State:        PeerAlive,
			JoinedAtUnix: time.Now().UTC().Add(time.Hour).Unix(),
		},
	})
	if code != http.StatusForbidden || !strings.Contains(body, "cannot impersonate existing node") {
		t.Fatalf("expected HTTP 403 when node-2 impersonates spoof-guard-3, got %d: %s", code, body)
	}

	// Verify spoof-guard-3's ClusterAddr and CertSerialHex on n1 were NOT poisoned!
	for _, p := range n1.engine.Peers() {
		if p.NodeID == "spoof-guard-3" {
			if p.ClusterAddr == "127.0.0.1:29993" || !strings.EqualFold(p.CertSerialHex, n3.certSerial) {
				t.Fatalf("spoof-guard-3 peer record was poisoned: %+v", p)
			}
		}
	}

	// 3. Legitimate re-enrollment of spoof-guard-3 (e.g. wiped disk re-joining with a fresh CSR cert
	// where CN == "spoof-guard-3" and JoinedAtUnix advances) MUST succeed and gossip cleanly!
	_ = n3.engine.Close()
	rejoinTok, _, err := n1.engine.CreateJoinToken(5*time.Minute, "spoof-guard-3")
	if err != nil {
		t.Fatalf("CreateJoinToken(rejoin): %v", err)
	}
	rejoinDir := filepath.Join(t.TempDir(), "spoof-guard-3-rejoined")
	rejoinRes, err := BootstrapJoin(context.Background(), BootstrapJoinOptions{
		JoinAddr:        n1.engine.Addr(),
		JoinToken:       rejoinTok,
		NodeID:          "spoof-guard-3",
		ClusterBindAddr: "127.0.0.1:0",
		CertPath:        filepath.Join(rejoinDir, "server.crt"),
		KeyPath:         filepath.Join(rejoinDir, "server.key"),
		CAPath:          filepath.Join(rejoinDir, "ca.crt"),
		CRLPath:         filepath.Join(rejoinDir, "crl.pem"),
		StatePath:       filepath.Join(rejoinDir, "cluster-state.json"),
	})
	if err != nil {
		t.Fatalf("BootstrapJoin(re-enrolled spoof-guard-3): %v", err)
	}
	if strings.EqualFold(rejoinRes.CertSerialHex, n3.certSerial) {
		t.Fatal("expected fresh certificate serial on re-enrolled spoof-guard-3")
	}

	n3Rejoined := startBootstrappedNodeEngine(
		t,
		"spoof-guard-3",
		filepath.Join(rejoinDir, "server.crt"),
		filepath.Join(rejoinDir, "server.key"),
		filepath.Join(rejoinDir, "ca.crt"),
		filepath.Join(rejoinDir, "crl.pem"),
		filepath.Join(rejoinDir, "cluster-state.json"),
		"",
		[]string{n2.engine.Addr()}, // Seed via n2 so n2 validates re-enrolled CN=spoof-guard-3 + advanced JoinedAtUnix!
	)

	waitForCondition(t, 3*time.Second, "re-enrolled spoof-guard-3 accepted by both n1 and n2", func() bool {
		var n2SawNewSerial bool
		for _, p := range n2.engine.Peers() {
			if p.NodeID == "spoof-guard-3" && strings.EqualFold(p.CertSerialHex, n3Rejoined.certSerial) && p.State == PeerAlive {
				n2SawNewSerial = true
			}
		}
		return n1.engine.Status().AliveNodes == 3 &&
			n2.engine.Status().AliveNodes == 3 &&
			n3Rejoined.engine.Status().AliveNodes == 3 &&
			n2SawNewSerial
	})
}

func mustCIDRAddrForTest(t *testing.T, raw string) net.Addr {
	t.Helper()
	ip, ipNet, err := net.ParseCIDR(raw)
	if err != nil {
		t.Fatalf("ParseCIDR(%s): %v", raw, err)
	}
	return &net.IPNet{IP: ip, Mask: ipNet.Mask}
}

func TestMultiListenerClusterControlPlaneAndStartWithListeners(t *testing.T) {
	fix := newTestPKIFixture(t)
	nodeDir := filepath.Join(t.TempDir(), "multi-bind-node")
	issued, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:    fix.caDir,
		OutDir:   nodeDir,
		Type:     pki.TypePeer,
		Name:     "multi-bind-node",
		IPs:      []string{"127.0.0.1"},
		DNSNames: []string{"localhost"},
	})
	if err != nil {
		t.Fatalf("IssueCert: %v", err)
	}
	caPath := filepath.Join(nodeDir, pki.CACertFilename)
	crlPath := filepath.Join(nodeDir, pki.CRLFilename)
	statePath := filepath.Join(nodeDir, "cluster-state.json")
	copyFileForTest(t, fix.caRes.CACertPath, caPath, 0o644)
	copyFileForTest(t, fix.caRes.CRLPath, crlPath, 0o644)

	caCert, _, err := pki.LoadCACertPool(caPath)
	if err != nil {
		t.Fatalf("LoadCACertPool: %v", err)
	}
	watcher, err := pki.NewCRLWatcher(crlPath, caCert, nil, nil)
	if err != nil {
		t.Fatalf("NewCRLWatcher: %v", err)
	}
	t.Cleanup(func() { _ = watcher.Close() })

	ln1, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(ln1): %v", err)
	}
	ln2, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = ln1.Close()
		t.Fatalf("Listen(ln2): %v", err)
	}

	eng, err := NewEngine(Config{
		NodeID:             "multi-bind-node",
		ClusterBindAddrs:   []string{ln1.Addr().String(), ln2.Addr().String()},
		CertPath:           issued.CertPath,
		KeyPath:            issued.KeyPath,
		CAPath:             caPath,
		CAKeyPath:          fix.caRes.CAKeyPath,
		StatePath:          statePath,
		CRLWatcher:         watcher,
		GossipInterval:     testGossipInterval,
		SuspectTimeout:     testSuspectTimeout,
		UnreachableTimeout: testUnreachableTimeout,
		Logger:             log.New(io.Discard, "", 0),
	})
	if err != nil {
		_ = ln1.Close()
		_ = ln2.Close()
		t.Fatalf("NewEngine: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	if err := eng.StartWithListeners(ctx, []net.Listener{ln1, ln2}); err != nil {
		cancel()
		t.Fatalf("StartWithListeners: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		_ = eng.Close()
	})
	<-eng.Ready()

	bound := eng.BoundAddrs()
	if len(bound) != 2 || bound[0] != ln1.Addr().String() || bound[1] != ln2.Addr().String() {
		t.Fatalf("unexpected BoundAddrs(): %v (want [%s %s])", bound, ln1.Addr().String(), ln2.Addr().String())
	}

	// Verify both listeners serve authenticated mTLS ClusterStatus.
	for _, targetAddr := range bound {
		cli, cliErr := NewClient(&config.ResolvedClusterConfig{
			ClusterAddr: targetAddr,
			CertPath:    fix.adminCert.CertPath,
			KeyPath:     fix.adminCert.KeyPath,
			CAPath:      caPath,
			Timeout:     5 * time.Second,
		})
		if cliErr != nil {
			t.Fatalf("NewClient(%s): %v", targetAddr, cliErr)
		}
		st, stErr := cli.Status(context.Background())
		_ = cli.Close()
		if stErr != nil {
			t.Fatalf("Status(%s): %v", targetAddr, stErr)
		}
		if len(st.ClusterBindAddrs) != 2 {
			t.Fatalf("expected Status().ClusterBindAddrs to expose 2 listeners, got: %v", st.ClusterBindAddrs)
		}
	}
}

func TestMultiSeedBootstrapJoinFallbackAndHairpinSkip(t *testing.T) {
	fix := newTestPKIFixture(t)
	seedNode := startPreIssuedTestNode(t, fix, "seed-primary", true, nil)

	tok, _, err := seedNode.engine.CreateJoinToken(5*time.Minute, "fallback-joiner")
	if err != nil {
		t.Fatalf("CreateJoinToken: %v", err)
	}

	// Allocate and immediately close an ephemeral TCP listener to obtain a guaranteed dead port.
	deadLn, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(deadLn): %v", err)
	}
	deadAddr := deadLn.Addr().String()
	_ = deadLn.Close()

	mockProvider := netbind.InterfaceProviderFunc(func() ([]netbind.InterfaceInfo, error) {
		return []netbind.InterfaceInfo{
			{
				Index: 2,
				Name:  "eth0",
				Flags: net.FlagUp | net.FlagBroadcast,
				Addrs: []net.Addr{mustCIDRAddrForTest(t, "192.168.1.20/24")},
			},
			{
				Index: 3,
				Name:  "tailscale0",
				Flags: net.FlagUp | net.FlagPointToPoint,
				Addrs: []net.Addr{mustCIDRAddrForTest(t, "100.64.0.20/10")},
			},
		}, nil
	})
	mockRoute := func(targetAddr string) (net.IP, error) {
		if strings.HasPrefix(targetAddr, "192.168.1.") {
			// Simulate Tailscale --accept-routes hijacking local physical LAN traffic into 100.64.0.0/10!
			return net.ParseIP("100.64.0.20").To4(), nil
		}
		return net.ParseIP("127.0.0.1").To4(), nil
	}

	joinDir := filepath.Join(t.TempDir(), "fallback-joiner")
	// 1. Verify hairpinned-only seed fails fast with remediation WITHOUT consuming the single-use token!
	_, hairpinOnlyErr := BootstrapJoin(context.Background(), BootstrapJoinOptions{
		JoinAddr:          "192.168.1.50:8444",
		JoinToken:         tok,
		NodeID:            "fallback-joiner",
		ClusterBindAddr:   "127.0.0.1:0",
		CertPath:          filepath.Join(joinDir, "server.crt"),
		KeyPath:           filepath.Join(joinDir, "server.key"),
		CAPath:            filepath.Join(joinDir, "ca.crt"),
		CRLPath:           filepath.Join(joinDir, "crl.pem"),
		StatePath:         filepath.Join(joinDir, "cluster-state.json"),
		InterfaceProvider: mockProvider,
		RouteSourceIP:     mockRoute,
	})
	if hairpinOnlyErr == nil || !strings.Contains(hairpinOnlyErr.Error(), "--accept-routes=false") {
		t.Fatalf("expected outbound LAN hairpin error mentioning --accept-routes=false, got: %v", hairpinOnlyErr)
	}

	// 2. Now pass comma-separated seeds: [hairpinned LAN seed, dead seed, live seed] using the SAME single-use token!
	multiSeedSpec := strings.Join([]string{"192.168.1.50:8444", deadAddr, seedNode.engine.Addr()}, ",")
	res, err := BootstrapJoin(context.Background(), BootstrapJoinOptions{
		JoinAddr:          multiSeedSpec,
		JoinToken:         tok,
		NodeID:            "fallback-joiner",
		ClusterBindAddr:   "127.0.0.1:0",
		CertPath:          filepath.Join(joinDir, "server.crt"),
		KeyPath:           filepath.Join(joinDir, "server.key"),
		CAPath:            filepath.Join(joinDir, "ca.crt"),
		CRLPath:           filepath.Join(joinDir, "crl.pem"),
		StatePath:         filepath.Join(joinDir, "cluster-state.json"),
		InterfaceProvider: mockProvider,
		RouteSourceIP:     mockRoute,
	})
	if err != nil {
		t.Fatalf("BootstrapJoin multi-seed fallback failed: %v", err)
	}
	if res.SeedAddr != seedNode.engine.Addr() || len(res.SeedAddrs) != 2 || slices.Contains(res.SeedAddrs, "192.168.1.50:8444") {
		t.Fatalf("unexpected multi-seed BootstrapJoinResult: %+v", res)
	}

	// Verify persisted cluster-state.json retained SeedPeers!
	persisted, err := loadPersistedState(filepath.Join(joinDir, "cluster-state.json"))
	if err != nil {
		t.Fatalf("loadPersistedState: %v", err)
	}
	if !slices.Contains(persisted.SeedPeers, seedNode.engine.Addr()) {
		t.Fatalf("expected persisted SeedPeers to contain %s, got %v", seedNode.engine.Addr(), persisted.SeedPeers)
	}
}

func TestCollectNodeSANsAndAutoInterfaceSANHarvesting(t *testing.T) {
	fix := newTestPKIFixture(t)
	seedNode := startPreIssuedTestNode(t, fix, "san-seed-1", true, nil)

	tok, _, err := seedNode.engine.CreateJoinToken(5*time.Minute, "san-harvest-node")
	if err != nil {
		t.Fatalf("CreateJoinToken: %v", err)
	}

	mockProvider := netbind.InterfaceProviderFunc(func() ([]netbind.InterfaceInfo, error) {
		return []netbind.InterfaceInfo{
			{
				Index: 2,
				Name:  "eth0",
				Flags: net.FlagUp | net.FlagBroadcast,
				Addrs: []net.Addr{
					mustCIDRAddrForTest(t, "192.168.1.20/24"),
					mustCIDRAddrForTest(t, "169.254.10.20/16"),
					mustCIDRAddrForTest(t, "fe80::1/64"),
				},
			},
			{
				Index: 3,
				Name:  "tailscale0",
				Flags: net.FlagUp | net.FlagPointToPoint,
				Addrs: []net.Addr{
					mustCIDRAddrForTest(t, "100.64.0.20/10"),
					mustCIDRAddrForTest(t, "fd7a:115c:a1e0::20/128"),
				},
			},
			{
				Index: 4,
				Name:  "docker0",
				Flags: net.FlagUp | net.FlagBroadcast,
				Addrs: []net.Addr{
					mustCIDRAddrForTest(t, "172.17.0.1/16"),
				},
			},
		}, nil
	})

	ips, dnsNames := CollectNodeSANs(NodeSANOptions{
		ClusterBindSpecs:  []string{"all:8444"},
		Hostname:          "win-dc-01.corp.example.test",
		ExtraIPs:          []string{"198.51.100.25"},
		ExtraDNSNames:     []string{"edge-node.internal"},
		AutoInterfaceSANs: true,
		InterfaceProvider: mockProvider,
	})
	for _, wantIP := range []string{"127.0.0.1", "192.168.1.20", "100.64.0.20", "fd7a:115c:a1e0::20", "198.51.100.25"} {
		if !slices.Contains(ips, wantIP) {
			t.Fatalf("CollectNodeSANs missing expected IP %q in %v", wantIP, ips)
		}
	}
	for _, unwantedIP := range []string{"172.17.0.1", "169.254.10.20", "fe80::1"} {
		if slices.Contains(ips, unwantedIP) {
			t.Fatalf("CollectNodeSANs leaked excluded bridge/link-local IP %q in %v", unwantedIP, ips)
		}
	}
	for _, wantDNS := range []string{"localhost", "win-dc-01.corp.example.test", "win-dc-01", "edge-node.internal"} {
		if !slices.Contains(dnsNames, wantDNS) {
			t.Fatalf("CollectNodeSANs missing expected DNS SAN %q in %v", wantDNS, dnsNames)
		}
	}

	joinDir := filepath.Join(t.TempDir(), "san-harvest-node")
	certPath := filepath.Join(joinDir, "server.crt")
	if _, err := BootstrapJoin(context.Background(), BootstrapJoinOptions{
		JoinAddr:          seedNode.engine.Addr(),
		JoinToken:         tok,
		NodeID:            "san-harvest-node",
		ClusterBindAddrs:  []string{"127.0.0.1:0"},
		CertPath:          certPath,
		KeyPath:           filepath.Join(joinDir, "server.key"),
		CAPath:            filepath.Join(joinDir, "ca.crt"),
		CRLPath:           filepath.Join(joinDir, "crl.pem"),
		StatePath:         filepath.Join(joinDir, "cluster-state.json"),
		ExtraIPs:          []string{"198.51.100.25"},
		ExtraDNSNames:     []string{"edge-node.internal"},
		AutoInterfaceSANs: true,
		InterfaceProvider: mockProvider,
	}); err != nil {
		t.Fatalf("BootstrapJoin(san-harvest-node): %v", err)
	}

	leafCert, err := pki.LoadCertificate(certPath)
	if err != nil {
		t.Fatalf("LoadCertificate: %v", err)
	}
	for _, verifyHost := range []string{"127.0.0.1", "192.168.1.20", "100.64.0.20", "fd7a:115c:a1e0::20", "198.51.100.25", "localhost", "edge-node.internal"} {
		if err := leafCert.VerifyHostname(verifyHost); err != nil {
			t.Fatalf("issued leaf certificate failed VerifyHostname(%q): %v", verifyHost, err)
		}
	}
	if err := leafCert.VerifyHostname("172.17.0.1"); err == nil {
		t.Fatal("expected docker0 bridge IP 172.17.0.1 to be excluded from issued leaf SANs")
	}
}

func TestValidateAlreadyBootstrappedLeafSerialReplacement(t *testing.T) {
	fix := newTestPKIFixture(t)
	seedNode := startPreIssuedTestNode(t, fix, "serial-seed-1", true, nil)

	tok1, _, err := seedNode.engine.CreateJoinToken(5*time.Minute, "rekey-node-2")
	if err != nil {
		t.Fatalf("CreateJoinToken(tok1): %v", err)
	}

	nodeDir := filepath.Join(t.TempDir(), "rekey-node-2")
	certPath := filepath.Join(nodeDir, "server.crt")
	keyPath := filepath.Join(nodeDir, "server.key")
	caPath := filepath.Join(nodeDir, "ca.crt")
	crlPath := filepath.Join(nodeDir, "crl.pem")
	statePath := filepath.Join(nodeDir, "cluster-state.json")

	res1, err := BootstrapJoin(context.Background(), BootstrapJoinOptions{
		JoinAddr:        seedNode.engine.Addr(),
		JoinToken:       tok1,
		NodeID:          "rekey-node-2",
		ClusterBindAddr: "127.0.0.1:0",
		CertPath:        certPath,
		KeyPath:         keyPath,
		CAPath:          caPath,
		CRLPath:         crlPath,
		StatePath:       statePath,
	})
	if err != nil {
		t.Fatalf("initial BootstrapJoin: %v", err)
	}

	// 1. Unchanged leaf serial on disk -> idempotent AlreadyBootstrapped: true even without a token!
	idemRes, err := BootstrapJoin(context.Background(), BootstrapJoinOptions{
		JoinAddr:        seedNode.engine.Addr(),
		NodeID:          "rekey-node-2",
		ClusterBindAddr: "127.0.0.1:0",
		CertPath:        certPath,
		KeyPath:         keyPath,
		CAPath:          caPath,
		CRLPath:         crlPath,
		StatePath:       statePath,
	})
	if err != nil || !idemRes.AlreadyBootstrapped {
		t.Fatalf("expected idempotent AlreadyBootstrapped=true with unchanged cert, got res=%+v err=%v", idemRes, err)
	}

	// 2. Replace server.crt + server.key on disk with a newly pre-issued peer certificate!
	replacementIssued, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:    fix.caDir,
		OutDir:   filepath.Join(t.TempDir(), "reissued"),
		Type:     pki.TypePeer,
		Name:     "rekey-node-2",
		IPs:      []string{"127.0.0.1", "100.64.0.99"},
		DNSNames: []string{"localhost"},
	})
	if err != nil {
		t.Fatalf("IssueCert(replacement): %v", err)
	}
	copyFileForTest(t, replacementIssued.CertPath, certPath, 0o644)
	copyFileForTest(t, replacementIssued.KeyPath, keyPath, 0o600)

	// Without a join token -> MUST return an actionable error mentioning serial mismatch and 'agent-bridge cluster rejoin'!
	_, noTokErr := BootstrapJoin(context.Background(), BootstrapJoinOptions{
		JoinAddr:        seedNode.engine.Addr(),
		JoinToken:       "",
		NodeID:          "rekey-node-2",
		ClusterBindAddr: "127.0.0.1:0",
		CertPath:        certPath,
		KeyPath:         keyPath,
		CAPath:          caPath,
		CRLPath:         crlPath,
		StatePath:       statePath,
	})
	if noTokErr == nil || !strings.Contains(noTokErr.Error(), "agent-bridge cluster rejoin") {
		t.Fatalf("expected actionable serial-mismatch error suggesting 'agent-bridge cluster rejoin', got: %v", noTokErr)
	}

	// 3. With a fresh join token -> MUST NOT short-circuit to AlreadyBootstrapped: true; must execute Mode B PoP re-keying!
	tok2, _, err := seedNode.engine.CreateJoinToken(5*time.Minute, "rekey-node-2")
	if err != nil {
		t.Fatalf("CreateJoinToken(tok2): %v", err)
	}
	res2, err := BootstrapJoin(context.Background(), BootstrapJoinOptions{
		JoinAddr:        seedNode.engine.Addr(),
		JoinToken:       tok2,
		NodeID:          "rekey-node-2",
		ClusterBindAddr: "127.0.0.1:0",
		CertPath:        certPath,
		KeyPath:         keyPath,
		CAPath:          caPath,
		CRLPath:         crlPath,
		StatePath:       statePath,
	})
	if err != nil {
		t.Fatalf("Mode B re-key BootstrapJoin failed: %v", err)
	}
	if res2.AlreadyBootstrapped || res2.Mode != "pre-issued" {
		t.Fatalf("expected Mode B pre-issued re-keying (AlreadyBootstrapped=false), got: %+v", res2)
	}
	if strings.EqualFold(res2.CertSerialHex, res1.CertSerialHex) || !strings.EqualFold(res2.CertSerialHex, replacementIssued.SerialHex) {
		t.Fatalf("unexpected CertSerialHex after Mode B re-keying: got %s, want %s", res2.CertSerialHex, replacementIssued.SerialHex)
	}

	n2 := startBootstrappedNodeEngine(t, "rekey-node-2", certPath, keyPath, caPath, crlPath, statePath, "", []string{seedNode.engine.Addr()})
	waitForCondition(t, 3*time.Second, "re-keyed node-2 healthy in 2-node cluster", func() bool {
		return seedNode.engine.Status().AliveNodes == 2 && n2.engine.Status().AliveNodes == 2
	})
}

func TestTokenlessAuthenticatedPeerCertRenewalAndForwarding(t *testing.T) {
	fix := newTestPKIFixture(t)

	authCA1 := startPreIssuedTestNode(t, fix, "auth-ca-1", true, nil)
	relayPeer2 := startPreIssuedTestNode(t, fix, "relay-peer-2", false, []string{authCA1.engine.Addr()})
	workerPeer3 := startPreIssuedTestNode(t, fix, "worker-peer-3", false, []string{authCA1.engine.Addr(), relayPeer2.engine.Addr()})

	waitForCondition(t, 3*time.Second, "3-node mesh converged before renewal", func() bool {
		return authCA1.engine.Status().AliveNodes == 3 &&
			relayPeer2.engine.Status().AliveNodes == 3 &&
			workerPeer3.engine.Status().AliveNodes == 3
	})

	// 1. Security checks on POST /cluster/v1/renew:
	// 1a. --type client certificate MUST be rejected with HTTP 403 (ServerAuth EKU required).
	adminHTTP := newRawMTLSHTTPClientForTest(t, fix.adminCert.CertPath, fix.adminCert.KeyPath, fix.caRes.CACertPath)
	_, _, dummyCSR, err := pki.GenerateKeyAndCSR("worker-peer-3", []string{"127.0.0.1"}, []string{"localhost"})
	if err != nil {
		t.Fatalf("GenerateKeyAndCSR: %v", err)
	}
	code, body := doJSONRequestForTest(t, adminHTTP, http.MethodPost, "https://"+authCA1.engine.Addr()+pathClusterRenew, RenewRequest{
		NodeID:      "worker-peer-3",
		ClusterAddr: workerPeer3.engine.Addr(),
		CSRPEM:      string(dummyCSR),
	})
	if code != http.StatusForbidden || !strings.Contains(body, "ServerAuth") {
		t.Fatalf("expected HTTP 403 for --type client cert on %s, got %d: %s", pathClusterRenew, code, body)
	}

	// 1b. relay-peer-2 attempting to renew worker-peer-3 MUST be rejected with HTTP 403!
	relayHTTP := newRawMTLSHTTPClientForTest(t, relayPeer2.certPath, relayPeer2.keyPath, fix.caRes.CACertPath)
	code, body = doJSONRequestForTest(t, relayHTTP, http.MethodPost, "https://"+authCA1.engine.Addr()+pathClusterRenew, RenewRequest{
		NodeID:      "worker-peer-3",
		ClusterAddr: workerPeer3.engine.Addr(),
		CSRPEM:      string(dummyCSR),
	})
	if code != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 when relay-peer-2 attempts to renew worker-peer-3, got %d: %s", code, body)
	}

	// 2. Stop worker-peer-3, run tokenless Mode A CSR RenewPeerCert via NON-CA relay-peer-2 (exercising /cluster/v1/sign-join forwarding!)
	//    with ExtraIPs + ExtraDNSNames + RevokeOldSerial: true!
	oldSerialHex := workerPeer3.certSerial
	oldSerialBig, err := pki.ParseSerialHex(oldSerialHex)
	if err != nil {
		t.Fatalf("ParseSerialHex: %v", err)
	}
	if err := workerPeer3.engine.Close(); err != nil {
		t.Fatalf("workerPeer3.Close: %v", err)
	}

	renewRes, err := RenewPeerCert(context.Background(), RenewOptions{
		JoinAddr:        relayPeer2.engine.Addr(), // Non-CA relay peer!
		NodeID:          "worker-peer-3",
		ClusterBindAddr: "127.0.0.1:0",
		CertPath:        workerPeer3.certPath,
		KeyPath:         workerPeer3.keyPath,
		CAPath:          workerPeer3.caPath,
		CRLPath:         workerPeer3.crlPath,
		StatePath:       workerPeer3.statePath,
		ExtraIPs:        []string{"100.64.0.33"},
		ExtraDNSNames:   []string{"worker-3.mesh.internal"},
		RevokeOldSerial: true,
	})
	if err != nil {
		t.Fatalf("RenewPeerCert(Mode A via non-CA relayPeer2) failed: %v", err)
	}
	if renewRes.Mode != "csr-renewed" || !renewRes.OldSerialRevoked || strings.EqualFold(renewRes.CertSerialHex, oldSerialHex) {
		t.Fatalf("unexpected Mode A RenewResult: %+v", renewRes)
	}

	// Verify renewed leaf certificate contains the new SANs and old serial was revoked across cluster CRLs!
	renewedLeaf, err := pki.LoadCertificate(workerPeer3.certPath)
	if err != nil {
		t.Fatalf("LoadCertificate(renewed): %v", err)
	}
	if err := renewedLeaf.VerifyHostname("100.64.0.33"); err != nil {
		t.Fatalf("renewed leaf missing ExtraIP 100.64.0.33: %v", err)
	}
	if err := renewedLeaf.VerifyHostname("worker-3.mesh.internal"); err != nil {
		t.Fatalf("renewed leaf missing ExtraDNSName worker-3.mesh.internal: %v", err)
	}
	waitForCondition(t, time.Second, "old serial revoked in authCA1 and relayPeer2 CRLs", func() bool {
		return authCA1.watcher.IsRevoked(oldSerialBig) && relayPeer2.watcher.IsRevoked(oldSerialBig)
	})

	// Restart worker-peer-3 with its renewed certificate and verify all 3 nodes converge to AliveNodes == 3!
	workerRestarted := startBootstrappedNodeEngine(
		t,
		"worker-peer-3",
		workerPeer3.certPath,
		workerPeer3.keyPath,
		workerPeer3.caPath,
		workerPeer3.crlPath,
		workerPeer3.statePath,
		"",
		[]string{relayPeer2.engine.Addr()},
	)
	waitForCondition(t, 3*time.Second, "restarted worker-peer-3 healthy across 3-node cluster after Mode A renew", func() bool {
		return authCA1.engine.Status().AliveNodes == 3 &&
			relayPeer2.engine.Status().AliveNodes == 3 &&
			workerRestarted.engine.Status().AliveNodes == 3
	})

	// 3. Also test Mode B pre-issued RenewPeerCert (NewCertPath + NewKeyPath + PoP signature)!
	preIssuedReplacement, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:    fix.caDir,
		OutDir:   filepath.Join(t.TempDir(), "mode-b-renew"),
		Type:     pki.TypePeer,
		Name:     "worker-peer-3",
		IPs:      []string{"127.0.0.1", "100.64.0.44"},
		DNSNames: []string{"localhost"},
	})
	if err != nil {
		t.Fatalf("IssueCert(mode-b-renew): %v", err)
	}
	_ = workerRestarted.engine.Close()

	modeBRes, err := RenewPeerCert(context.Background(), RenewOptions{
		JoinAddr:        authCA1.engine.Addr(),
		NodeID:          "worker-peer-3",
		ClusterBindAddr: "127.0.0.1:0",
		CertPath:        workerPeer3.certPath,
		KeyPath:         workerPeer3.keyPath,
		NewCertPath:     preIssuedReplacement.CertPath,
		NewKeyPath:      preIssuedReplacement.KeyPath,
		CAPath:          workerPeer3.caPath,
		CRLPath:         workerPeer3.crlPath,
		StatePath:       workerPeer3.statePath,
		RevokeOldSerial: true,
	})
	if err != nil {
		t.Fatalf("RenewPeerCert(Mode B pre-issued) failed: %v", err)
	}
	if modeBRes.Mode != "pre-issued-renewed" || !strings.EqualFold(modeBRes.CertSerialHex, preIssuedReplacement.SerialHex) {
		t.Fatalf("unexpected Mode B RenewResult: %+v", modeBRes)
	}

	workerRestartedB := startBootstrappedNodeEngine(
		t,
		"worker-peer-3",
		workerPeer3.certPath,
		workerPeer3.keyPath,
		workerPeer3.caPath,
		workerPeer3.crlPath,
		workerPeer3.statePath,
		"",
		[]string{authCA1.engine.Addr()},
	)
	waitForCondition(t, 3*time.Second, "restarted worker-peer-3 healthy across 3-node cluster after Mode B renew", func() bool {
		return authCA1.engine.Status().AliveNodes == 3 &&
			relayPeer2.engine.Status().AliveNodes == 3 &&
			workerRestartedB.engine.Status().AliveNodes == 3
	})
}
