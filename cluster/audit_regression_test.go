package cluster

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/pki"
	"github.com/kennyparsons/agent-bridge/internal/protocol"
)

func generateTestCSRWithCN(t *testing.T, commonName string) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: commonName},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}, priv)
	if err != nil {
		t.Fatalf("x509.CreateCertificateRequest: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})
	return csrPEM, priv
}

func waitForAliveCount(t *testing.T, engines []*Engine, wantAlive int, timeout time.Duration) {
	t.Helper()
	waitForCondition(t, timeout, "cluster alive node convergence", func() bool {
		for _, eng := range engines {
			st := eng.Status()
			if st.AliveNodes < wantAlive {
				return false
			}
		}
		return true
	})
}

func postClusterJSONForTest(
	t *testing.T,
	httpClient *http.Client,
	urlStr string,
	payload any,
) (int, []byte) {
	t.Helper()
	rawBody, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, urlStr, bytes.NewReader(rawBody))
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s failed: %v", urlStr, err)
	}
	defer func() { _ = resp.Body.Close() }()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("io.ReadAll: %v", err)
	}
	return resp.StatusCode, respBytes
}

func TestJoinAndRenewRejectCommonNameMismatch(t *testing.T) {
	fix := newTestPKIFixture(t)
	nodeA := startPreIssuedTestNode(t, fix, "node-a", true, nil)
	nodeD := startPreIssuedTestNode(t, fix, "node-d", false, []string{nodeA.engine.Addr()})

	waitForAliveCount(t, []*Engine{nodeA.engine, nodeD.engine}, 2, 5*time.Second)

	rawToken, _, err := nodeA.engine.CreateJoinToken(10*time.Minute, "node-b")
	if err != nil {
		t.Fatalf("CreateJoinToken: %v", err)
	}
	if _, err := nodeA.engine.Sync(context.Background(), SyncRequest{}); err != nil {
		t.Fatalf("Sync token to node-d: %v", err)
	}

	parsedTok, err := ParseJoinToken(rawToken)
	if err != nil {
		t.Fatalf("ParseJoinToken: %v", err)
	}

	_, caPool, err := pki.LoadCACertPool(fix.caRes.CACertPath)
	if err != nil {
		t.Fatalf("LoadCACertPool: %v", err)
	}
	anonJoinClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				RootCAs:    caPool,
			},
		},
	}
	t.Cleanup(anonJoinClient.CloseIdleConnections)

	_, baseHTTPSA, err := config.NormalizeClusterAddr(nodeA.engine.Addr())
	if err != nil {
		t.Fatalf("NormalizeClusterAddr(node-a): %v", err)
	}
	_, baseHTTPSD, err := config.NormalizeClusterAddr(nodeD.engine.Addr())
	if err != nil {
		t.Fatalf("NormalizeClusterAddr(node-d): %v", err)
	}

	// 1. Mode A CSR with CN != req.NodeID must be rejected with 403 Forbidden (both on CA node-a and non-CA node-d before forwarding).
	mismatchedCSR, _ := generateTestCSRWithCN(t, "node-impersonated")
	badModeAReq := JoinRequest{
		Token:       rawToken,
		NodeID:      "node-b",
		ClusterAddr: "127.0.0.1:18444",
		ExecAddr:    "127.0.0.1:18443",
		CSRPEM:      string(mismatchedCSR),
	}

	for _, target := range []struct {
		name string
		base string
	}{
		{name: "authority-node-a", base: baseHTTPSA},
		{name: "forwarding-node-d", base: baseHTTPSD},
	} {
		code, body := postClusterJSONForTest(t, anonJoinClient, target.base+pathClusterJoin, badModeAReq)
		if code != http.StatusForbidden {
			t.Fatalf("Mode A mismatched CSR CN on %s returned HTTP %d, want 403 Forbidden (body=%s)", target.name, code, string(body))
		}
	}

	// 2. Mode B pre-issued cert with CN != req.NodeID must be rejected with 403 Forbidden even with valid PoP signature.
	otherCertDir := filepath.Join(t.TempDir(), "node-other")
	otherIssued, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:    fix.caDir,
		OutDir:   otherCertDir,
		Type:     pki.TypePeer,
		Name:     "node-other",
		IPs:      []string{"127.0.0.1"},
		DNSNames: []string{"localhost", "node-other"},
	})
	if err != nil {
		t.Fatalf("IssueCert(node-other): %v", err)
	}
	otherKP, err := tls.LoadX509KeyPair(otherIssued.CertPath, otherIssued.KeyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair(node-other): %v", err)
	}
	otherPriv, ok := otherKP.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PrivateKey, got %T", otherKP.PrivateKey)
	}
	otherCertPEM, err := os.ReadFile(otherIssued.CertPath)
	if err != nil {
		t.Fatalf("ReadFile(otherIssued.CertPath): %v", err)
	}
	popSig, err := signJoinPoP(otherPriv, parsedTok.TokenID, "node-b", "127.0.0.1:18444")
	if err != nil {
		t.Fatalf("signJoinPoP: %v", err)
	}
	badModeBReq := JoinRequest{
		Token:              rawToken,
		NodeID:             "node-b",
		ClusterAddr:        "127.0.0.1:18444",
		ExecAddr:           "127.0.0.1:18443",
		ExistingCertPEM:    string(otherCertPEM),
		PoPSignatureBase64: popSig,
	}
	for _, target := range []struct {
		name string
		base string
	}{
		{name: "authority-node-a", base: baseHTTPSA},
		{name: "forwarding-node-d", base: baseHTTPSD},
	} {
		code, body := postClusterJSONForTest(t, anonJoinClient, target.base+pathClusterJoin, badModeBReq)
		if code != http.StatusForbidden {
			t.Fatalf("Mode B mismatched cert CN on %s returned HTTP %d, want 403 Forbidden (body=%s)", target.name, code, string(body))
		}
	}

	// Verify none of the rejected requests consumed the single-use join token or admitted node-b.
	for _, p := range nodeA.engine.Peers() {
		if p.NodeID == "node-b" {
			t.Fatalf("node-b must not be admitted after rejected CN-mismatch join attempts: %+v", p)
		}
	}

	// 3. Defense-in-depth on POST /cluster/v1/renew: authenticated peer node-d claiming req.NodeID="node-a" -> 403 Forbidden.
	nodeDTLSCert, err := tls.LoadX509KeyPair(nodeD.certPath, nodeD.keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair(node-d): %v", err)
	}
	peerRenewClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion:   tls.VersionTLS13,
				RootCAs:      caPool,
				Certificates: []tls.Certificate{nodeDTLSCert},
			},
		},
	}
	t.Cleanup(peerRenewClient.CloseIdleConnections)

	renewCSR, _ := generateTestCSRWithCN(t, "node-a")
	code, body := postClusterJSONForTest(t, peerRenewClient, baseHTTPSA+pathClusterRenew, RenewRequest{
		NodeID:      "node-a",
		ClusterAddr: nodeD.engine.Addr(),
		CSRPEM:      string(renewCSR),
	})
	if code != http.StatusForbidden {
		t.Fatalf("POST /cluster/v1/renew with caller CN!=node_id returned HTTP %d, want 403 Forbidden (body=%s)", code, string(body))
	}

	// 4. Positive control: valid Mode A CSR with CN=="node-b" succeeds using the unconsumed token.
	validCSR, _ := generateTestCSRWithCN(t, "node-b")
	code, body = postClusterJSONForTest(t, anonJoinClient, baseHTTPSD+pathClusterJoin, JoinRequest{
		Token:       rawToken,
		NodeID:      "node-b",
		ClusterAddr: "127.0.0.1:18444",
		ExecAddr:    "127.0.0.1:18443",
		CSRPEM:      string(validCSR),
	})
	if code != http.StatusOK {
		t.Fatalf("expected valid Mode A join with matching CN to succeed (200 OK), got %d: %s", code, string(body))
	}
}

func TestRenewRevokeOldReSignsPeerSignedPolicyAndForwardsModeB(t *testing.T) {
	fix := newTestPKIFixture(t)
	nodeA := startPreIssuedTestNode(t, fix, "node-a", true, nil)

	// Enroll non-CA node-b and non-CA node-d via BootstrapJoin.
	enrollPeer := func(nodeID string) *testNodeHarness {
		t.Helper()
		rawTok, _, err := nodeA.engine.CreateJoinToken(10*time.Minute, nodeID)
		if err != nil {
			t.Fatalf("CreateJoinToken(%s): %v", nodeID, err)
		}
		dir := filepath.Join(t.TempDir(), nodeID)
		certPath := filepath.Join(dir, pki.ServerCertFilename)
		keyPath := filepath.Join(dir, pki.ServerKeyFilename)
		caPath := filepath.Join(dir, pki.CACertFilename)
		crlPath := filepath.Join(dir, pki.CRLFilename)
		statePath := filepath.Join(dir, "cluster-state.json")

		_, err = BootstrapJoin(context.Background(), BootstrapJoinOptions{
			NodeID:          nodeID,
			ClusterBindAddr: "127.0.0.1:8444",
			ExecBindAddr:    "127.0.0.1:8443",
			JoinAddrs:       []string{nodeA.engine.Addr()},
			JoinToken:       rawTok,
			CertPath:        certPath,
			KeyPath:         keyPath,
			CAPath:          caPath,
			CRLPath:         crlPath,
			StatePath:       statePath,
		})
		if err != nil {
			t.Fatalf("BootstrapJoin(%s): %v", nodeID, err)
		}
		return startBootstrappedNodeEngine(t, nodeID, certPath, keyPath, caPath, crlPath, statePath, "", []string{nodeA.engine.Addr()})
	}

	nodeB := enrollPeer("node-b")
	nodeD := enrollPeer("node-d")
	waitForAliveCount(t, []*Engine{nodeA.engine, nodeB.engine, nodeD.engine}, 3, 5*time.Second)

	// 1. Non-CA peer node-b signs a cluster-wide ExecutionPolicy update via Sync.
	wantPol := protocol.ExecutionPolicy{
		DefaultTimeoutSeconds: 47,
		MaxTimeoutSeconds:     300,
		EnforceClientACL:      true,
		AllowedClients:        []string{"workstation-01"},
	}
	if _, err := nodeB.engine.Sync(context.Background(), SyncRequest{PolicyUpdate: &wantPol}); err != nil {
		t.Fatalf("node-b Sync(PolicyUpdate) failed: %v", err)
	}
	waitForCondition(t, 5*time.Second, "policy v1 propagation from non-CA node-b to node-a and node-d", func() bool {
		return nodeA.engine.ExecutionPolicy().DefaultTimeoutSeconds == 47 &&
			nodeD.engine.ExecutionPolicy().DefaultTimeoutSeconds == 47
	})

	nodeA.engine.mu.RLock()
	peerSignedEnv := nodeA.engine.signedPolicy.Clone()
	nodeA.engine.mu.RUnlock()
	if peerSignedEnv == nil {
		t.Fatal("expected non-nil signedPolicy on node-a")
	}
	beforeSigner, err := parseSingleCertificatePEM([]byte(peerSignedEnv.SignerCertPEM))
	if err != nil {
		t.Fatalf("parseSingleCertificatePEM(beforeSigner): %v", err)
	}
	if beforeSigner.IsCA || !strings.EqualFold(pki.FormatSerialHex(beforeSigner.SerialNumber), nodeB.certSerial) {
		t.Fatalf("expected initial SignedPolicy signer to be node-b leaf [%s], got IsCA=%v serial=%s",
			nodeB.certSerial, beforeSigner.IsCA, pki.FormatSerialHex(beforeSigner.SerialNumber))
	}

	// 2. Stop node-b and rotate its leaf cert with RevokeOldSerial=true (against non-CA node-d to exercise forwarding!).
	oldSerialB := nodeB.certSerial
	_ = nodeB.engine.Close()
	_ = nodeB.watcher.Close()

	renewResB, err := RenewPeerCert(context.Background(), RenewOptions{
		NodeID:          "node-b",
		ClusterBindAddr: "127.0.0.1:8444",
		ExecBindAddr:    "127.0.0.1:8443",
		JoinAddrs:       []string{nodeD.engine.Addr()},
		CertPath:        nodeB.certPath,
		KeyPath:         nodeB.keyPath,
		CAPath:          nodeB.caPath,
		CRLPath:         nodeB.crlPath,
		StatePath:       nodeB.statePath,
		ExtraIPs:        []string{"198.51.100.77"},
		RevokeOldSerial: true,
	})
	if err != nil {
		t.Fatalf("RenewPeerCert(node-b via non-CA node-d, RevokeOldSerial=true) failed: %v", err)
	}
	if !renewResB.OldSerialRevoked {
		t.Fatalf("expected OldSerialRevoked=true, got %+v", renewResB)
	}
	if strings.EqualFold(renewResB.CertSerialHex, oldSerialB) {
		t.Fatalf("expected rotated serial to differ from %s", oldSerialB)
	}

	// Verify node-a re-signed SignedPolicy using the Root CA certificate and advanced ordering above peerSignedEnv.
	nodeA.engine.mu.RLock()
	caReSignedEnv := nodeA.engine.signedPolicy.Clone()
	nodeA.engine.mu.RUnlock()
	if caReSignedEnv == nil {
		t.Fatal("expected non-nil signedPolicy on node-a after renew")
	}
	afterSigner, err := parseSingleCertificatePEM([]byte(caReSignedEnv.SignerCertPEM))
	if err != nil {
		t.Fatalf("parseSingleCertificatePEM(afterSigner): %v", err)
	}
	if !afterSigner.IsCA {
		t.Fatalf("expected SignedPolicy to be re-signed by Root CA (IsCA=true), got CN=%q IsCA=%v",
			afterSigner.Subject.CommonName, afterSigner.IsCA)
	}
	if !caReSignedEnv.IsNewerThan(peerSignedEnv) {
		t.Fatalf("expected CA re-signed policy (%+v) to order newer than old peer-signed policy (%+v)",
			caReSignedEnv.Policy, peerSignedEnv.Policy)
	}
	if err := caReSignedEnv.Verify(nodeA.engine.caCert, nodeA.engine.caPool, nodeA.watcher); err != nil {
		t.Fatalf("CA re-signed policy failed Verify against updated CRL: %v", err)
	}

	// 3. Restart BOTH node-a and node-b from persisted state -> policy MUST remain enforced (no fail-open reset!).
	_ = nodeA.engine.Close()
	_ = nodeA.watcher.Close()

	nodeARestarted := startBootstrappedNodeEngine(
		t, "node-a",
		nodeA.certPath, nodeA.keyPath, nodeA.caPath, nodeA.crlPath, nodeA.statePath,
		fix.caRes.CAKeyPath, nil,
	)
	nodeBRestarted := startBootstrappedNodeEngine(
		t, "node-b",
		nodeB.certPath, nodeB.keyPath, nodeB.caPath, nodeB.crlPath, nodeB.statePath,
		"", []string{nodeARestarted.engine.Addr(), nodeD.engine.Addr()},
	)
	if _, err := nodeBRestarted.engine.Sync(context.Background(), SyncRequest{}); err != nil {
		t.Fatalf("nodeBRestarted Sync: %v", err)
	}
	waitForAliveCount(t, []*Engine{nodeARestarted.engine, nodeBRestarted.engine, nodeD.engine}, 3, 5*time.Second)

	for _, check := range []struct {
		name string
		eng  *Engine
	}{
		{name: "restarted-node-a", eng: nodeARestarted.engine},
		{name: "restarted-node-b", eng: nodeBRestarted.engine},
		{name: "forwarding-node-d", eng: nodeD.engine},
	} {
		pol := check.eng.ExecutionPolicy()
		if pol.DefaultTimeoutSeconds != 47 || !pol.EnforceClientACL || len(pol.AllowedClients) != 1 || pol.AllowedClients[0] != "workstation-01" {
			t.Fatalf("%s lost enforced ExecutionPolicy after revoking old policy-signer leaf cert: got %+v", check.name, pol)
		}
	}

	// 4. Brand-new peer node-c can BootstrapJoin cleanly and inherits the enforced ExecutionPolicy!
	rawTokC, _, err := nodeARestarted.engine.CreateJoinToken(10*time.Minute, "node-c")
	if err != nil {
		t.Fatalf("CreateJoinToken(node-c): %v", err)
	}
	nodeCDir := filepath.Join(t.TempDir(), "node-c")
	joinResC, err := BootstrapJoin(context.Background(), BootstrapJoinOptions{
		NodeID:          "node-c",
		ClusterBindAddr: "127.0.0.1:8444",
		ExecBindAddr:    "127.0.0.1:8443",
		JoinAddrs:       []string{nodeARestarted.engine.Addr()},
		JoinToken:       rawTokC,
		CertPath:        filepath.Join(nodeCDir, pki.ServerCertFilename),
		KeyPath:         filepath.Join(nodeCDir, pki.ServerKeyFilename),
		CAPath:          filepath.Join(nodeCDir, pki.CACertFilename),
		CRLPath:         filepath.Join(nodeCDir, pki.CRLFilename),
		StatePath:       filepath.Join(nodeCDir, "cluster-state.json"),
	})
	if err != nil {
		t.Fatalf("BootstrapJoin(node-c) failed after peer-signed policy rotation: %v", err)
	}
	if joinResC.Policy.DefaultTimeoutSeconds != 47 || !joinResC.Policy.EnforceClientACL {
		t.Fatalf("node-c BootstrapJoin did not receive enforced ExecutionPolicy: %+v", joinResC.Policy)
	}

	// 5. Verify Mode B (pre-issued cert) RenewPeerCert with RevokeOldSerial=true ALSO forwards via non-CA node-b!
	wantPol2 := protocol.ExecutionPolicy{
		DefaultTimeoutSeconds: 53,
		MaxTimeoutSeconds:     300,
		EnforceClientACL:      true,
		AllowedClients:        []string{"workstation-01"},
	}
	if _, err := nodeD.engine.Sync(context.Background(), SyncRequest{PolicyUpdate: &wantPol2}); err != nil {
		t.Fatalf("node-d Sync(PolicyUpdate v2) failed: %v", err)
	}
	waitForCondition(t, 5*time.Second, "policy v2 propagation from node-d", func() bool {
		return nodeARestarted.engine.ExecutionPolicy().DefaultTimeoutSeconds == 53 &&
			nodeBRestarted.engine.ExecutionPolicy().DefaultTimeoutSeconds == 53
	})

	preIssuedDir := filepath.Join(t.TempDir(), "node-d-replacement")
	replacementD, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:    fix.caDir,
		OutDir:   preIssuedDir,
		Type:     pki.TypePeer,
		Name:     "node-d",
		IPs:      []string{"127.0.0.1", "198.51.100.88"},
		DNSNames: []string{"localhost", "node-d"},
	})
	if err != nil {
		t.Fatalf("IssueCert(node-d replacement): %v", err)
	}

	oldSerialD := nodeD.certSerial
	_ = nodeD.engine.Close()
	_ = nodeD.watcher.Close()

	renewResD, err := RenewPeerCert(context.Background(), RenewOptions{
		NodeID:          "node-d",
		ClusterBindAddr: "127.0.0.1:8444",
		ExecBindAddr:    "127.0.0.1:8443",
		JoinAddrs:       []string{nodeBRestarted.engine.Addr()}, // non-CA peer forwards Mode B + RevokeOldSerial to node-a!
		CertPath:        nodeD.certPath,
		KeyPath:         nodeD.keyPath,
		NewCertPath:     replacementD.CertPath,
		NewKeyPath:      replacementD.KeyPath,
		CAPath:          nodeD.caPath,
		CRLPath:         nodeD.crlPath,
		StatePath:       nodeD.statePath,
		RevokeOldSerial: true,
	})
	if err != nil {
		t.Fatalf("Mode B RenewPeerCert(node-d via non-CA node-b, RevokeOldSerial=true) failed: %v", err)
	}
	if !renewResD.OldSerialRevoked {
		t.Fatalf("expected Mode B forwarded renew to revoke old serial %s, got %+v", oldSerialD, renewResD)
	}
	if renewResD.Policy.DefaultTimeoutSeconds != 53 || !renewResD.Policy.EnforceClientACL {
		t.Fatalf("expected Mode B forwarded renew to preserve enforced policy (53s), got %+v", renewResD.Policy)
	}
}
