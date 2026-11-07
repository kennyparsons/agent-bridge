package pki

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGenerateKeyAndCSRSignNodeCSRAndTamperRejection(t *testing.T) {
	tmp := t.TempDir()
	caDir := filepath.Join(tmp, "ca")

	caRes, err := InitCA(InitCAOptions{
		OutDir: caDir,
		Years:  2,
	})
	if err != nil {
		t.Fatalf("InitCA failed: %v", err)
	}

	// Verify CertFingerprintSHA256 matches exact 64-char lowercase SHA-256 of caCert.Raw.
	fp := CertFingerprintSHA256(caRes.Certificate)
	wantSum := sha256.Sum256(caRes.Certificate.Raw)
	if fp != hex.EncodeToString(wantSum[:]) || len(fp) != 64 {
		t.Fatalf("CertFingerprintSHA256 = %q, want %q", fp, hex.EncodeToString(wantSum[:]))
	}
	if CertFingerprintSHA256(nil) != "" {
		t.Fatal("expected empty fingerprint for nil cert")
	}

	caCert, caKey, err := LoadCAKeyPair(caRes.CACertPath, caRes.CAKeyPath)
	if err != nil {
		t.Fatalf("LoadCAKeyPair failed: %v", err)
	}

	priv, keyPEM, csrPEM, err := GenerateKeyAndCSR(
		"win-dc-02",
		[]string{"127.0.0.1", "100.64.0.11"},
		[]string{"win-dc-02"},
	)
	if err != nil {
		t.Fatalf("GenerateKeyAndCSR failed: %v", err)
	}

	parsedPriv, err := ParsePrivateKeyPEM(keyPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKeyPEM failed: %v", err)
	}
	if !parsedPriv.Equal(priv) {
		t.Fatal("ParsePrivateKeyPEM key does not match generated private key")
	}

	// Sign CSR with SAN merging/deduplication, dual EKU, and Years=10 (must clamp to 2y CA NotAfter).
	certPEM, signedCert, err := SignNodeCSR(csrPEM, caCert, caKey, SignCSROptions{
		ExtraIPs:           []string{"100.64.0.11", "fd7a:115c:a1e0::2"},
		ExtraDNSNames:      []string{"WIN-DC-02", "win-dc-02.tailnet-example.ts.net"},
		Years:              10,
		ServerAndClientEKU: true,
	})
	if err != nil {
		t.Fatalf("SignNodeCSR failed: %v", err)
	}
	if len(certPEM) == 0 {
		t.Fatal("SignNodeCSR returned empty certPEM")
	}
	if signedCert.Subject.CommonName != "win-dc-02" {
		t.Fatalf("signedCert CN = %q, want win-dc-02", signedCert.Subject.CommonName)
	}
	if !signedCert.NotAfter.Equal(caCert.NotAfter) {
		t.Fatalf("signedCert NotAfter = %s, want clamped to CA NotAfter %s",
			signedCert.NotAfter.Format(time.RFC3339),
			caCert.NotAfter.Format(time.RFC3339))
	}
	if len(signedCert.IPAddresses) != 3 {
		t.Fatalf("merged IP SAN count = %d, want 3 (%v)", len(signedCert.IPAddresses), signedCert.IPAddresses)
	}
	if len(signedCert.DNSNames) != 2 {
		t.Fatalf("merged DNS SAN count = %d, want 2 (%v)", len(signedCert.DNSNames), signedCert.DNSNames)
	}
	if len(signedCert.ExtKeyUsage) != 2 ||
		signedCert.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth ||
		signedCert.ExtKeyUsage[1] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("signedCert ExtKeyUsage = %v, want [ServerAuth ClientAuth]", signedCert.ExtKeyUsage)
	}

	// Verify keyPEM + certPEM form a valid TLS keypair.
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("tls.X509KeyPair(certPEM, keyPEM) failed: %v", err)
	}

	// Tamper with a signature byte inside CSR DER and assert SignNodeCSR rejects it.
	csrBlock, _ := pem.Decode(csrPEM)
	if csrBlock == nil {
		t.Fatal("failed to decode csrPEM")
	}
	tamperedDER := append([]byte(nil), csrBlock.Bytes...)
	tamperedDER[len(tamperedDER)-3] ^= 0xFF
	tamperedPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: tamperedDER,
	})
	if _, _, err := SignNodeCSR(tamperedPEM, caCert, caKey, SignCSROptions{ServerAndClientEKU: true}); err == nil {
		t.Fatal("expected SignNodeCSR to reject tampered CSR signature")
	}
}

func TestCRLWatcherApplyCRLPEMAndReloadListeners(t *testing.T) {
	tmp := t.TempDir()
	authCADir := filepath.Join(tmp, "authority-pki")
	followerDir := filepath.Join(tmp, "follower-state")
	clientDir := filepath.Join(tmp, "client")

	caRes, err := InitCA(InitCAOptions{OutDir: authCADir})
	if err != nil {
		t.Fatalf("InitCA failed: %v", err)
	}

	cliRes, err := IssueCert(IssueCertOptions{
		CADir:  authCADir,
		OutDir: clientDir,
		Type:   TypeClient,
		Name:   "agent-01",
	})
	if err != nil {
		t.Fatalf("IssueCert(client) failed: %v", err)
	}

	// Seed follower node with initial CRL #1.
	initialCRLPEM, err := os.ReadFile(caRes.CRLPath)
	if err != nil {
		t.Fatalf("ReadFile(initial CRL) failed: %v", err)
	}
	followerCRLPath := filepath.Join(followerDir, CRLFilename)
	if err := WriteFileAtomic(followerCRLPath, initialCRLPEM, 0o644); err != nil {
		t.Fatalf("WriteFileAtomic(follower CRL) failed: %v", err)
	}

	caCert, _, err := LoadCACertPool(caRes.CACertPath)
	if err != nil {
		t.Fatalf("LoadCACertPool failed: %v", err)
	}

	authWatcher, err := NewCRLWatcher(caRes.CRLPath, caCert, nil, nil)
	if err != nil {
		t.Fatalf("NewCRLWatcher(authority) failed: %v", err)
	}
	defer authWatcher.Close()

	followerWatcher, err := NewCRLWatcher(followerCRLPath, caCert, nil, nil)
	if err != nil {
		t.Fatalf("NewCRLWatcher(follower) failed: %v", err)
	}
	defer followerWatcher.Close()

	if !bytes.Equal(followerWatcher.CRLPEM(), authWatcher.CRLPEM()) {
		t.Fatal("initial CRLPEM mismatch between authority and follower")
	}
	if followerWatcher.CRLPath() == "" {
		t.Fatal("expected non-empty follower CRLPath()")
	}

	// Register reload listener on authority watcher so local RevokeCert triggers gossip callback.
	type reloadEvent struct {
		pem []byte
		num *big.Int
	}
	authEvents := make(chan reloadEvent, 4)
	authWatcher.AddReloadListener(func(crlPEM []byte, crlNum *big.Int) {
		authEvents <- reloadEvent{pem: crlPEM, num: crlNum}
	})

	var followerListenerHits atomic.Int32
	followerWatcher.AddReloadListener(func(_ []byte, _ *big.Int) {
		followerListenerHits.Add(1)
	})

	// Revoke client on authority CA -> CRL #2.
	revRes, err := RevokeCert(RevokeCertOptions{
		CADir:        authCADir,
		SerialNumber: cliRes.Serial,
	})
	if err != nil {
		t.Fatalf("RevokeCert failed: %v", err)
	}

	var gossipEvent reloadEvent
	select {
	case gossipEvent = <-authEvents:
	case <-time.After(950 * time.Millisecond):
		t.Fatal("timed out waiting for authority AddReloadListener callback after RevokeCert")
	}
	if gossipEvent.num == nil || gossipEvent.num.Cmp(revRes.CRLNumber) != 0 {
		t.Fatalf("listener CRLNumber = %v, want %v", gossipEvent.num, revRes.CRLNumber)
	}

	// Apply gossiped CRL #2 on follower -> must enforce revocation in 0ms synchronously!
	applied, appliedNum, err := followerWatcher.ApplyCRLPEM(gossipEvent.pem)
	if err != nil {
		t.Fatalf("follower ApplyCRLPEM(#2) failed: %v", err)
	}
	if !applied || appliedNum.Int64() != 2 {
		t.Fatalf("ApplyCRLPEM(#2) = (applied=%v, num=%v), want (true, 2)", applied, appliedNum)
	}
	if !followerWatcher.IsRevoked(cliRes.Serial) {
		t.Fatal("expected immediate 0ms synchronous revocation on follower after ApplyCRLPEM")
	}
	if followerListenerHits.Load() != 1 {
		t.Fatalf("follower reload listener count = %d, want 1", followerListenerHits.Load())
	}

	// Re-applying equal CRL #2 or stale CRL #1 must return applied=false without firing listeners again.
	appliedDup, dupNum, err := followerWatcher.ApplyCRLPEM(gossipEvent.pem)
	if err != nil || appliedDup || dupNum.Int64() != 2 {
		t.Fatalf("ApplyCRLPEM(duplicate #2) = (%v, %v, %v), want (false, 2, nil)", appliedDup, dupNum, err)
	}
	appliedStale, staleNum, err := followerWatcher.ApplyCRLPEM(initialCRLPEM)
	if err != nil || appliedStale || staleNum.Int64() != 2 {
		t.Fatalf("ApplyCRLPEM(stale #1) = (%v, %v, %v), want (false, 2, nil)", appliedStale, staleNum, err)
	}
	time.Sleep(120 * time.Millisecond)
	if followerListenerHits.Load() != 1 {
		t.Fatalf("expected no duplicate follower listener notifications after ApplyCRLPEM, got %d", followerListenerHits.Load())
	}

	// Applying a CRL signed by a rogue CA must fail and leave CRL #2 active.
	rogueCADir := filepath.Join(tmp, "rogue-ca")
	rogueCA, err := InitCA(InitCAOptions{OutDir: rogueCADir})
	if err != nil {
		t.Fatalf("InitCA(rogue) failed: %v", err)
	}
	rogueCRLPEM, err := os.ReadFile(rogueCA.CRLPath)
	if err != nil {
		t.Fatalf("ReadFile(rogue CRL) failed: %v", err)
	}
	if appliedRogue, _, rogueErr := followerWatcher.ApplyCRLPEM(rogueCRLPEM); rogueErr == nil || appliedRogue {
		t.Fatalf("expected rogue CRL to be rejected by ApplyCRLPEM, got applied=%v err=%v", appliedRogue, rogueErr)
	}
	if !followerWatcher.IsRevoked(cliRes.Serial) || followerWatcher.CRLNumber().Int64() != 2 {
		t.Fatal("follower CRL state was corrupted after rejecting rogue CRL")
	}

	// Verify ReloadNow() synchronously picks up CRL #3 written directly to disk.
	client2Res, err := IssueCert(IssueCertOptions{
		CADir:  authCADir,
		OutDir: filepath.Join(tmp, "client2"),
		Type:   TypeClient,
		Name:   "agent-02",
	})
	if err != nil {
		t.Fatalf("IssueCert(client2) failed: %v", err)
	}
	if _, err := RevokeCert(RevokeCertOptions{
		CADir:        authCADir,
		SerialNumber: client2Res.Serial,
		CRLOut:       followerCRLPath,
	}); err != nil {
		t.Fatalf("RevokeCert(CRL #3 -> follower path) failed: %v", err)
	}
	if err := followerWatcher.ReloadNow(); err != nil {
		t.Fatalf("followerWatcher.ReloadNow() failed: %v", err)
	}
	if !followerWatcher.IsRevoked(client2Res.Serial) || followerWatcher.CRLNumber().Int64() != 3 {
		t.Fatalf("expected ReloadNow() to load CRL #3 synchronously, got CRLNumber=%v", followerWatcher.CRLNumber())
	}
}

func TestVerifyPeerCertDualEKUAndTypePeerTLS13(t *testing.T) {
	tmp := t.TempDir()
	caDir := filepath.Join(tmp, "pki")
	rogueCADir := filepath.Join(tmp, "rogue-pki")

	caRes, err := InitCA(InitCAOptions{OutDir: caDir})
	if err != nil {
		t.Fatalf("InitCA failed: %v", err)
	}
	rogueCA, err := InitCA(InitCAOptions{OutDir: rogueCADir})
	if err != nil {
		t.Fatalf("InitCA(rogue) failed: %v", err)
	}

	caCert, caPool, err := LoadCACertPool(caRes.CACertPath)
	if err != nil {
		t.Fatalf("LoadCACertPool failed: %v", err)
	}
	watcher, err := NewCRLWatcher(caRes.CRLPath, caCert, nil, nil)
	if err != nil {
		t.Fatalf("NewCRLWatcher failed: %v", err)
	}
	defer watcher.Close()

	srvCertRes, err := IssueCert(IssueCertOptions{
		CADir:  caDir,
		OutDir: filepath.Join(tmp, "srv"),
		Type:   TypeServer,
		Name:   "node-srv",
		IPs:    []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("IssueCert(server) failed: %v", err)
	}

	cliCertRes, err := IssueCert(IssueCertOptions{
		CADir:  caDir,
		OutDir: filepath.Join(tmp, "cli"),
		Type:   TypeClient,
		Name:   "node-cli",
	})
	if err != nil {
		t.Fatalf("IssueCert(client) failed: %v", err)
	}

	peerCertRes, err := IssueCert(IssueCertOptions{
		CADir:    caDir,
		OutDir:   filepath.Join(tmp, "peer"),
		Type:     TypePeer,
		Name:     "node-peer",
		IPs:      []string{"127.0.0.1"},
		DNSNames: []string{"node-peer.internal"},
	})
	if err != nil {
		t.Fatalf("IssueCert(peer) failed: %v", err)
	}
	if len(peerCertRes.Certificate.ExtKeyUsage) != 2 {
		t.Fatalf("TypePeer ExtKeyUsage = %v, want [ServerAuth ClientAuth]", peerCertRes.Certificate.ExtKeyUsage)
	}

	// VerifyPeerCertDualEKU must accept TypeServer, TypeClient, and TypePeer certs from caPool.
	for _, tc := range []*IssueCertResult{srvCertRes, cliCertRes, peerCertRes} {
		gotLeaf, vErr := VerifyPeerCertDualEKU([][]byte{tc.Certificate.Raw}, caPool, watcher)
		if vErr != nil {
			t.Fatalf("VerifyPeerCertDualEKU(%s) failed: %v", tc.Certificate.Subject.CommonName, vErr)
		}
		if !gotLeaf.Equal(tc.Certificate) {
			t.Fatalf("VerifyPeerCertDualEKU returned mismatched leaf for %s", tc.Certificate.Subject.CommonName)
		}
	}

	// Reject CA cert presented directly as peer leaf.
	if _, err := VerifyPeerCertDualEKU([][]byte{caCert.Raw}, caPool, watcher); err == nil {
		t.Fatal("expected VerifyPeerCertDualEKU to reject CA cert presented as leaf")
	}

	// Reject peer cert issued by rogue CA.
	roguePeer, err := IssueCert(IssueCertOptions{
		CADir:  rogueCADir,
		OutDir: filepath.Join(tmp, "rogue-peer"),
		Type:   TypePeer,
		Name:   "rogue-node",
		IPs:    []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("IssueCert(roguePeer) failed: %v", err)
	}
	if _, err := VerifyPeerCertDualEKU([][]byte{roguePeer.Certificate.Raw, rogueCA.Certificate.Raw}, caPool, watcher); err == nil {
		t.Fatal("expected VerifyPeerCertDualEKU to reject rogue-CA peer cert")
	}

	// Live TLS 1.3 peer-to-peer handshake where a ServerAuth-only cert dials a TypePeer listener!
	if err := runClusterPeerTLS13Handshake(srvCertRes.CertPath, srvCertRes.KeyPath, peerCertRes.CertPath, peerCertRes.KeyPath, caPool, watcher); err != nil {
		t.Fatalf("cluster TLS 1.3 dual-EKU handshake failed before revocation: %v", err)
	}

	// Revoke srvCertRes and assert immediate rejection with exact spec error string.
	if _, err := RevokeCert(RevokeCertOptions{
		CADir:        caDir,
		SerialNumber: srvCertRes.Serial,
	}); err != nil {
		t.Fatalf("RevokeCert(srvCert) failed: %v", err)
	}
	if err := watcher.ReloadNow(); err != nil {
		t.Fatalf("watcher.ReloadNow() failed: %v", err)
	}

	wantSubstr := fmt.Sprintf("TLS Handshake Rejected: Certificate Serial [%s] is Revoked", srvCertRes.SerialHex)
	if _, err := VerifyPeerCertDualEKU([][]byte{srvCertRes.Certificate.Raw}, caPool, watcher); err == nil || !strings.Contains(err.Error(), wantSubstr) {
		t.Fatalf("VerifyPeerCertDualEKU(revoked) = %v, want substring %q", err, wantSubstr)
	}
	if hsErr := runClusterPeerTLS13Handshake(srvCertRes.CertPath, srvCertRes.KeyPath, peerCertRes.CertPath, peerCertRes.KeyPath, caPool, watcher); hsErr == nil || !strings.Contains(hsErr.Error(), wantSubstr) {
		t.Fatalf("cluster TLS 1.3 handshake after revocation = %v, want substring %q", hsErr, wantSubstr)
	}
}

func runClusterPeerTLS13Handshake(
	dialerCertPath, dialerKeyPath string,
	listenerCertPath, listenerKeyPath string,
	caPool *x509.CertPool,
	watcher *CRLWatcher,
) error {
	dialerPair, err := tls.LoadX509KeyPair(dialerCertPath, dialerKeyPath)
	if err != nil {
		return err
	}
	listenerPair, err := tls.LoadX509KeyPair(listenerCertPath, listenerKeyPath)
	if err != nil {
		return err
	}

	serverTLS := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{listenerPair},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			_, verifyErr := VerifyPeerCertDualEKU(rawCerts, caPool, watcher)
			return verifyErr
		},
	}

	clientTLS := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{dialerPair},
		InsecureSkipVerify: true, // Verified explicitly via VerifyPeerCertDualEKU against caPool + CRL.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			_, verifyErr := VerifyPeerCertDualEKU(rawCerts, caPool, watcher)
			return verifyErr
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()

	srvErrCh := make(chan error, 1)
	cliErrCh := make(chan error, 1)

	go func() {
		rawConn, acceptErr := ln.Accept()
		if acceptErr != nil {
			srvErrCh <- acceptErr
			return
		}
		defer rawConn.Close()
		_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))

		srvConn := tls.Server(rawConn, serverTLS)
		if hsErr := srvConn.Handshake(); hsErr != nil {
			srvErrCh <- hsErr
			return
		}
		buf := make([]byte, 2)
		if _, rErr := srvConn.Read(buf); rErr != nil {
			srvErrCh <- rErr
			return
		}
		_, wErr := srvConn.Write([]byte("ok"))
		srvErrCh <- wErr
	}()

	go func() {
		rawConn, dialErr := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if dialErr != nil {
			cliErrCh <- dialErr
			return
		}
		defer rawConn.Close()
		_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))

		cliConn := tls.Client(rawConn, clientTLS)
		if hsErr := cliConn.Handshake(); hsErr != nil {
			cliErrCh <- hsErr
			return
		}
		if _, wErr := cliConn.Write([]byte("hi")); wErr != nil {
			cliErrCh <- wErr
			return
		}
		reply := make([]byte, 2)
		_, rErr := cliConn.Read(reply)
		cliErrCh <- rErr
	}()

	srvErr := <-srvErrCh
	cliErr := <-cliErrCh
	if srvErr != nil {
		return srvErr
	}
	return cliErr
}
