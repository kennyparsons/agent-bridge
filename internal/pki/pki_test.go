package pki

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSerialHexFormattingAndParsing(t *testing.T) {
	rawHex := "4A:2F:89:1B:3E:00:1C:78"
	serial, err := ParseSerialHex(rawHex)
	if err != nil {
		t.Fatalf("ParseSerialHex(%q) failed: %v", rawHex, err)
	}
	if got := FormatSerialHex(serial); got != rawHex {
		t.Fatalf("FormatSerialHex = %q, want %q", got, rawHex)
	}

	equivalents := []string{
		"4a:2f:89:1b:3e:00:1c:78",
		"4A2F891B3E001C78",
		"4a2f891b3e001c78",
		"0x4A2F891B3E001C78",
		"0X4a2f891b3e001c78",
		"  0x4A:2F:89:1B:3E:00:1C:78 ",
	}
	for _, input := range equivalents {
		parsed, parseErr := ParseSerialHex(input)
		if parseErr != nil {
			t.Fatalf("ParseSerialHex(%q) failed: %v", input, parseErr)
		}
		if parsed.Cmp(serial) != 0 {
			t.Fatalf("ParseSerialHex(%q) = %s, want %s", input, FormatSerialHex(parsed), rawHex)
		}
	}

	// Verify odd nibble padding per byte.
	oddNibble, err := ParseSerialHex("0x42F")
	if err != nil {
		t.Fatalf("ParseSerialHex(0x42F) failed: %v", err)
	}
	if got := FormatSerialHex(oddNibble); got != "04:2F" {
		t.Fatalf("FormatSerialHex(0x42F) = %q, want %q", got, "04:2F")
	}

	if got := FormatSerialHex(nil); got != "" {
		t.Fatalf("FormatSerialHex(nil) = %q, want empty", got)
	}
	if got := FormatSerialHex(big.NewInt(0)); got != "00" {
		t.Fatalf("FormatSerialHex(0) = %q, want 00", got)
	}

	invalidInputs := []string{
		"",
		"   ",
		"0x",
		"00",
		"00:00:00",
		"-0x01",
		"4A::2F",
		":4A:2F",
		"4A:2F:",
		"4A2:2F",
		"ZZ:11",
	}
	for _, bad := range invalidInputs {
		if _, err := ParseSerialHex(bad); err == nil {
			t.Errorf("ParseSerialHex(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestFullPKILifecycleTLS13AndLiveCRLHotReload(t *testing.T) {
	rootDir := t.TempDir()
	caDir := filepath.Join(rootDir, "pki")
	serverDir := filepath.Join(rootDir, "certs", "win-dc-01")
	clientDir := filepath.Join(rootDir, "certs", "automation-prod")
	client2Dir := filepath.Join(rootDir, "certs", "secondary-agent")

	// 1. Initialize Root CA with defaults.
	caRes, err := InitCA(InitCAOptions{OutDir: caDir})
	if err != nil {
		t.Fatalf("InitCA failed: %v", err)
	}

	if caRes.Certificate.Subject.CommonName != DefaultCACommonName {
		t.Fatalf("CA CommonName = %q, want %q", caRes.Certificate.Subject.CommonName, DefaultCACommonName)
	}
	if len(caRes.Certificate.Subject.Organization) != 1 || caRes.Certificate.Subject.Organization[0] != DefaultCAOrg {
		t.Fatalf("CA Organization = %v, want [%q]", caRes.Certificate.Subject.Organization, DefaultCAOrg)
	}
	if !caRes.Certificate.IsCA || !caRes.Certificate.BasicConstraintsValid || !caRes.Certificate.MaxPathLenZero || caRes.Certificate.MaxPathLen != 0 {
		t.Fatalf("unexpected CA basic constraints: IsCA=%v BasicConstraintsValid=%v MaxPathLen=%d MaxPathLenZero=%v",
			caRes.Certificate.IsCA, caRes.Certificate.BasicConstraintsValid, caRes.Certificate.MaxPathLen, caRes.Certificate.MaxPathLenZero)
	}
	wantCAUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if caRes.Certificate.KeyUsage != wantCAUsage {
		t.Fatalf("CA KeyUsage = %v, want %v", caRes.Certificate.KeyUsage, wantCAUsage)
	}
	if len(caRes.Certificate.SubjectKeyId) != 20 {
		t.Fatalf("CA SubjectKeyId length = %d, want 20", len(caRes.Certificate.SubjectKeyId))
	}
	assertP256AndSerial128(t, caRes.Certificate)
	assertFilePerm(t, caRes.CAKeyPath, 0o600)
	assertFilePerm(t, caRes.CACertPath, 0o644)
	assertFilePerm(t, caRes.CRLPath, 0o644)

	// 2. Issue Server Certificate with IPv4, IPv6, and DNS SANs.
	srvRes, err := IssueCert(IssueCertOptions{
		CADir:    caDir,
		OutDir:   serverDir,
		Type:     TypeServer,
		Name:     "win-dc-01",
		IPs:      []string{"100.64.0.10", "fd7a:115c:a1e0::1"},
		DNSNames: []string{"win-dc-01", "win-dc-01.tailnet-example.ts.net"},
	})
	if err != nil {
		t.Fatalf("IssueCert(server) failed: %v", err)
	}
	assertP256AndSerial128(t, srvRes.Certificate)
	assertFilePerm(t, srvRes.KeyPath, 0o600)
	assertFilePerm(t, srvRes.CertPath, 0o644)

	if srvRes.Certificate.Subject.CommonName != "win-dc-01" {
		t.Fatalf("Server CN = %q, want win-dc-01", srvRes.Certificate.Subject.CommonName)
	}
	if !bytes.Equal(srvRes.Certificate.AuthorityKeyId, caRes.Certificate.SubjectKeyId) {
		t.Fatalf("Server AuthorityKeyId mismatch with CA SubjectKeyId")
	}
	wantSrvUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if srvRes.Certificate.KeyUsage != wantSrvUsage {
		t.Fatalf("Server KeyUsage = %v, want %v", srvRes.Certificate.KeyUsage, wantSrvUsage)
	}
	if len(srvRes.Certificate.ExtKeyUsage) != 1 || srvRes.Certificate.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("Server ExtKeyUsage = %v, want [ServerAuth]", srvRes.Certificate.ExtKeyUsage)
	}
	if len(srvRes.Certificate.IPAddresses) != 2 ||
		!srvRes.Certificate.IPAddresses[0].Equal(net.ParseIP("100.64.0.10")) ||
		!srvRes.Certificate.IPAddresses[1].Equal(net.ParseIP("fd7a:115c:a1e0::1")) {
		t.Fatalf("Server IPAddresses = %v, want [100.64.0.10 fd7a:115c:a1e0::1]", srvRes.Certificate.IPAddresses)
	}
	if len(srvRes.Certificate.DNSNames) != 2 ||
		srvRes.Certificate.DNSNames[0] != "win-dc-01" ||
		srvRes.Certificate.DNSNames[1] != "win-dc-01.tailnet-example.ts.net" {
		t.Fatalf("Server DNSNames = %v, want [win-dc-01 win-dc-01.tailnet-example.ts.net]", srvRes.Certificate.DNSNames)
	}

	// 3. Issue Client Certificates.
	cliRes, err := IssueCert(IssueCertOptions{
		CADir:  caDir,
		OutDir: clientDir,
		Type:   TypeClient,
		Name:   "automation-prod",
	})
	if err != nil {
		t.Fatalf("IssueCert(client) failed: %v", err)
	}
	assertP256AndSerial128(t, cliRes.Certificate)
	assertFilePerm(t, cliRes.KeyPath, 0o600)
	assertFilePerm(t, cliRes.CertPath, 0o644)
	if cliRes.Certificate.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("Client KeyUsage = %v, want DigitalSignature", cliRes.Certificate.KeyUsage)
	}
	if len(cliRes.Certificate.ExtKeyUsage) != 1 || cliRes.Certificate.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatalf("Client ExtKeyUsage = %v, want [ClientAuth]", cliRes.Certificate.ExtKeyUsage)
	}

	cli2Res, err := IssueCert(IssueCertOptions{
		CADir:  caDir,
		OutDir: client2Dir,
		Type:   TypeClient,
		Name:   "secondary-agent",
	})
	if err != nil {
		t.Fatalf("IssueCert(client2) failed: %v", err)
	}

	// 4. LoadCACertPool & verify X.509 chains.
	caCert, caPool, err := LoadCACertPool(caRes.CACertPath)
	if err != nil {
		t.Fatalf("LoadCACertPool failed: %v", err)
	}

	verifiedClientChains, err := cliRes.Certificate.Verify(x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Fatalf("client certificate failed X.509 chain verification: %v", err)
	}

	// 5. Startup fail-fast checks on NewCRLWatcher.
	if _, err := NewCRLWatcher(filepath.Join(rootDir, "nonexistent-crl.pem"), caCert, nil, nil); err == nil {
		t.Fatal("expected NewCRLWatcher to fail on missing CRL file")
	}

	// Rogue CA CRL must be rejected at startup.
	rogueDir := filepath.Join(rootDir, "rogue-pki")
	rogueCA, err := InitCA(InitCAOptions{OutDir: rogueDir, CommonName: "Rogue-CA"})
	if err != nil {
		t.Fatalf("InitCA(rogue) failed: %v", err)
	}
	if _, err := NewCRLWatcher(rogueCA.CRLPath, caCert, nil, nil); err == nil {
		t.Fatal("expected NewCRLWatcher to reject CRL signed by rogue CA")
	}

	// Expired CRL must be rejected at startup.
	expiredCRLPath := filepath.Join(rootDir, "expired-crl.pem")
	writeExpiredCRL(t, caDir, caCert, expiredCRLPath)
	if _, err := NewCRLWatcher(expiredCRLPath, caCert, nil, nil); err == nil {
		t.Fatal("expected NewCRLWatcher to reject expired CRL")
	}

	// 6. Start active CRLWatcher on valid crl.pem.
	var reloadCount atomic.Int32
	var lastCRLNum atomic.Int64
	var reloadErrors atomic.Int32
	reloadNotify := make(chan struct{}, 8)
	errNotify := make(chan error, 8)

	watcher, err := NewCRLWatcher(
		caRes.CRLPath,
		caCert,
		func(revokedCount int, crlNum *big.Int) {
			reloadCount.Add(1)
			if crlNum != nil {
				lastCRLNum.Store(crlNum.Int64())
			}
			select {
			case reloadNotify <- struct{}{}:
			default:
			}
		},
		func(err error) {
			reloadErrors.Add(1)
			select {
			case errNotify <- err:
			default:
			}
		},
	)
	if err != nil {
		t.Fatalf("NewCRLWatcher(valid) failed: %v", err)
	}
	defer func() {
		if closeErr := watcher.Close(); closeErr != nil {
			t.Errorf("watcher.Close() error: %v", closeErr)
		}
	}()

	if watcher.IsRevoked(cliRes.Serial) {
		t.Fatalf("expected client serial %s not to be revoked initially", cliRes.SerialHex)
	}
	if gotNum := watcher.CRLNumber(); gotNum == nil || gotNum.Int64() != 1 {
		t.Fatalf("initial CRLNumber = %v, want 1", gotNum)
	}
	if err := watcher.CheckPeerChains(verifiedClientChains); err != nil {
		t.Fatalf("CheckPeerChains failed for unrevoked client: %v", err)
	}

	// Perform live TLS 1.3 mTLS handshake before revocation (testing both IP SAN and DNS SAN).
	if err := runTLS13Handshake(srvRes.CertPath, srvRes.KeyPath, cliRes.CertPath, cliRes.KeyPath, caCert, caPool, watcher, "100.64.0.10"); err != nil {
		t.Fatalf("TLS 1.3 mTLS handshake over IPv4 SAN failed before revocation: %v", err)
	}
	if err := runTLS13Handshake(srvRes.CertPath, srvRes.KeyPath, cliRes.CertPath, cliRes.KeyPath, caCert, caPool, watcher, "win-dc-01.tailnet-example.ts.net"); err != nil {
		t.Fatalf("TLS 1.3 mTLS handshake over DNS SAN failed before revocation: %v", err)
	}

	// 7. Revoke automation-prod while watcher is active and assert hot-reload within < 1s without restart!
	revokeStart := time.Now()
	revRes, err := RevokeCert(RevokeCertOptions{
		CADir:  caDir,
		Serial: cliRes.SerialHex,
	})
	if err != nil {
		t.Fatalf("RevokeCert failed: %v", err)
	}
	if revRes.CRLNumber.Int64() != 2 {
		t.Fatalf("RevokeCert CRLNumber = %v, want 2", revRes.CRLNumber)
	}
	if revRes.AlreadyRevoked {
		t.Fatal("expected AlreadyRevoked=false on first revocation")
	}

	deadline := time.Now().Add(900 * time.Millisecond)
	for !watcher.IsRevoked(cliRes.Serial) {
		if time.Now().After(deadline) {
			t.Fatalf("CRLWatcher failed to hot-reload revoked serial %s within 900ms", cliRes.SerialHex)
		}
		select {
		case <-reloadNotify:
		case <-time.After(10 * time.Millisecond):
		}
	}
	elapsed := time.Since(revokeStart)
	if elapsed >= time.Second {
		t.Fatalf("CRL hot-reload took %v, want < 1s", elapsed)
	}

	// Verify exact spec rejection error text on CheckPeerChains AND live TLS 1.3 handshake.
	wantErrSubstr := fmt.Sprintf("TLS Handshake Rejected: Certificate Serial [%s] is Revoked", cliRes.SerialHex)
	chainErr := watcher.CheckPeerChains(verifiedClientChains)
	if chainErr == nil || !strings.Contains(chainErr.Error(), wantErrSubstr) {
		t.Fatalf("CheckPeerChains error = %v, want substring %q", chainErr, wantErrSubstr)
	}

	tlsErr := runTLS13Handshake(srvRes.CertPath, srvRes.KeyPath, cliRes.CertPath, cliRes.KeyPath, caCert, caPool, watcher, "100.64.0.10")
	if tlsErr == nil || !strings.Contains(tlsErr.Error(), wantErrSubstr) {
		t.Fatalf("TLS 1.3 handshake error after revocation = %v, want substring %q", tlsErr, wantErrSubstr)
	}

	// Verify unrevoked secondary client still succeeds over TLS 1.3!
	if err := runTLS13Handshake(srvRes.CertPath, srvRes.KeyPath, cli2Res.CertPath, cli2Res.KeyPath, caCert, caPool, watcher, "fd7a:115c:a1e0::1"); err != nil {
		t.Fatalf("unrevoked secondary client failed TLS 1.3 handshake over IPv6 SAN: %v", err)
	}

	// 8. Verify idempotent re-revocation and multi-cert revocation preserve entries and increment CRLNumber.
	revDup, err := RevokeCert(RevokeCertOptions{
		CADir:  caDir,
		Serial: cliRes.SerialHex,
	})
	if err != nil {
		t.Fatalf("idempotent RevokeCert failed: %v", err)
	}
	if !revDup.AlreadyRevoked || revDup.RevokedCount != 1 || revDup.CRLNumber.Int64() != 3 {
		t.Fatalf("unexpected idempotent RevokeCert result: %+v", revDup)
	}

	revSecond, err := RevokeCert(RevokeCertOptions{
		CADir:        caDir,
		SerialNumber: cli2Res.Serial,
	})
	if err != nil {
		t.Fatalf("second RevokeCert failed: %v", err)
	}
	if revSecond.AlreadyRevoked || revSecond.RevokedCount != 2 || revSecond.CRLNumber.Int64() != 4 {
		t.Fatalf("unexpected second RevokeCert result: %+v", revSecond)
	}

	deadline2 := time.Now().Add(900 * time.Millisecond)
	for !watcher.IsRevoked(cli2Res.Serial) {
		if time.Now().After(deadline2) {
			t.Fatalf("CRLWatcher failed to hot-reload second revoked serial %s within 900ms", cli2Res.SerialHex)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !watcher.IsRevoked(cliRes.Serial) {
		t.Fatalf("first revoked serial %s was lost after second revocation", cliRes.SerialHex)
	}

	// 9. Verify runtime resilience: corrupting crl.pem on disk triggers onError while keeping active snapshot intact.
	if err := writeFileAtomic(caRes.CRLPath, []byte("corrupted-not-a-pem"), 0o644); err != nil {
		t.Fatalf("failed to write corrupted CRL: %v", err)
	}
	select {
	case <-errNotify:
	case <-time.After(900 * time.Millisecond):
		t.Fatal("expected CRLWatcher onError callback when crl.pem is corrupted at runtime")
	}
	if !watcher.IsRevoked(cliRes.Serial) || !watcher.IsRevoked(cli2Res.Serial) {
		t.Fatal("CRLWatcher dropped last-known-good revoked snapshot after corrupted CRL reload")
	}

	// Verify rogue chain rejection in CheckPeerChains.
	rogueClientDir := filepath.Join(rootDir, "certs", "rogue-client")
	rogueClient, err := IssueCert(IssueCertOptions{
		CADir:  rogueDir,
		OutDir: rogueClientDir,
		Type:   TypeClient,
		Name:   "rogue-agent",
	})
	if err != nil {
		t.Fatalf("IssueCert(rogueClient) failed: %v", err)
	}
	if err := watcher.CheckPeerChains([][]*x509.Certificate{{rogueClient.Certificate, rogueCA.Certificate}}); err == nil {
		t.Fatal("expected CheckPeerChains to reject certificate chain anchored at rogue CA")
	}
}

func assertP256AndSerial128(t *testing.T, cert *x509.Certificate) {
	t.Helper()
	if cert.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		t.Fatalf("SignatureAlgorithm = %v, want ECDSAWithSHA256", cert.SignatureAlgorithm)
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey is %T, want *ecdsa.PublicKey", cert.PublicKey)
	}
	if pub.Curve != elliptic.P256() {
		t.Fatalf("ECDSA curve = %v, want P-256", pub.Curve.Params().Name)
	}
	if cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 {
		t.Fatalf("SerialNumber = %v, want strictly positive integer", cert.SerialNumber)
	}
	if cert.SerialNumber.BitLen() > 128 {
		t.Fatalf("SerialNumber bit length = %d, want <= 128", cert.SerialNumber.BitLen())
	}
}

func assertFilePerm(t *testing.T, path string, wantPerm os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("os.Stat(%q) failed: %v", path, err)
	}
	if runtime.GOOS != "windows" {
		gotPerm := info.Mode().Perm()
		if gotPerm != wantPerm {
			t.Fatalf("permissions on %q = %04o, want %04o", path, gotPerm, wantPerm)
		}
	}
}

func writeExpiredCRL(t *testing.T, caDir string, caCert *x509.Certificate, outPath string) {
	t.Helper()
	_, caKey, err := loadCAKeyPair(caDir)
	if err != nil {
		t.Fatalf("loadCAKeyPair failed: %v", err)
	}
	past := time.Now().UTC().Add(-2 * time.Hour)
	tmpl := &x509.RevocationList{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Number:             big.NewInt(1),
		ThisUpdate:         past.Add(-time.Hour),
		NextUpdate:         past,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, caCert, caKey)
	if err != nil {
		t.Fatalf("CreateRevocationList(expired) failed: %v", err)
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	if err := writeFileAtomic(outPath, data, 0o644); err != nil {
		t.Fatalf("writeFileAtomic(expired) failed: %v", err)
	}
}

func runTLS13Handshake(
	serverCertPath, serverKeyPath string,
	clientCertPath, clientKeyPath string,
	caCert *x509.Certificate,
	caPool *x509.CertPool,
	watcher *CRLWatcher,
	serverName string,
) error {
	srvTLSCert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return fmt.Errorf("load server keypair: %w", err)
	}
	cliTLSCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return fmt.Errorf("load client keypair: %w", err)
	}

	serverTLSConfig := &tls.Config{
		MinVersion:            tls.VersionTLS13,
		MaxVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{srvTLSCert},
		ClientAuth:            tls.RequireAndVerifyClientCert,
		ClientCAs:             caPool,
		VerifyPeerCertificate: watcher.VerifyPeerCertChain(caCert),
	}

	clientTLSConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cliTLSCert},
		RootCAs:      caPool,
		ServerName:   serverName,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen loopback tcp: %w", err)
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

		srvTLS := tls.Server(rawConn, serverTLSConfig)
		if hsErr := srvTLS.Handshake(); hsErr != nil {
			srvErrCh <- hsErr
			return
		}
		buf := make([]byte, 4)
		if _, rErr := srvTLS.Read(buf); rErr != nil {
			srvErrCh <- rErr
			return
		}
		if _, wErr := srvTLS.Write([]byte("pong")); wErr != nil {
			srvErrCh <- wErr
			return
		}
		srvErrCh <- nil
	}()

	go func() {
		rawConn, dialErr := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
		if dialErr != nil {
			cliErrCh <- dialErr
			return
		}
		defer rawConn.Close()
		_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))

		cliTLS := tls.Client(rawConn, clientTLSConfig)
		if hsErr := cliTLS.Handshake(); hsErr != nil {
			cliErrCh <- hsErr
			return
		}
		if _, wErr := cliTLS.Write([]byte("ping")); wErr != nil {
			cliErrCh <- wErr
			return
		}
		reply := make([]byte, 4)
		if _, rErr := cliTLS.Read(reply); rErr != nil {
			cliErrCh <- rErr
			return
		}
		cliErrCh <- nil
	}()

	srvErr := <-srvErrCh
	cliErr := <-cliErrCh
	if srvErr != nil {
		return srvErr
	}
	return cliErr
}

func TestIssueCertClampsToCANotAfterAndRejectsExpiredCA(t *testing.T) {
	tmp := t.TempDir()

	// 1. Leaf certificate --years exceeding CA remaining lifetime must be clamped to caCert.NotAfter.
	shortCADir := filepath.Join(tmp, "short-ca")
	shortCA, err := InitCA(InitCAOptions{
		OutDir: shortCADir,
		Years:  1,
	})
	if err != nil {
		t.Fatalf("InitCA(short-ca) failed: %v", err)
	}

	srvClamped, err := IssueCert(IssueCertOptions{
		CADir:  shortCADir,
		OutDir: filepath.Join(tmp, "clamped-server"),
		Type:   TypeServer,
		Name:   "win-dc-01",
		IPs:    []string{"100.64.0.10"},
		Years:  5,
	})
	if err != nil {
		t.Fatalf("IssueCert(clamped-server) failed: %v", err)
	}
	if !srvClamped.Certificate.NotAfter.Equal(shortCA.Certificate.NotAfter) {
		t.Fatalf("clamped leaf NotAfter = %s, want equal to CA NotAfter %s",
			srvClamped.Certificate.NotAfter.Format(time.RFC3339),
			shortCA.Certificate.NotAfter.Format(time.RFC3339))
	}

	// Default 3-year server certificate against 1-year CA must also clamp cleanly.
	srvDefaultClamped, err := IssueCert(IssueCertOptions{
		CADir:  shortCADir,
		OutDir: filepath.Join(tmp, "default-clamped-server"),
		Type:   TypeServer,
		Name:   "win-dc-02",
		IPs:    []string{"100.64.0.11"},
	})
	if err != nil {
		t.Fatalf("IssueCert(default-clamped-server) failed: %v", err)
	}
	if !srvDefaultClamped.Certificate.NotAfter.Equal(shortCA.Certificate.NotAfter) {
		t.Fatalf("default-years leaf NotAfter = %s, want equal to CA NotAfter %s",
			srvDefaultClamped.Certificate.NotAfter.Format(time.RFC3339),
			shortCA.Certificate.NotAfter.Format(time.RFC3339))
	}

	// 2. Expired Root CA must be rejected by IssueCert.
	expiredCADir := filepath.Join(tmp, "expired-ca")
	if err := os.MkdirAll(expiredCADir, 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	expKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	expSerial, err := GenerateSerial()
	if err != nil {
		t.Fatalf("GenerateSerial failed: %v", err)
	}
	expSKI, err := computeSubjectKeyID(&expKey.PublicKey)
	if err != nil {
		t.Fatalf("computeSubjectKeyID failed: %v", err)
	}
	past := time.Now().UTC().Add(-2 * time.Hour)
	expTmpl := &x509.Certificate{
		SerialNumber:          expSerial,
		Subject:               pkix.Name{CommonName: "Expired-Root-CA"},
		NotBefore:             past.Add(-24 * time.Hour),
		NotAfter:              past,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          expSKI,
	}
	expDER, err := x509.CreateCertificate(rand.Reader, expTmpl, expTmpl, &expKey.PublicKey, expKey)
	if err != nil {
		t.Fatalf("CreateCertificate(expired CA) failed: %v", err)
	}
	expKeyDER, err := x509.MarshalECPrivateKey(expKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey failed: %v", err)
	}
	if err := writeFileAtomic(filepath.Join(expiredCADir, CACertFilename), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expDER}), 0o644); err != nil {
		t.Fatalf("write expired ca.crt failed: %v", err)
	}
	if err := writeFileAtomic(filepath.Join(expiredCADir, CAKeyFilename), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: expKeyDER}), 0o600); err != nil {
		t.Fatalf("write expired ca.key failed: %v", err)
	}

	_, err = IssueCert(IssueCertOptions{
		CADir:  expiredCADir,
		OutDir: filepath.Join(tmp, "expired-ca-client"),
		Type:   TypeClient,
		Name:   "ops-agent",
	})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("IssueCert against expired CA = %v, want error containing 'expired'", err)
	}
}
