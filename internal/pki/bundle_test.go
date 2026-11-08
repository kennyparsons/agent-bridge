package pki

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kennyparsons/agent-bridge/internal/acl"
)

func TestPKIKeyLockdownAndRevokeByCertPath(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	caDir := filepath.Join(tmp, "ca")
	caRes, err := InitCA(InitCAOptions{OutDir: caDir})
	if err != nil {
		t.Fatalf("InitCA failed: %v", err)
	}

	if st, err := acl.AuditPathACL(caDir, false); err != nil || !st.Secure {
		t.Fatalf("expected InitCA outDir locked down, got st=%+v err=%v", st, err)
	}
	if st, err := acl.AuditPathACL(caRes.CAKeyPath, false); err != nil || !st.Secure {
		t.Fatalf("expected ca.key locked down, got st=%+v err=%v", st, err)
	}

	cli1, err := IssueCert(IssueCertOptions{
		CADir:  caDir,
		OutDir: filepath.Join(tmp, "client1"),
		Type:   TypeClient,
		Name:   "automation-01",
	})
	if err != nil {
		t.Fatalf("IssueCert(client1) failed: %v", err)
	}
	if st, err := acl.AuditPathACL(cli1.KeyPath, false); err != nil || !st.Secure {
		t.Fatalf("expected client1 key locked down, got st=%+v err=%v", st, err)
	}

	cli2, err := IssueCert(IssueCertOptions{
		CADir:  caDir,
		OutDir: filepath.Join(tmp, "client2"),
		Type:   TypeClient,
		Name:   "automation-02",
	})
	if err != nil {
		t.Fatalf("IssueCert(client2) failed: %v", err)
	}

	csrKeyPath := filepath.Join(tmp, "csr", "node.key")
	if _, _, _, err := GenerateAndSaveKeyAndCSR("win-dc-01", []string{"100.64.0.10"}, []string{"win-dc-01"}, csrKeyPath); err != nil {
		t.Fatalf("GenerateAndSaveKeyAndCSR failed: %v", err)
	}
	if st, err := acl.AuditPathACL(csrKeyPath, false); err != nil || !st.Secure {
		t.Fatalf("expected CSR private key locked down, got st=%+v err=%v", st, err)
	}

	// Mismatched CertPath + Serial must return a clear conflict error without mutating the CRL.
	if _, err := RevokeCert(RevokeCertOptions{
		CADir:    caDir,
		CertPath: cli1.CertPath,
		Serial:   cli2.SerialHex,
	}); err == nil || !strings.Contains(err.Error(), "conflicting serial") {
		t.Fatalf("expected conflicting serial error for mismatched CertPath + Serial, got: %v", err)
	}

	// Revoke via CertPath alone.
	revRes, err := RevokeCert(RevokeCertOptions{
		CADir:    caDir,
		CertPath: cli1.CertPath,
	})
	if err != nil {
		t.Fatalf("RevokeCert(CertPath) failed: %v", err)
	}
	if revRes.Serial.Cmp(cli1.Serial) != 0 || revRes.SerialHex != cli1.SerialHex {
		t.Fatalf("RevokeCert(CertPath) serial = %s, want %s", revRes.SerialHex, cli1.SerialHex)
	}

	// Matching CertPath + Serial succeeds idempotently.
	revSame, err := RevokeCert(RevokeCertOptions{
		CADir:    caDir,
		CertPath: cli1.CertPath,
		Serial:   cli1.SerialHex,
	})
	if err != nil {
		t.Fatalf("RevokeCert(matching CertPath + Serial) failed: %v", err)
	}
	if !revSame.AlreadyRevoked {
		t.Fatal("expected AlreadyRevoked=true on matching CertPath + Serial")
	}
}

func TestClientBundlePlainAndEncryptedRoundTrip(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	caDir := filepath.Join(tmp, "ca")
	if _, err := InitCA(InitCAOptions{OutDir: caDir}); err != nil {
		t.Fatalf("InitCA failed: %v", err)
	}

	cliRes, err := IssueCert(IssueCertOptions{
		CADir:  caDir,
		OutDir: filepath.Join(tmp, "client"),
		Type:   TypeClient,
		Name:   "ops-client",
	})
	if err != nil {
		t.Fatalf("IssueCert(client) failed: %v", err)
	}

	srvRes, err := IssueCert(IssueCertOptions{
		CADir:  caDir,
		OutDir: filepath.Join(tmp, "server"),
		Type:   TypeServer,
		Name:   "win-dc-01",
		IPs:    []string{"100.64.0.10"},
	})
	if err != nil {
		t.Fatalf("IssueCert(server) failed: %v", err)
	}

	bundle, err := BuildClientBundle(BuildClientBundleOptions{
		CACertPath:      filepath.Join(caDir, CACertFilename),
		ClientCertPath:  cliRes.CertPath,
		ClientKeyPath:   cliRes.KeyPath,
		DefaultHost:     "win-dc-01",
		ClusterEndpoint: "100.64.0.10:8444",
		Hosts: map[string]HostBundleEntry{
			"win-dc-01": {
				Endpoint:        "100.64.0.10:8443",
				ClusterEndpoint: "100.64.0.10:8444",
				Timeout:         "60s",
			},
			"win-dc-02": {
				Endpoint:        "100.64.0.11:8443",
				ClusterEndpoint: "100.64.0.11:8444",
			},
		},
	})
	if err != nil {
		t.Fatalf("BuildClientBundle failed: %v", err)
	}

	// 1. Plaintext `.abbundle` file write, ACL lockdown, and read-back.
	plainPath := filepath.Join(tmp, "ops-plain.abbundle")
	if err := WriteBundleFile(plainPath, bundle, ""); err != nil {
		t.Fatalf("WriteBundleFile(plain) failed: %v", err)
	}
	if st, err := acl.AuditPathACL(plainPath, false); err != nil || !st.Secure {
		t.Fatalf("expected plain .abbundle file ACL locked down, got st=%+v err=%v", st, err)
	}
	plainRaw, err := MarshalBundle(bundle, "")
	if err != nil {
		t.Fatalf("MarshalBundle(plain) failed: %v", err)
	}
	if IsEncryptedBundle(plainRaw) {
		t.Fatal("expected IsEncryptedBundle(plainRaw) == false")
	}
	parsedPlain, err := ReadBundleFile(plainPath, "")
	if err != nil {
		t.Fatalf("ReadBundleFile(plain) failed: %v", err)
	}
	if parsedPlain.Version != BundleVersionV1 || parsedPlain.DefaultHost != "win-dc-01" || len(parsedPlain.Hosts) != 2 {
		t.Fatalf("unexpected parsedPlain: %+v", parsedPlain)
	}

	// 2. Passphrase-encrypted `.abbundle` round-trip and wrong/missing passphrase rejection.
	encPath := filepath.Join(tmp, "ops-enc.abbundle")
	passphrase := "correct-horse-battery-staple-2026"
	if err := WriteBundleFile(encPath, bundle, passphrase); err != nil {
		t.Fatalf("WriteBundleFile(encrypted) failed: %v", err)
	}
	if st, err := acl.AuditPathACL(encPath, false); err != nil || !st.Secure {
		t.Fatalf("expected encrypted .abbundle file ACL locked down, got st=%+v err=%v", st, err)
	}

	encRaw, err := MarshalBundle(bundle, passphrase)
	if err != nil {
		t.Fatalf("MarshalBundle(encrypted) failed: %v", err)
	}
	if !IsEncryptedBundle(encRaw) {
		t.Fatal("expected IsEncryptedBundle(encRaw) == true")
	}
	if strings.Contains(string(encRaw), "BEGIN EC PRIVATE KEY") {
		t.Fatal("encrypted bundle leaked plaintext EC PRIVATE KEY PEM")
	}

	if _, err := ReadBundleFile(encPath, ""); !errors.Is(err, ErrBundlePassphraseRequired) {
		t.Fatalf("ReadBundleFile(empty passphrase) = %v, want ErrBundlePassphraseRequired", err)
	}
	if _, err := ReadBundleFile(encPath, "wrong-passphrase"); !errors.Is(err, ErrBundleInvalidPassphrase) {
		t.Fatalf("ReadBundleFile(wrong passphrase) = %v, want ErrBundleInvalidPassphrase", err)
	}

	parsedEnc, err := ReadBundleFile(encPath, passphrase)
	if err != nil {
		t.Fatalf("ReadBundleFile(correct passphrase) failed: %v", err)
	}
	if parsedEnc.ClientKeyPEM != bundle.ClientKeyPEM || parsedEnc.Hosts["win-dc-02"].Endpoint != "100.64.0.11:8443" {
		t.Fatalf("decrypted bundle mismatch: %+v", parsedEnc)
	}

	// 3. Reject ServerAuth-only leaf cert or mismatched private key when building ClientBundle.
	if _, err := BuildClientBundle(BuildClientBundleOptions{
		CACertPath:     filepath.Join(caDir, CACertFilename),
		ClientCertPath: srvRes.CertPath,
		ClientKeyPath:  srvRes.KeyPath,
	}); err == nil {
		t.Fatal("expected BuildClientBundle to reject ServerAuth-only certificate")
	}
	if _, err := BuildClientBundle(BuildClientBundleOptions{
		CACertPath:     filepath.Join(caDir, CACertFilename),
		ClientCertPath: cliRes.CertPath,
		ClientKeyPath:  srvRes.KeyPath,
	}); err == nil {
		t.Fatal("expected BuildClientBundle to reject mismatched cert/key pair")
	}
}
