package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignVerifyAndPrintPubKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubHex := hex.EncodeToString(pub)

	keyFormats := []struct {
		name string
		val  string
	}{
		{"hex_seed_64", hex.EncodeToString(priv.Seed())},
		{"hex_seed_with_whitespace", "  " + hex.EncodeToString(priv.Seed()) + "\n"},
		{"hex_priv_128", hex.EncodeToString(priv)},
		{"base64_seed_std", base64.StdEncoding.EncodeToString(priv.Seed())},
		{"base64_seed_raw", base64.RawStdEncoding.EncodeToString(priv.Seed())},
		{"base64_priv_std", base64.StdEncoding.EncodeToString(priv)},
		{"base64_priv_raw_url", base64.RawURLEncoding.EncodeToString(priv)},
	}

	for _, kf := range keyFormats {
		t.Run(kf.name, func(t *testing.T) {
			dir := t.TempDir()
			inFile := filepath.Join(dir, "SHA256SUMS.txt")
			payload := []byte("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  agent-bridge-linux-amd64\n")
			if err := os.WriteFile(inFile, payload, 0644); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}

			env := func(k string) string {
				if k == privKeyEnv {
					return kf.val
				}
				return ""
			}

			var outBuf, errBuf bytes.Buffer
			if err := run([]string{"--print-pubkey"}, env, &outBuf, &errBuf); err != nil {
				t.Fatalf("--print-pubkey failed: %v", err)
			}
			if got := outBuf.String(); got != pubHex+"\n" {
				t.Fatalf("--print-pubkey = %q, want %q", got, pubHex+"\n")
			}

			outBuf.Reset()
			errBuf.Reset()
			if err := run([]string{"--in", inFile}, env, &outBuf, &errBuf); err != nil {
				t.Fatalf("sign failed: %v", err)
			}

			sigPath := inFile + ".sig"
			sigBytes, err := os.ReadFile(sigPath)
			if err != nil {
				t.Fatalf("ReadFile sig: %v", err)
			}
			sigStr := string(sigBytes)
			if len(sigStr) != 129 || sigStr[128] != '\n' {
				t.Fatalf("unexpected signature file length/newline: len=%d content=%q", len(sigStr), sigStr)
			}
			if sigStr[:128] != strings.ToLower(sigStr[:128]) {
				t.Fatalf("signature is not lowercase hex: %q", sigStr[:128])
			}

			noEnv := func(string) string { return "" }
			if err := run([]string{"--verify", "--in", inFile, "--pubkey", pubHex}, noEnv, &outBuf, &errBuf); err != nil {
				t.Fatalf("verify failed: %v", err)
			}
		})
	}
}

func TestCustomOutAndTamperRejection(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey other: %v", err)
	}

	dir := t.TempDir()
	inFile := filepath.Join(dir, "SHA256SUMS.txt")
	sigFile := filepath.Join(dir, "custom.sig")
	origData := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  agent-bridge-darwin-arm64\n")
	if err := os.WriteFile(inFile, origData, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	env := func(k string) string {
		if k == privKeyEnv {
			return hex.EncodeToString(priv.Seed())
		}
		return ""
	}
	noEnv := func(string) string { return "" }

	var out, errOut bytes.Buffer
	if err := run([]string{"--in", inFile, "--out", sigFile}, env, &out, &errOut); err != nil {
		t.Fatalf("sign custom --out: %v", err)
	}

	pubHex := hex.EncodeToString(pub)
	if err := run([]string{"--verify", "--in", inFile, "--out", sigFile, "--pubkey", pubHex}, noEnv, &out, &errOut); err != nil {
		t.Fatalf("verify custom --out: %v", err)
	}

	// Wrong public key must be rejected.
	if err := run([]string{"--verify", "--in", inFile, "--out", sigFile, "--pubkey", hex.EncodeToString(otherPub)}, noEnv, &out, &errOut); err == nil {
		t.Fatal("expected verification failure with wrong public key")
	}

	// Tampered input file must be rejected.
	tampered := append([]byte(nil), origData...)
	tampered[0] ^= 0x01
	tamperedFile := filepath.Join(dir, "tampered.txt")
	if err := os.WriteFile(tamperedFile, tampered, 0644); err != nil {
		t.Fatalf("WriteFile tampered: %v", err)
	}
	if err := run([]string{"--verify", "--in", tamperedFile, "--out", sigFile, "--pubkey", pubHex}, noEnv, &out, &errOut); err == nil {
		t.Fatal("expected verification failure on tampered payload")
	}

	// Tampered signature byte must be rejected.
	rawSig, err := os.ReadFile(sigFile)
	if err != nil {
		t.Fatalf("ReadFile sig: %v", err)
	}
	mutSig := append([]byte(nil), rawSig...)
	if mutSig[0] == '0' {
		mutSig[0] = '1'
	} else {
		mutSig[0] = '0'
	}
	badSigFile := filepath.Join(dir, "bad.sig")
	if err := os.WriteFile(badSigFile, mutSig, 0644); err != nil {
		t.Fatalf("WriteFile bad sig: %v", err)
	}
	if err := run([]string{"--verify", "--in", inFile, "--out", badSigFile, "--pubkey", pubHex}, noEnv, &out, &errOut); err == nil {
		t.Fatal("expected verification failure on tampered signature")
	}
}

func TestInvalidInputsAndKeyErrorsDoNotLeakSecret(t *testing.T) {
	var out, errOut bytes.Buffer
	secretCandidate := "super-secret-malformed-key-material-value"
	env := func(k string) string {
		if k == privKeyEnv {
			return secretCandidate
		}
		return ""
	}
	err := run([]string{"--print-pubkey"}, env, &out, &errOut)
	if err == nil {
		t.Fatal("expected error for malformed private key")
	}
	if strings.Contains(err.Error(), secretCandidate) {
		t.Fatalf("error leaked secret material: %v", err)
	}

	// Corrupted 64-byte private key where suffix doesn't match seed must fail.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	corrupt := append([]byte(nil), priv...)
	corrupt[ed25519.PrivateKeySize-1] ^= 0xff
	corruptEnv := func(k string) string {
		if k == privKeyEnv {
			return hex.EncodeToString(corrupt)
		}
		return ""
	}
	if err := run([]string{"--print-pubkey"}, corruptEnv, &out, &errOut); err == nil {
		t.Fatal("expected error for 64-byte private key with mismatched public suffix")
	}
}
