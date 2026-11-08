// Command agent-bridge-sign signs and verifies release checksum manifests
// using Ed25519 detached hex signatures.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const privKeyEnv = "RELEASE_ED25519_PRIVATE_KEY"

func main() {
	if err := run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "agent-bridge-sign: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("agent-bridge-sign", flag.ContinueOnError)
	fs.SetOutput(stderr)

	inPath := fs.String("in", "", "Input file path to sign or verify (e.g. dist/SHA256SUMS.txt)")
	outPath := fs.String("out", "", "Signature file path (defaults to <in>.sig)")
	verifyMode := fs.Bool("verify", false, "Verify signature instead of signing")
	pubKeyHex := fs.String("pubkey", "", "64-char hex Ed25519 public key (required with --verify)")
	printPubKey := fs.Bool("print-pubkey", false, "Derive and print 64-char hex public key from "+privKeyEnv)

	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("unexpected positional arguments: %v", fs.Args())
	}

	if *printPubKey && *verifyMode {
		return errors.New("--print-pubkey and --verify cannot be used together")
	}

	if *printPubKey {
		privKey, err := parsePrivateKey(getenv(privKeyEnv))
		if err != nil {
			return err
		}
		pub := privKey.Public().(ed25519.PublicKey)
		_, err = fmt.Fprintf(stdout, "%s\n", hex.EncodeToString(pub))
		return err
	}

	if strings.TrimSpace(*inPath) == "" {
		return errors.New("--in is required")
	}

	sigPath := *outPath
	if strings.TrimSpace(sigPath) == "" {
		sigPath = *inPath + ".sig"
	}

	if *verifyMode {
		return verifyFile(*inPath, sigPath, *pubKeyHex)
	}

	if strings.TrimSpace(*pubKeyHex) != "" {
		return errors.New("--pubkey is only valid with --verify")
	}

	privKey, err := parsePrivateKey(getenv(privKeyEnv))
	if err != nil {
		return err
	}
	return signFile(*inPath, sigPath, privKey)
}

func signFile(inPath, sigPath string, privKey ed25519.PrivateKey) error {
	data, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("read input file %q: %w", inPath, err)
	}
	sig := ed25519.Sign(privKey, data)
	encoded := hex.EncodeToString(sig) + "\n"
	if err := os.WriteFile(sigPath, []byte(encoded), 0644); err != nil {
		return fmt.Errorf("write signature file %q: %w", sigPath, err)
	}
	return nil
}

func verifyFile(inPath, sigPath, pubHex string) error {
	pubKey, err := parsePublicKeyHex(pubHex)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("read input file %q: %w", inPath, err)
	}
	sigRaw, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("read signature file %q: %w", sigPath, err)
	}
	sigHex := strings.TrimSpace(string(sigRaw))
	if len(sigHex) != ed25519.SignatureSize*2 {
		return fmt.Errorf("invalid signature length: got %d hex chars, want %d", len(sigHex), ed25519.SignatureSize*2)
	}
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return errors.New("signature file is not valid hex")
	}
	if !ed25519.Verify(pubKey, data, sigBytes) {
		return errors.New("signature verification failed")
	}
	return nil
}

func parsePublicKeyHex(s string) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return nil, errors.New("--pubkey is required with --verify")
	}
	if len(trimmed) != ed25519.PublicKeySize*2 {
		return nil, fmt.Errorf("invalid --pubkey length: got %d hex chars, want %d", len(trimmed), ed25519.PublicKeySize*2)
	}
	pub, err := hex.DecodeString(trimmed)
	if err != nil {
		return nil, errors.New("invalid --pubkey: must be valid hex")
	}
	return ed25519.PublicKey(pub), nil
}

func parsePrivateKey(raw string) (ed25519.PrivateKey, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("%s environment variable is empty or unset", privKeyEnv)
	}

	if len(trimmed) == ed25519.SeedSize*2 || len(trimmed) == ed25519.PrivateKeySize*2 {
		if decoded, err := hex.DecodeString(trimmed); err == nil {
			return privateKeyFromBytes(decoded)
		}
	}

	encodings := []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	}
	for _, enc := range encodings {
		if decoded, err := enc.DecodeString(trimmed); err == nil {
			if len(decoded) == ed25519.SeedSize || len(decoded) == ed25519.PrivateKeySize {
				return privateKeyFromBytes(decoded)
			}
		}
	}

	return nil, fmt.Errorf("invalid %s: expected 64-char hex seed, 128-char hex private key, or base64 32/64-byte key", privKeyEnv)
}

func privateKeyFromBytes(b []byte) (ed25519.PrivateKey, error) {
	switch len(b) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(b), nil
	case ed25519.PrivateKeySize:
		expected := ed25519.NewKeyFromSeed(b[:ed25519.SeedSize])
		if !bytes.Equal(expected, b) {
			return nil, fmt.Errorf("invalid %s: 64-byte Ed25519 private key public suffix does not match seed", privKeyEnv)
		}
		return expected, nil
	default:
		return nil, fmt.Errorf("invalid %s decoded byte length: %d", privKeyEnv, len(b))
	}
}
