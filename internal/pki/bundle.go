package pki

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/kennyparsons/agent-bridge/internal/acl"
)

const (
	// BundleVersionV1 identifies a plaintext JSON ClientBundle (.abbundle).
	BundleVersionV1 = "abbundle.v1"
	// BundleEncryptedVersionV1 identifies a passphrase-encrypted AES-256-GCM ClientBundle (.abbundle).
	BundleEncryptedVersionV1 = "abbundle.enc.v1"
	// BundleFileExtension is the standard extension for self-contained client onboarding bundles.
	BundleFileExtension = ".abbundle"

	bundleKDFIterations = 210000
	bundleSaltBytes     = 16
	bundleKeyBytes      = 32
	bundleKDFName       = "pbkdf2-hmac-sha256"
	bundleCipherName    = "aes-256-gcm"
)

var (
	// ErrBundlePassphraseRequired is returned when attempting to unmarshal an encrypted bundle with an empty passphrase.
	ErrBundlePassphraseRequired = errors.New("client bundle is encrypted: passphrase is required")
	// ErrBundleInvalidPassphrase is returned when AES-256-GCM authentication fails during bundle decryption.
	ErrBundleInvalidPassphrase = errors.New("failed to decrypt client bundle: invalid passphrase or corrupted ciphertext")
)

// HostBundleEntry defines per-host connection targets inside a ClientBundle.
type HostBundleEntry struct {
	Endpoint        string `json:"endpoint,omitempty"`
	ClusterEndpoint string `json:"cluster_endpoint,omitempty"`
	Timeout         string `json:"timeout,omitempty"`
}

// ClientBundle represents a self-contained `.abbundle` onboarding payload carrying the Root CA
// certificate, mTLS client certificate + private key, and named host connection profiles.
type ClientBundle struct {
	Version         string                     `json:"version"`
	DefaultHost     string                     `json:"default_host,omitempty"`
	Endpoint        string                     `json:"endpoint,omitempty"`
	ClusterEndpoint string                     `json:"cluster_endpoint,omitempty"`
	Timeout         string                     `json:"timeout,omitempty"`
	Hosts           map[string]HostBundleEntry `json:"hosts,omitempty"`
	CACertPEM       string                     `json:"ca_cert_pem"`
	ClientCertPEM   string                     `json:"client_cert_pem"`
	ClientKeyPEM    string                     `json:"client_key_pem"`
}

// BuildClientBundleOptions configures BuildClientBundle from on-disk PEM artifacts.
type BuildClientBundleOptions struct {
	CACertPath      string
	ClientCertPath  string
	ClientKeyPath   string
	DefaultHost     string
	Endpoint        string
	ClusterEndpoint string
	Timeout         string
	Hosts           map[string]HostBundleEntry
}

type encryptedBundleEnvelope struct {
	Version      string `json:"version"`
	KDF          string `json:"kdf"`
	Iterations   int    `json:"iterations"`
	SaltBase64   string `json:"salt"`
	Cipher       string `json:"cipher"`
	NonceBase64  string `json:"nonce"`
	CipherBase64 string `json:"ciphertext"`
}

type bundleVersionProbe struct {
	Version string `json:"version"`
}

// BuildClientBundle loads CACertPath, ClientCertPath, and ClientKeyPath from disk, attaches target
// host metadata, cryptographically validates the chain and keypair, and returns a ClientBundle.
func BuildClientBundle(opts BuildClientBundleOptions) (*ClientBundle, error) {
	caRaw, err := os.ReadFile(strings.TrimSpace(opts.CACertPath))
	if err != nil {
		return nil, fmt.Errorf("failed to read Root CA certificate %q: %w", opts.CACertPath, err)
	}
	certRaw, err := os.ReadFile(strings.TrimSpace(opts.ClientCertPath))
	if err != nil {
		return nil, fmt.Errorf("failed to read client certificate %q: %w", opts.ClientCertPath, err)
	}
	keyRaw, err := os.ReadFile(strings.TrimSpace(opts.ClientKeyPath))
	if err != nil {
		return nil, fmt.Errorf("failed to read client private key %q: %w", opts.ClientKeyPath, err)
	}

	var hostsCopy map[string]HostBundleEntry
	if len(opts.Hosts) > 0 {
		hostsCopy = make(map[string]HostBundleEntry, len(opts.Hosts))
		for k, v := range opts.Hosts {
			trimmed := strings.TrimSpace(k)
			if trimmed == "" {
				continue
			}
			hostsCopy[trimmed] = HostBundleEntry{
				Endpoint:        strings.TrimSpace(v.Endpoint),
				ClusterEndpoint: strings.TrimSpace(v.ClusterEndpoint),
				Timeout:         strings.TrimSpace(v.Timeout),
			}
		}
	}

	bundle := &ClientBundle{
		Version:         BundleVersionV1,
		DefaultHost:     strings.TrimSpace(opts.DefaultHost),
		Endpoint:        strings.TrimSpace(opts.Endpoint),
		ClusterEndpoint: strings.TrimSpace(opts.ClusterEndpoint),
		Timeout:         strings.TrimSpace(opts.Timeout),
		Hosts:           hostsCopy,
		CACertPEM:       string(caRaw),
		ClientCertPEM:   string(certRaw),
		ClientKeyPEM:    string(keyRaw),
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	return bundle, nil
}

// Validate cryptographically verifies that CACertPEM is a valid CA, ClientCertPEM and ClientKeyPEM
// form a matching ECDSA P-256 TLS keypair, and ClientCertPEM chains to CACertPEM with ClientAuth EKU.
func (b *ClientBundle) Validate() error {
	if b == nil {
		return errors.New("client bundle cannot be nil")
	}
	if b.Version != "" && b.Version != BundleVersionV1 {
		return fmt.Errorf("unsupported client bundle version %q (expected %q)", b.Version, BundleVersionV1)
	}
	if strings.TrimSpace(b.CACertPEM) == "" {
		return errors.New("client bundle is missing ca_cert_pem")
	}
	if strings.TrimSpace(b.ClientCertPEM) == "" {
		return errors.New("client bundle is missing client_cert_pem")
	}
	if strings.TrimSpace(b.ClientKeyPEM) == "" {
		return errors.New("client bundle is missing client_key_pem")
	}

	caBlock, _ := pem.Decode([]byte(b.CACertPEM))
	if caBlock == nil || caBlock.Type != "CERTIFICATE" {
		return errors.New("client bundle ca_cert_pem does not contain a valid CERTIFICATE PEM block")
	}
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("invalid ca_cert_pem in client bundle: %w", err)
	}
	if !caCert.IsCA {
		return errors.New("ca_cert_pem in client bundle is not a CA certificate")
	}

	if _, err := ParsePrivateKeyPEM([]byte(b.ClientKeyPEM)); err != nil {
		return fmt.Errorf("invalid client_key_pem in client bundle: %w", err)
	}

	tlsPair, err := tls.X509KeyPair([]byte(b.ClientCertPEM), []byte(b.ClientKeyPEM))
	if err != nil || len(tlsPair.Certificate) == 0 {
		return fmt.Errorf("client_cert_pem and client_key_pem do not form a matching keypair: %w", err)
	}

	leafCert, err := x509.ParseCertificate(tlsPair.Certificate[0])
	if err != nil {
		return fmt.Errorf("invalid client_cert_pem in client bundle: %w", err)
	}
	if leafCert.IsCA {
		return errors.New("client_cert_pem in client bundle cannot be a CA certificate")
	}
	if !slices.Contains(leafCert.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return errors.New("client_cert_pem in client bundle lacks ExtKeyUsageClientAuth")
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	if _, err := leafCert.Verify(x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("client_cert_pem does not chain to ca_cert_pem: %w", err)
	}

	if dh := strings.TrimSpace(b.DefaultHost); dh != "" && len(b.Hosts) > 0 {
		if _, ok := b.Hosts[dh]; !ok {
			return fmt.Errorf("client bundle default_host %q is not defined in hosts map", dh)
		}
	}
	return nil
}

// IsEncryptedBundle reports whether raw JSON bytes represent an encrypted `abbundle.enc.v1` envelope.
func IsEncryptedBundle(data []byte) bool {
	trimmed := bytes.TrimPrefix(bytes.TrimSpace(data), []byte("\xef\xbb\xbf"))
	var probe bundleVersionProbe
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return false
	}
	return probe.Version == BundleEncryptedVersionV1
}

// MarshalBundle serializes a validated ClientBundle to JSON (`abbundle.v1`), optionally encrypting
// the payload with AES-256-GCM + PBKDF2-HMAC-SHA256 (`abbundle.enc.v1`) when passphrase is non-empty.
func MarshalBundle(b *ClientBundle, passphrase string) ([]byte, error) {
	if b == nil {
		return nil, errors.New("client bundle cannot be nil")
	}
	clone := *b
	if clone.Version == "" {
		clone.Version = BundleVersionV1
	}
	if err := clone.Validate(); err != nil {
		return nil, err
	}

	plainJSON, err := json.MarshalIndent(&clone, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal client bundle JSON: %w", err)
	}
	plainJSON = append(plainJSON, '\n')

	if passphrase == "" {
		return plainJSON, nil
	}

	salt := make([]byte, bundleSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("failed to generate bundle encryption salt: %w", err)
	}
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, bundleKDFIterations, bundleKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to derive bundle encryption key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES-256 cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES-256-GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate AES-256-GCM nonce: %w", err)
	}

	aad := []byte(BundleEncryptedVersionV1)
	ciphertext := gcm.Seal(nil, nonce, plainJSON, aad)

	env := encryptedBundleEnvelope{
		Version:      BundleEncryptedVersionV1,
		KDF:          bundleKDFName,
		Iterations:   bundleKDFIterations,
		SaltBase64:   base64.StdEncoding.EncodeToString(salt),
		Cipher:       bundleCipherName,
		NonceBase64:  base64.StdEncoding.EncodeToString(nonce),
		CipherBase64: base64.StdEncoding.EncodeToString(ciphertext),
	}
	encJSON, err := json.MarshalIndent(&env, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal encrypted client bundle envelope: %w", err)
	}
	return append(encJSON, '\n'), nil
}

// UnmarshalBundle parses and validates a plaintext (`abbundle.v1`) or passphrase-encrypted
// (`abbundle.enc.v1`) ClientBundle from raw bytes.
func UnmarshalBundle(data []byte, passphrase string) (*ClientBundle, error) {
	trimmed := bytes.TrimPrefix(bytes.TrimSpace(data), []byte("\xef\xbb\xbf"))
	if len(trimmed) == 0 {
		return nil, errors.New("client bundle payload cannot be empty")
	}

	var probe bundleVersionProbe
	if err := json.Unmarshal(trimmed, &probe); err != nil {
		return nil, fmt.Errorf("invalid client bundle JSON: %w", err)
	}

	var plainBytes []byte
	switch probe.Version {
	case BundleEncryptedVersionV1:
		if passphrase == "" {
			return nil, ErrBundlePassphraseRequired
		}
		var env encryptedBundleEnvelope
		if err := json.Unmarshal(trimmed, &env); err != nil {
			return nil, fmt.Errorf("invalid encrypted bundle envelope: %w", err)
		}
		if env.KDF != bundleKDFName {
			return nil, fmt.Errorf("unsupported bundle KDF %q", env.KDF)
		}
		if env.Cipher != bundleCipherName {
			return nil, fmt.Errorf("unsupported bundle cipher %q", env.Cipher)
		}
		if env.Iterations < 10000 || env.Iterations > 5_000_000 {
			return nil, fmt.Errorf("invalid bundle KDF iterations %d", env.Iterations)
		}
		salt, err := base64.StdEncoding.DecodeString(env.SaltBase64)
		if err != nil || len(salt) < 8 {
			return nil, errors.New("invalid salt in encrypted client bundle")
		}
		nonce, err := base64.StdEncoding.DecodeString(env.NonceBase64)
		if err != nil {
			return nil, errors.New("invalid nonce in encrypted client bundle")
		}
		ciphertext, err := base64.StdEncoding.DecodeString(env.CipherBase64)
		if err != nil || len(ciphertext) == 0 {
			return nil, errors.New("invalid ciphertext in encrypted client bundle")
		}

		key, err := pbkdf2.Key(sha256.New, passphrase, salt, env.Iterations, bundleKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to derive bundle decryption key: %w", err)
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize AES-256 cipher: %w", err)
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize AES-256-GCM: %w", err)
		}
		if len(nonce) != gcm.NonceSize() {
			return nil, errors.New("invalid AES-256-GCM nonce length in encrypted client bundle")
		}

		decrypted, err := gcm.Open(nil, nonce, ciphertext, []byte(BundleEncryptedVersionV1))
		if err != nil {
			return nil, ErrBundleInvalidPassphrase
		}
		plainBytes = decrypted

	case BundleVersionV1, "":
		plainBytes = trimmed

	default:
		return nil, fmt.Errorf("unsupported client bundle version %q", probe.Version)
	}

	var bundle ClientBundle
	if err := json.Unmarshal(plainBytes, &bundle); err != nil {
		return nil, fmt.Errorf("failed to decode client bundle payload: %w", err)
	}
	if bundle.Version == "" {
		bundle.Version = BundleVersionV1
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}
	return &bundle, nil
}

// WriteBundleFile marshals b (optionally encrypted with passphrase), writes it atomically to path,
// and enforces private file ACL lockdown (`acl.LockdownPrivateFile`).
func WriteBundleFile(path string, b *ClientBundle, passphrase string) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return errors.New("bundle output path cannot be empty")
	}
	cleanPath := filepath.Clean(trimmed)

	encoded, err := MarshalBundle(b, passphrase)
	if err != nil {
		return err
	}
	if err := writeFileAtomic(cleanPath, encoded, 0o600); err != nil {
		return fmt.Errorf("failed to write bundle file %q: %w", cleanPath, err)
	}
	if err := acl.LockdownPrivateFile(cleanPath); err != nil {
		return fmt.Errorf("failed to lock down bundle file %q: %w", cleanPath, err)
	}
	return nil
}

// ReadBundleFile reads a `.abbundle` file from disk and unmarshals/decrypts it using passphrase.
func ReadBundleFile(path string, passphrase string) (*ClientBundle, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return nil, errors.New("bundle path cannot be empty")
	}
	raw, err := os.ReadFile(filepath.Clean(trimmed))
	if err != nil {
		return nil, fmt.Errorf("failed to read bundle file %q: %w", path, err)
	}
	return UnmarshalBundle(raw, passphrase)
}
