package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultCACommonName is the default Subject CN for the self-contained Root CA.
	DefaultCACommonName = "Agent-Bridge-Root-CA"
	// DefaultCAOrg is the default Subject Organization for the Root CA and issued certificates.
	DefaultCAOrg = "Agent-Bridge PKI"

	// DefaultCAYears is the default validity period (in years) for the Root CA and initial CRL.
	DefaultCAYears = 10
	// DefaultServerYears is the default validity period (in years) for server certificates.
	DefaultServerYears = 3
	// DefaultClientYears is the default validity period (in years) for client certificates.
	DefaultClientYears = 1
	// DefaultPeerYears is the default validity period (in years) for dual-EKU cluster peer certificates.
	DefaultPeerYears = 3

	// TypeServer selects the TLS Server certificate profile in IssueCert.
	TypeServer = "server"
	// TypeClient selects the mTLS Client certificate profile in IssueCert.
	TypeClient = "client"
	// TypePeer selects the dual-EKU (ServerAuth + ClientAuth) cluster peer certificate profile in IssueCert.
	TypePeer = "peer"

	// Standard artifact filenames inside PKI and certificate output directories.
	CACertFilename     = "ca.crt"
	CAKeyFilename      = "ca.key"
	CRLFilename        = "crl.pem"
	ServerCertFilename = "server.crt"
	ServerKeyFilename  = "server.key"
	ClientCertFilename = "client.crt"
	ClientKeyFilename  = "client.key"
	PeerCertFilename   = "peer.crt"
	PeerKeyFilename    = "peer.key"

	clockSkewLeeway = 5 * time.Minute
)

// InitCAOptions configures Root CA generation and initial CRL bootstrapping.
type InitCAOptions struct {
	OutDir     string
	CommonName string
	Org        string
	Years      int
}

// InitCAResult describes the generated Root CA and initial CRL artifacts.
type InitCAResult struct {
	CACertPath  string
	CAKeyPath   string
	CRLPath     string
	Serial      *big.Int
	SerialHex   string
	Certificate *x509.Certificate
}

// IssueCertOptions configures server or client leaf certificate issuance signed by the Root CA.
type IssueCertOptions struct {
	CADir    string
	OutDir   string
	Type     string
	Name     string
	IPs      []string
	DNSNames []string
	Years    int
}

// IssueCertResult describes the issued leaf certificate and private key artifacts.
type IssueCertResult struct {
	CertPath    string
	KeyPath     string
	Serial      *big.Int
	SerialHex   string
	Certificate *x509.Certificate
}

// RevokeCertOptions configures certificate revocation and atomic CRL regeneration.
type RevokeCertOptions struct {
	CADir        string
	Serial       string
	SerialNumber *big.Int
	CRLOut       string
}

// RevokeCertResult describes the updated CRL state after a revocation operation.
type RevokeCertResult struct {
	CRLPath        string
	Serial         *big.Int
	SerialHex      string
	CRLNumber      *big.Int
	AlreadyRevoked bool
	RevokedCount   int
}

type subjectPublicKeyInfoASN1 struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// GenerateSerial returns a cryptographically random, strictly positive 128-bit integer in [1, 2^128 - 1].
func GenerateSerial() (*big.Int, error) {
	// maxOffset = 2^128 - 1; rand.Int returns n in [0, 2^128 - 2]; n + 1 is uniform in [1, 2^128 - 1].
	twoPow128 := new(big.Int).Lsh(big.NewInt(1), 128)
	maxOffset := new(big.Int).Sub(twoPow128, big.NewInt(1))
	n, err := rand.Int(rand.Reader, maxOffset)
	if err != nil {
		return nil, fmt.Errorf("failed to generate 128-bit random serial: %w", err)
	}
	return new(big.Int).Add(n, big.NewInt(1)), nil
}

// FormatSerialHex formats a serial number as uppercase colon-separated hex bytes (e.g. "4A:2F:89:1B"),
// padding each byte to two uppercase hexadecimal digits.
func FormatSerialHex(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	if serial.Sign() == 0 {
		return "00"
	}
	prefix := ""
	mag := serial
	if serial.Sign() < 0 {
		prefix = "-"
		mag = new(big.Int).Abs(serial)
	}
	raw := mag.Bytes()
	parts := make([]string, len(raw))
	for i, b := range raw {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return prefix + strings.Join(parts, ":")
}

// ParseSerialHex parses a strictly positive serial number from colon-separated hex ("4A:2F:..."),
// plain hex ("4a2f..."), or 0x-prefixed hex ("0x4A2F...").
func ParseSerialHex(s string) (*big.Int, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return nil, errors.New("serial number cannot be empty")
	}
	if strings.HasPrefix(trimmed, "-") {
		return nil, errors.New("serial number must be positive")
	}
	if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") {
		trimmed = trimmed[2:]
	}
	if trimmed == "" {
		return nil, errors.New("serial number hex payload is empty")
	}

	var normalized strings.Builder
	if strings.Contains(trimmed, ":") {
		segments := strings.Split(trimmed, ":")
		normalized.Grow(len(segments) * 2)
		for _, seg := range segments {
			if len(seg) == 0 || len(seg) > 2 {
				return nil, fmt.Errorf("invalid colon-separated hex byte %q in serial %q", seg, s)
			}
			if len(seg) == 1 {
				normalized.WriteByte('0')
			}
			normalized.WriteString(seg)
		}
	} else {
		if len(trimmed)%2 != 0 {
			normalized.WriteByte('0')
		}
		normalized.WriteString(trimmed)
	}

	decoded, err := hex.DecodeString(normalized.String())
	if err != nil {
		return nil, fmt.Errorf("invalid hexadecimal serial %q: %w", s, err)
	}
	serial := new(big.Int).SetBytes(decoded)
	if serial.Sign() <= 0 {
		return nil, fmt.Errorf("serial number %q must be strictly positive", s)
	}
	return serial, nil
}

// computeSubjectKeyID computes a 20-byte RFC 7093 Method 1 SubjectKeyIdentifier (truncated SHA-256 over SPKI BIT STRING).
func computeSubjectKeyID(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil {
		return nil, errors.New("nil ECDSA public key")
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SPKI public key: %w", err)
	}
	var spki subjectPublicKeyInfoASN1
	if _, err := asn1.Unmarshal(spkiDER, &spki); err != nil {
		return nil, fmt.Errorf("failed to unmarshal SPKI ASN.1 structure: %w", err)
	}
	sum := sha256.Sum256(spki.PublicKey.Bytes)
	ski := make([]byte, 20)
	copy(ski, sum[:20])
	return ski, nil
}

// InitCA generates an ECDSA P-256 self-signed Root CA, writes ca.crt (0644) and ca.key (0600),
// and bootstraps an initial empty RFC 5280 v2 crl.pem (0644) with CRLNumber = 1.
func InitCA(opts InitCAOptions) (*InitCAResult, error) {
	outDir := strings.TrimSpace(opts.OutDir)
	if outDir == "" {
		return nil, errors.New("out-dir is required")
	}

	commonName := strings.TrimSpace(opts.CommonName)
	if commonName == "" {
		commonName = DefaultCACommonName
	}

	org := strings.TrimSpace(opts.Org)
	if org == "" {
		org = DefaultCAOrg
	}

	years := opts.Years
	if years < 0 {
		return nil, fmt.Errorf("years must be positive, got %d", years)
	}
	if years == 0 {
		years = DefaultCAYears
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create CA directory %q: %w", outDir, err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P-256 Root CA key: %w", err)
	}

	serial, err := GenerateSerial()
	if err != nil {
		return nil, err
	}

	ski, err := computeSubjectKeyID(&caKey.PublicKey)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	notBefore := now.Add(-clockSkewLeeway)
	notAfter := now.AddDate(years, 0, 0)

	caTemplate := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{org},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          ski,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create Root CA certificate: %w", err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated Root CA certificate: %w", err)
	}

	caCertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caDER,
	})

	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Root CA ECDSA private key: %w", err)
	}
	caKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: caKeyDER,
	})

	crlTemplate := &x509.RevocationList{
		SignatureAlgorithm:        x509.ECDSAWithSHA256,
		RevokedCertificateEntries: nil,
		Number:                    big.NewInt(1),
		ThisUpdate:                notBefore,
		NextUpdate:                notAfter,
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create initial CRL: %w", err)
	}
	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})

	caCertPath := filepath.Join(outDir, CACertFilename)
	caKeyPath := filepath.Join(outDir, CAKeyFilename)
	crlPath := filepath.Join(outDir, CRLFilename)

	if err := writeFileAtomic(caKeyPath, caKeyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write CA private key: %w", err)
	}
	if err := writeFileAtomic(caCertPath, caCertPEM, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write CA certificate: %w", err)
	}
	if err := writeFileAtomic(crlPath, crlPEM, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write initial CRL: %w", err)
	}

	return &InitCAResult{
		CACertPath:  caCertPath,
		CAKeyPath:   caKeyPath,
		CRLPath:     crlPath,
		Serial:      new(big.Int).Set(serial),
		SerialHex:   FormatSerialHex(serial),
		Certificate: caCert,
	}, nil
}

// IssueCert issues an ECDSA P-256 server or client certificate signed by the Root CA in opts.CADir.
func IssueCert(opts IssueCertOptions) (*IssueCertResult, error) {
	caDir := strings.TrimSpace(opts.CADir)
	if caDir == "" {
		return nil, errors.New("ca-dir is required")
	}

	outDir := strings.TrimSpace(opts.OutDir)
	if outDir == "" {
		return nil, errors.New("out-dir is required")
	}

	name := strings.TrimSpace(opts.Name)
	if name == "" {
		return nil, errors.New("certificate common name (--name) is required")
	}

	certType := strings.ToLower(strings.TrimSpace(opts.Type))
	if certType != TypeServer && certType != TypeClient && certType != TypePeer {
		return nil, fmt.Errorf("invalid certificate type %q: must be %q, %q, or %q", opts.Type, TypeServer, TypeClient, TypePeer)
	}

	if opts.Years < 0 {
		return nil, fmt.Errorf("years must be positive, got %d", opts.Years)
	}
	years := opts.Years
	if years == 0 {
		switch certType {
		case TypeServer:
			years = DefaultServerYears
		case TypePeer:
			years = DefaultPeerYears
		default:
			years = DefaultClientYears
		}
	}

	ipSANs, err := parseIPSANs(opts.IPs)
	if err != nil {
		return nil, err
	}
	dnsSANs := parseDNSSANs(opts.DNSNames)

	if certType == TypeServer && len(ipSANs) == 0 && len(dnsSANs) == 0 {
		return nil, errors.New("server certificate requires at least one IP (--ip) or DNS (--dns) Subject Alternative Name")
	}

	caCert, caKey, err := loadCAKeyPair(caDir)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if !now.Before(caCert.NotAfter) {
		return nil, fmt.Errorf("cannot issue %s certificate: Root CA certificate expired at %s", certType, caCert.NotAfter.UTC().Format(time.RFC3339))
	}

	notBefore := now.Add(-clockSkewLeeway)
	notAfter := now.AddDate(years, 0, 0)
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	if !notAfter.After(notBefore) {
		return nil, fmt.Errorf("cannot issue %s certificate: Root CA remaining validity is insufficient (expires %s)", certType, caCert.NotAfter.UTC().Format(time.RFC3339))
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, fmt.Errorf("failed to create certificate output directory %q: %w", outDir, err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate P-256 %s private key: %w", certType, err)
	}

	serial, err := GenerateSerial()
	if err != nil {
		return nil, err
	}

	leafSKI, err := computeSubjectKeyID(&leafKey.PublicKey)
	if err != nil {
		return nil, err
	}

	subject := pkix.Name{
		CommonName: name,
	}
	if len(caCert.Subject.Organization) > 0 {
		subject.Organization = append([]string(nil), caCert.Subject.Organization...)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          leafSKI,
		AuthorityKeyId:        append([]byte(nil), caCert.SubjectKeyId...),
	}

	var certFilename, keyFilename string
	switch certType {
	case TypeServer:
		leafTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		leafTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		leafTemplate.IPAddresses = ipSANs
		leafTemplate.DNSNames = dnsSANs
		certFilename = ServerCertFilename
		keyFilename = ServerKeyFilename
	case TypeClient:
		leafTemplate.KeyUsage = x509.KeyUsageDigitalSignature
		leafTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		certFilename = ClientCertFilename
		keyFilename = ClientKeyFilename
	case TypePeer:
		leafTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
		leafTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
		leafTemplate.IPAddresses = ipSANs
		leafTemplate.DNSNames = dnsSANs
		certFilename = PeerCertFilename
		keyFilename = PeerKeyFilename
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign %s certificate: %w", certType, err)
	}

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issued %s certificate: %w", certType, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: leafDER,
	})

	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal %s ECDSA private key: %w", certType, err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	certPath := filepath.Join(outDir, certFilename)
	keyPath := filepath.Join(outDir, keyFilename)

	if err := writeFileAtomic(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write %s private key: %w", certType, err)
	}
	if err := writeFileAtomic(certPath, certPEM, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write %s certificate: %w", certType, err)
	}

	return &IssueCertResult{
		CertPath:    certPath,
		KeyPath:     keyPath,
		Serial:      new(big.Int).Set(serial),
		SerialHex:   FormatSerialHex(serial),
		Certificate: leafCert,
	}, nil
}

// RevokeCert appends a revoked certificate serial number to the Root CA's CRL,
// increments the RFC 5280 CRLNumber extension monotonically, signs the updated CRL,
// and writes it atomically to disk so active fsnotify watchers never observe partial writes.
func RevokeCert(opts RevokeCertOptions) (*RevokeCertResult, error) {
	caDir := strings.TrimSpace(opts.CADir)
	if caDir == "" {
		return nil, errors.New("ca-dir is required")
	}

	var targetSerial *big.Int
	if opts.SerialNumber != nil {
		if opts.SerialNumber.Sign() <= 0 {
			return nil, errors.New("serial number must be strictly positive")
		}
		targetSerial = new(big.Int).Set(opts.SerialNumber)
	}
	if strings.TrimSpace(opts.Serial) != "" {
		parsed, err := ParseSerialHex(opts.Serial)
		if err != nil {
			return nil, err
		}
		if targetSerial != nil && targetSerial.Cmp(parsed) != 0 {
			return nil, fmt.Errorf("conflicting serial numbers provided: %s vs %s", FormatSerialHex(targetSerial), FormatSerialHex(parsed))
		}
		targetSerial = parsed
	}
	if targetSerial == nil {
		return nil, errors.New("serial number (--serial) is required")
	}

	crlOut := strings.TrimSpace(opts.CRLOut)
	defaultCRLPath := filepath.Join(caDir, CRLFilename)
	if crlOut == "" {
		crlOut = defaultCRLPath
	}

	caCert, caKey, err := loadCAKeyPair(caDir)
	if err != nil {
		return nil, err
	}

	sourceCRLPath := crlOut
	if _, statErr := os.Stat(sourceCRLPath); errors.Is(statErr, os.ErrNotExist) && sourceCRLPath != defaultCRLPath {
		if _, fallbackErr := os.Stat(defaultCRLPath); fallbackErr == nil {
			sourceCRLPath = defaultCRLPath
		}
	}

	existingCRL, err := LoadCRL(sourceCRLPath, caCert)
	if err != nil {
		return nil, fmt.Errorf("failed to load existing CRL %q: %w", sourceCRLPath, err)
	}

	nextCRLNum := big.NewInt(1)
	if existingCRL.Number != nil && existingCRL.Number.Sign() > 0 {
		nextCRLNum = new(big.Int).Add(existingCRL.Number, big.NewInt(1))
	}

	now := time.Now().UTC()
	entries := make([]x509.RevocationListEntry, 0, len(existingCRL.RevokedCertificateEntries)+1)
	alreadyRevoked := false
	for _, entry := range existingCRL.RevokedCertificateEntries {
		if entry.SerialNumber == nil {
			continue
		}
		copied := x509.RevocationListEntry{
			SerialNumber:    new(big.Int).Set(entry.SerialNumber),
			RevocationTime:  entry.RevocationTime,
			ReasonCode:      entry.ReasonCode,
			ExtraExtensions: append([]pkix.Extension(nil), entry.Extensions...),
		}
		if entry.SerialNumber.Cmp(targetSerial) == 0 {
			alreadyRevoked = true
		}
		entries = append(entries, copied)
	}

	if !alreadyRevoked {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   new(big.Int).Set(targetSerial),
			RevocationTime: now,
		})
	}

	nextUpdate := existingCRL.NextUpdate
	if !nextUpdate.After(now) {
		nextUpdate = caCert.NotAfter
	}
	if !nextUpdate.After(now) {
		return nil, errors.New("cannot issue updated CRL: Root CA certificate has expired")
	}

	updatedTemplate := &x509.RevocationList{
		SignatureAlgorithm:        x509.ECDSAWithSHA256,
		RevokedCertificateEntries: entries,
		Number:                    nextCRLNum,
		ThisUpdate:                now.Add(-clockSkewLeeway),
		NextUpdate:                nextUpdate,
	}

	crlDER, err := x509.CreateRevocationList(rand.Reader, updatedTemplate, caCert, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign updated CRL: %w", err)
	}

	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})

	if err := writeFileAtomic(crlOut, crlPEM, 0o644); err != nil {
		return nil, fmt.Errorf("failed to write updated CRL %q: %w", crlOut, err)
	}

	return &RevokeCertResult{
		CRLPath:        crlOut,
		Serial:         new(big.Int).Set(targetSerial),
		SerialHex:      FormatSerialHex(targetSerial),
		CRLNumber:      new(big.Int).Set(nextCRLNum),
		AlreadyRevoked: alreadyRevoked,
		RevokedCount:   len(entries),
	}, nil
}

// LoadCertificate reads and parses a single PEM-encoded X.509 certificate from disk.
func LoadCertificate(certPath string) (*x509.Certificate, error) {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate %q: %w", certPath, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("file %q does not contain a valid CERTIFICATE PEM block", certPath)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate %q: %w", certPath, err)
	}
	return cert, nil
}

// CertFingerprintSHA256 returns the 64-character lowercase hexadecimal SHA-256 digest of cert.Raw,
// or an empty string if cert or cert.Raw is empty.
func CertFingerprintSHA256(cert *x509.Certificate) string {
	if cert == nil || len(cert.Raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// ParseAndVerifyCRL decodes a PEM-encoded X.509 CRL, parses it, and verifies its cryptographic signature against caCert.
func ParseAndVerifyCRL(crlPEM []byte, caCert *x509.Certificate) (*x509.RevocationList, error) {
	if caCert == nil {
		return nil, errors.New("caCert cannot be nil when verifying CRL")
	}
	block, rest := pem.Decode(crlPEM)
	if block == nil || block.Type != "X509 CRL" {
		return nil, errors.New("payload does not contain a valid X509 CRL PEM block")
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		return nil, errors.New("payload contains unexpected trailing data after X509 CRL PEM block")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 CRL: %w", err)
	}
	if err := crl.CheckSignatureFrom(caCert); err != nil {
		return nil, fmt.Errorf("CRL signature verification against Root CA failed: %w", err)
	}
	return crl, nil
}

// LoadCRL reads a PEM-encoded X.509 CRL from disk, parses it, and verifies its cryptographic signature against caCert.
func LoadCRL(crlPath string, caCert *x509.Certificate) (*x509.RevocationList, error) {
	if caCert == nil {
		return nil, errors.New("caCert cannot be nil when verifying CRL")
	}
	raw, err := os.ReadFile(crlPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRL %q: %w", crlPath, err)
	}
	crl, err := ParseAndVerifyCRL(raw, caCert)
	if err != nil {
		return nil, fmt.Errorf("CRL %q invalid: %w", crlPath, err)
	}
	return crl, nil
}

// LoadCAKeyPair loads and cross-verifies a Root CA certificate and its matching ECDSA P-256 private key from disk.
func LoadCAKeyPair(caCertPath, caKeyPath string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	caCert, err := LoadCertificate(caCertPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load Root CA certificate: %w", err)
	}
	if !caCert.IsCA {
		return nil, nil, fmt.Errorf("certificate %q is not a CA certificate (IsCA=false)", caCertPath)
	}
	if len(caCert.SubjectKeyId) == 0 {
		caPub, ok := caCert.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, nil, fmt.Errorf("CA certificate %q does not hold an ECDSA public key", caCertPath)
		}
		ski, skiErr := computeSubjectKeyID(caPub)
		if skiErr != nil {
			return nil, nil, skiErr
		}
		caCert.SubjectKeyId = ski
	}

	caKey, err := LoadPrivateKey(caKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load Root CA private key: %w", err)
	}

	caPub, ok := caCert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !caKey.PublicKey.Equal(caPub) {
		return nil, nil, fmt.Errorf("Root CA private key %q does not match certificate %q", caKeyPath, caCertPath)
	}

	return caCert, caKey, nil
}

func loadCAKeyPair(caDir string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	return LoadCAKeyPair(filepath.Join(caDir, CACertFilename), filepath.Join(caDir, CAKeyFilename))
}

// ParsePrivateKeyPEM parses a PEM-encoded ECDSA P-256 private key ("EC PRIVATE KEY" or PKCS#8 "PRIVATE KEY").
func ParsePrivateKeyPEM(keyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("payload does not contain a valid PEM block")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC PRIVATE KEY: %w", err)
		}
		if key.Curve != elliptic.P256() {
			return nil, errors.New("unsupported elliptic curve: expected P-256")
		}
		return key, nil
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 PRIVATE KEY: %w", err)
		}
		key, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 private key is %T, expected *ecdsa.PrivateKey", parsed)
		}
		if key.Curve != elliptic.P256() {
			return nil, errors.New("unsupported elliptic curve: expected P-256")
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported private key PEM type %q", block.Type)
	}
}

// LoadPrivateKey reads and parses a PEM-encoded ECDSA P-256 private key from disk.
func LoadPrivateKey(keyPath string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key %q: %w", keyPath, err)
	}
	key, err := ParsePrivateKeyPEM(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid private key %q: %w", keyPath, err)
	}
	return key, nil
}

func loadECPrivateKey(keyPath string) (*ecdsa.PrivateKey, error) {
	return LoadPrivateKey(keyPath)
}

func parseIPSANs(rawIPs []string) ([]net.IP, error) {
	var result []net.IP
	seen := make(map[string]struct{})
	for _, entry := range rawIPs {
		for _, token := range strings.Split(entry, ",") {
			candidate := strings.TrimSpace(token)
			if candidate == "" {
				continue
			}
			parsed := net.ParseIP(candidate)
			if parsed == nil {
				return nil, fmt.Errorf("invalid IP address %q in SANs", candidate)
			}
			if ip4 := parsed.To4(); ip4 != nil {
				parsed = ip4
			}
			canonical := parsed.String()
			if _, exists := seen[canonical]; exists {
				continue
			}
			seen[canonical] = struct{}{}
			result = append(result, parsed)
		}
	}
	return result, nil
}

func parseDNSSANs(rawDNS []string) []string {
	var result []string
	seen := make(map[string]struct{})
	for _, entry := range rawDNS {
		for _, token := range strings.Split(entry, ",") {
			candidate := strings.TrimSpace(token)
			if candidate == "" {
				continue
			}
			key := strings.ToLower(candidate)
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, candidate)
		}
	}
	return result
}

// WriteFileAtomic writes data to a temporary file in filepath.Dir(path),
// applies exact file permissions (bypassing process umask), fsyncs, and renames into place.
func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	return writeFileAtomic(path, data, perm)
}

// writeFileAtomic writes data to a temporary file in filepath.Dir(targetPath),
// applies exact file permissions (bypassing process umask), fsyncs, and renames into place.
func writeFileAtomic(targetPath string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("failed to ensure parent directory %q: %w", dir, err)
	}

	tmpFile, err := os.CreateTemp(dir, ".agent-bridge-tmp-*")
	if err != nil {
		return fmt.Errorf("failed to create temporary file in %q: %w", dir, err)
	}
	tmpPath := tmpFile.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmpFile.Write(data); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to write temporary file %q: %w", tmpPath, err)
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("failed to sync temporary file %q: %w", tmpPath, err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temporary file %q: %w", tmpPath, err)
	}
	if err := os.Chmod(tmpPath, perm); err != nil {
		return fmt.Errorf("failed to set permissions %04o on %q: %w", perm, tmpPath, err)
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return fmt.Errorf("failed to atomically rename %q -> %q: %w", tmpPath, targetPath, err)
	}

	cleanup = false
	return nil
}
