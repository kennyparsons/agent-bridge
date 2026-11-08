package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/acl"
)

// SignCSROptions configures how SignNodeCSR signs an incoming node Certificate Signing Request.
type SignCSROptions struct {
	ExtraIPs           []string
	ExtraDNSNames      []string
	Years              int
	ServerAndClientEKU bool
}

// GenerateKeyAndCSR generates an ECDSA P-256 private key and a SHA-256 signed PKCS#10
// Certificate Signing Request (CSR) embedding the provided CommonName, IP SANs, and DNS SANs.
// The returned private key PEM is encoded as "EC PRIVATE KEY" and never leaves the joining node.
func GenerateKeyAndCSR(
	commonName string,
	ips []string,
	dnsNames []string,
) (priv *ecdsa.PrivateKey, keyPEM []byte, csrPEM []byte, err error) {
	cn := strings.TrimSpace(commonName)
	if cn == "" {
		return nil, nil, nil, errors.New("CSR common name cannot be empty")
	}

	ipSANs, err := parseIPSANs(ips)
	if err != nil {
		return nil, nil, nil, err
	}
	dnsSANs := parseDNSSANs(dnsNames)

	priv, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate P-256 private key for CSR: %w", err)
	}

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to marshal ECDSA private key: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		IPAddresses:        ipSANs,
		DNSNames:           dnsSANs,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, priv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create X.509 CSR: %w", err)
	}
	csrPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return priv, keyPEM, csrPEM, nil
}

// GenerateAndSaveKeyAndCSR generates an ECDSA P-256 key and PKCS#10 CSR, atomically writes the
// private key PEM to keyOutPath, and enforces private file ACL lockdown via internal/acl.
func GenerateAndSaveKeyAndCSR(
	commonName string,
	ips []string,
	dnsNames []string,
	keyOutPath string,
) (priv *ecdsa.PrivateKey, keyPEM []byte, csrPEM []byte, err error) {
	trimmedKeyOut := strings.TrimSpace(keyOutPath)
	if trimmedKeyOut == "" {
		return nil, nil, nil, errors.New("CSR private key output path cannot be empty")
	}
	priv, keyPEM, csrPEM, err = GenerateKeyAndCSR(commonName, ips, dnsNames)
	if err != nil {
		return nil, nil, nil, err
	}
	if err := writeFileAtomic(trimmedKeyOut, keyPEM, 0o600); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to write CSR private key %q: %w", trimmedKeyOut, err)
	}
	if err := acl.LockdownPrivateFile(trimmedKeyOut); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to lock down CSR private key %q: %w", trimmedKeyOut, err)
	}
	return priv, keyPEM, csrPEM, nil
}

// SignNodeCSR parses and cryptographically verifies a PEM-encoded PKCS#10 CSR (proving private-key
// possession), merges CSR SANs with opts.ExtraIPs and opts.ExtraDNSNames, clamps validity to
// caCert.NotAfter, and signs a P-256 X.509 leaf certificate with caKey.
func SignNodeCSR(
	csrPEM []byte,
	caCert *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	opts SignCSROptions,
) (certPEM []byte, cert *x509.Certificate, err error) {
	if caCert == nil {
		return nil, nil, errors.New("Root CA certificate cannot be nil")
	}
	if !caCert.IsCA {
		return nil, nil, errors.New("issuer certificate is not a CA certificate (IsCA=false)")
	}
	if caKey == nil {
		return nil, nil, errors.New("Root CA private key cannot be nil")
	}
	caPub, ok := caCert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !caKey.PublicKey.Equal(caPub) {
		return nil, nil, errors.New("Root CA private key does not match Root CA certificate")
	}

	if opts.Years < 0 {
		return nil, nil, fmt.Errorf("years must be positive, got %d", opts.Years)
	}
	years := opts.Years
	if years == 0 {
		years = DefaultPeerYears
	}

	now := time.Now().UTC()
	if !now.Before(caCert.NotAfter) {
		return nil, nil, fmt.Errorf("cannot sign CSR: Root CA certificate expired at %s", caCert.NotAfter.UTC().Format(time.RFC3339))
	}

	block, rest := pem.Decode(csrPEM)
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return nil, nil, errors.New("payload does not contain a valid CERTIFICATE REQUEST PEM block")
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		return nil, nil, errors.New("payload contains unexpected trailing data after CERTIFICATE REQUEST PEM block")
	}

	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse X.509 CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("CSR cryptographic signature verification failed: %w", err)
	}

	csrPub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || csrPub.Curve != elliptic.P256() {
		return nil, nil, errors.New("CSR public key must be ECDSA P-256")
	}

	cn := strings.TrimSpace(csr.Subject.CommonName)
	if cn == "" {
		return nil, nil, errors.New("CSR Subject CommonName cannot be empty")
	}

	mergedIPs, err := mergeIPSANs(csr.IPAddresses, opts.ExtraIPs)
	if err != nil {
		return nil, nil, err
	}
	mergedDNS := mergeDNSSANs(csr.DNSNames, opts.ExtraDNSNames)

	notBefore := now.Add(-clockSkewLeeway)
	notAfter := now.AddDate(years, 0, 0)
	if notAfter.After(caCert.NotAfter) {
		notAfter = caCert.NotAfter
	}
	if !notAfter.After(notBefore) {
		return nil, nil, fmt.Errorf("cannot sign CSR: Root CA remaining validity is insufficient (expires %s)", caCert.NotAfter.UTC().Format(time.RFC3339))
	}

	serial, err := GenerateSerial()
	if err != nil {
		return nil, nil, err
	}

	leafSKI, err := computeSubjectKeyID(csrPub)
	if err != nil {
		return nil, nil, err
	}

	caSKI := caCert.SubjectKeyId
	if len(caSKI) == 0 {
		caSKI, err = computeSubjectKeyID(caPub)
		if err != nil {
			return nil, nil, err
		}
	}

	subject := pkix.Name{
		CommonName: cn,
	}
	if len(caCert.Subject.Organization) > 0 {
		subject.Organization = append([]string(nil), caCert.Subject.Organization...)
	}

	ekus := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if opts.ServerAndClientEKU {
		ekus = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	}

	leafTemplate := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           ekus,
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          leafSKI,
		AuthorityKeyId:        append([]byte(nil), caSKI...),
		IPAddresses:           mergedIPs,
		DNSNames:              mergedDNS,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, csrPub, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign CSR leaf certificate: %w", err)
	}
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse signed leaf certificate: %w", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	return certPEM, cert, nil
}

// VerifyPeerCertDualEKU validates raw peer X.509 certificates on the cluster TLS 1.3 transport,
// requiring a non-CA leaf signed by caPool with either ExtKeyUsageServerAuth or ExtKeyUsageClientAuth
// and verifying against crlWatcher (returning exact spec rejection text if revoked).
func VerifyPeerCertDualEKU(
	rawCerts [][]byte,
	caPool *x509.CertPool,
	crlWatcher *CRLWatcher,
) (*x509.Certificate, error) {
	if len(rawCerts) == 0 {
		return nil, errors.New("TLS Handshake Rejected: peer presented no certificates")
	}
	if caPool == nil {
		return nil, errors.New("TLS Handshake Rejected: Root CA pool is nil")
	}

	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, fmt.Errorf("TLS Handshake Rejected: malformed peer leaf certificate: %w", err)
	}
	if leaf.IsCA {
		return nil, errors.New("TLS Handshake Rejected: CA certificate cannot be used directly as peer leaf")
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) &&
		!slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageClientAuth) {
		return nil, errors.New("TLS Handshake Rejected: peer certificate lacks ServerAuth or ClientAuth extended key usage")
	}

	intermediates := x509.NewCertPool()
	for _, rawIntermediate := range rawCerts[1:] {
		ic, parseErr := x509.ParseCertificate(rawIntermediate)
		if parseErr != nil {
			return nil, fmt.Errorf("TLS Handshake Rejected: malformed intermediate certificate: %w", parseErr)
		}
		intermediates.AddCert(ic)
	}

	chains, verifyErr := leaf.Verify(x509.VerifyOptions{
		Roots:         caPool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if verifyErr != nil {
		chains, verifyErr = leaf.Verify(x509.VerifyOptions{
			Roots:         caPool,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		if verifyErr != nil {
			return nil, fmt.Errorf("TLS Handshake Rejected: peer certificate chain verification failed: %w", verifyErr)
		}
	}

	if crlWatcher != nil {
		if err := crlWatcher.CheckPeerChains(chains); err != nil {
			return nil, err
		}
	}

	return leaf, nil
}

func mergeIPSANs(csrIPs []net.IP, extraRaw []string) ([]net.IP, error) {
	var merged []net.IP
	seen := make(map[string]struct{})

	for _, ip := range csrIPs {
		if ip == nil {
			continue
		}
		norm := ip
		if ip4 := ip.To4(); ip4 != nil {
			norm = ip4
		}
		key := norm.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, norm)
	}

	parsedExtra, err := parseIPSANs(extraRaw)
	if err != nil {
		return nil, err
	}
	for _, ip := range parsedExtra {
		key := ip.String()
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, ip)
	}
	return merged, nil
}

func mergeDNSSANs(csrDNS []string, extraRaw []string) []string {
	combined := make([]string, 0, len(csrDNS)+len(extraRaw))
	combined = append(combined, csrDNS...)
	combined = append(combined, extraRaw...)
	return parseDNSSANs(combined)
}
