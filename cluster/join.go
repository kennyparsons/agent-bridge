package cluster

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/pki"
	"github.com/kennyparsons/agent-bridge/internal/protocol"
)

const (
	bootstrapJoinHTTPTimeout = 20 * time.Second
	maxJoinBodyBytes         = 1 << 20 // 1 MiB ceiling on join/control-plane JSON payloads
)

// BootstrapJoinOptions configures dual-mode cryptographic node enrollment (Mode A zero-touch CSR
// issuance when CertPath/KeyPath are absent on disk, or Mode B pre-issued certificate registration
// when CertPath/KeyPath already exist on disk).
type BootstrapJoinOptions struct {
	JoinAddr        string
	JoinToken       string
	NodeID          string
	ClusterBindAddr string
	AdvertiseAddr   string
	ExecBindAddr    string
	CertPath        string
	KeyPath         string
	CAPath          string
	CRLPath         string
	StatePath       string
	ExtraIPs        []string
	ExtraDNSNames   []string
}

// BootstrapJoinResult describes the completed (or idempotently skipped) node join outcome.
type BootstrapJoinResult struct {
	AlreadyBootstrapped bool                     `json:"already_bootstrapped"`
	Mode                string                   `json:"mode"`
	NodeID              string                   `json:"node_id"`
	ClusterAddr         string                   `json:"cluster_addr"`
	CertSerialHex       string                   `json:"cert_serial_hex,omitempty"`
	SeedAddr            string                   `json:"seed_addr"`
	Peers               []PeerInfo               `json:"peers,omitempty"`
	Policy              protocol.ExecutionPolicy `json:"policy"`
}

// BootstrapJoin enrolls the local node into an existing agent-bridge cluster using a single-use
// Root-CA-pinned join token (`abjt1.<ca_sha256>.<token_id>.<secret>`).
//
// Idempotent Restart Guarantee:
// If StatePath already records `Bootstrapped == true` AND CertPath, KeyPath, CAPath, and CRLPath
// all exist and validate on disk, BootstrapJoin returns `AlreadyBootstrapped: true` immediately
// without contacting JoinAddr or attempting to re-consume the single-use join token.
func BootstrapJoin(ctx context.Context, opts BootstrapJoinOptions) (*BootstrapJoinResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	certPath := strings.TrimSpace(opts.CertPath)
	keyPath := strings.TrimSpace(opts.KeyPath)
	caPath := strings.TrimSpace(opts.CAPath)
	crlPath := strings.TrimSpace(opts.CRLPath)
	if certPath == "" {
		return nil, errors.New("BootstrapJoin: CertPath is required")
	}
	if keyPath == "" {
		return nil, errors.New("BootstrapJoin: KeyPath is required")
	}
	if caPath == "" {
		return nil, errors.New("BootstrapJoin: CAPath is required")
	}
	if crlPath == "" {
		return nil, errors.New("BootstrapJoin: CRLPath is required")
	}

	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)
	caExists := fileExists(caPath)
	crlExists := fileExists(crlPath)

	if certExists != keyExists {
		return nil, fmt.Errorf(
			"BootstrapJoin: partial leaf keypair on disk (cert=%t, key=%t); provide both for pre-issued registration or neither for CSR issuance",
			certExists, keyExists,
		)
	}

	var existingLeafCert *x509.Certificate
	if certExists {
		if loadedLeaf, err := pki.LoadCertificate(certPath); err == nil {
			existingLeafCert = loadedLeaf
		}
	}

	hostname, _ := os.Hostname()
	hostname = strings.TrimSpace(hostname)

	nodeID := strings.TrimSpace(opts.NodeID)
	if nodeID == "" && existingLeafCert != nil {
		nodeID = strings.TrimSpace(existingLeafCert.Subject.CommonName)
	}
	if nodeID == "" {
		nodeID = hostname
	}
	if nodeID == "" {
		nodeID = "node-1"
	}

	statePath := strings.TrimSpace(opts.StatePath)
	if statePath == "" {
		statePath = DefaultStatePath(crlPath, nodeID)
	}

	rawAdvertise := strings.TrimSpace(opts.AdvertiseAddr)
	if rawAdvertise == "" {
		rawAdvertise = strings.TrimSpace(opts.ClusterBindAddr)
	}
	if rawAdvertise == "" {
		rawAdvertise = config.DefaultClusterEndpoint
	}
	clusterAddr, err := normalizeBindOrAdvertiseAddr(rawAdvertise, config.DefaultClusterPort, true)
	if err != nil {
		return nil, fmt.Errorf("BootstrapJoin: invalid cluster bind/advertise address %q: %w", rawAdvertise, err)
	}

	var execAddr string
	if strings.TrimSpace(opts.ExecBindAddr) != "" {
		normExec, execErr := normalizeBindOrAdvertiseAddr(opts.ExecBindAddr, protocol.DefaultPort, true)
		if execErr != nil {
			return nil, fmt.Errorf("BootstrapJoin: invalid exec bind address %q: %w", opts.ExecBindAddr, execErr)
		}
		execAddr = normExec
	}

	// Idempotent service restart short-circuit when a prior join already succeeded and all PKI artifacts exist.
	if certExists && keyExists && caExists && crlExists {
		persisted, stateErr := loadPersistedState(statePath)
		if stateErr == nil && persisted != nil && persisted.Bootstrapped {
			if validRes, ok := validateAlreadyBootstrapped(
				opts.JoinAddr,
				nodeID,
				clusterAddr,
				certPath,
				keyPath,
				caPath,
				crlPath,
				persisted,
			); ok {
				return validRes, nil
			}
		}
	}

	seedHostPort, seedBaseHTTPS, err := config.NormalizeClusterAddr(opts.JoinAddr)
	if err != nil {
		return nil, fmt.Errorf("BootstrapJoin: invalid --join address: %w", err)
	}

	parsedToken, err := ParseJoinToken(opts.JoinToken)
	if err != nil {
		return nil, err
	}

	// If CAPath already exists on disk, fail fast before dialing if its SHA-256 fingerprint mismatches the token pin.
	var diskCACert *x509.Certificate
	var diskCAPool *x509.CertPool
	if caExists {
		loadedCA, loadedPool, caErr := pki.LoadCACertPool(caPath)
		if caErr != nil {
			return nil, fmt.Errorf("BootstrapJoin: failed to load existing CA certificate %q: %w", caPath, caErr)
		}
		actualFP := pki.CertFingerprintSHA256(loadedCA)
		if subtle.ConstantTimeCompare([]byte(actualFP), []byte(parsedToken.CAFingerprint)) != 1 {
			return nil, fmt.Errorf(
				"BootstrapJoin: existing CA certificate %q fingerprint (%s) does not match join token CA pin (%s)",
				caPath, actualFP, parsedToken.CAFingerprint,
			)
		}
		diskCACert = loadedCA
		diskCAPool = loadedPool
	}

	var (
		mode           string
		joinReq        JoinRequest
		generatedKey   *ecdsa.PrivateKey
		generatedKeyPM []byte
		preIssuedCert  *x509.Certificate
		preIssuedTLS   *tls.Certificate
	)

	if !certExists {
		// Mode A: Zero-Touch CSR Certificate Issuance (private key generated locally and never transmitted).
		mode = "csr-issued"
		csrIPs, csrDNS := collectNodeSANs(
			opts.ClusterBindAddr,
			opts.AdvertiseAddr,
			opts.ExecBindAddr,
			hostname,
			opts.ExtraIPs,
			opts.ExtraDNSNames,
		)
		privKey, keyPEM, csrPEM, csrErr := pki.GenerateKeyAndCSR(nodeID, csrIPs, csrDNS)
		if csrErr != nil {
			return nil, fmt.Errorf("BootstrapJoin: failed to generate CSR: %w", csrErr)
		}
		generatedKey = privKey
		generatedKeyPM = keyPEM

		joinReq = JoinRequest{
			Token:       parsedToken.Raw,
			NodeID:      nodeID,
			ClusterAddr: clusterAddr,
			ExecAddr:    execAddr,
			Hostname:    hostname,
			CSRPEM:      string(csrPEM),
		}
	} else {
		// Mode B: Pre-Issued Certificate Registration (air-gapped / offline Root CA workflow).
		mode = "pre-issued"
		tlsPair, pairErr := tls.LoadX509KeyPair(certPath, keyPath)
		if pairErr != nil {
			return nil, fmt.Errorf("BootstrapJoin: failed to load existing certificate/key pair: %w", pairErr)
		}
		leafCert, parseErr := x509.ParseCertificate(tlsPair.Certificate[0])
		if parseErr != nil {
			return nil, fmt.Errorf("BootstrapJoin: failed to parse existing leaf certificate %q: %w", certPath, parseErr)
		}
		leafKey, keyErr := pki.LoadPrivateKey(keyPath)
		if keyErr != nil {
			return nil, fmt.Errorf("BootstrapJoin: failed to load existing private key %q: %w", keyPath, keyErr)
		}
		rawCertPEM, readErr := os.ReadFile(certPath)
		if readErr != nil {
			return nil, fmt.Errorf("BootstrapJoin: failed to read existing certificate %q: %w", certPath, readErr)
		}

		popSig, popErr := signJoinPoP(leafKey, parsedToken.TokenID, nodeID, clusterAddr)
		if popErr != nil {
			return nil, fmt.Errorf("BootstrapJoin: failed to sign join proof-of-possession: %w", popErr)
		}

		preIssuedCert = leafCert
		preIssuedTLS = &tlsPair
		joinReq = JoinRequest{
			Token:              parsedToken.Raw,
			NodeID:             nodeID,
			ClusterAddr:        clusterAddr,
			ExecAddr:           execAddr,
			Hostname:           hostname,
			ExistingCertPEM:    string(rawCertPEM),
			PoPSignatureBase64: popSig,
		}
	}

	tlsCfg := buildBootstrapClientTLSConfig(parsedToken.CAFingerprint, diskCACert, diskCAPool, preIssuedTLS)
	transport := &http.Transport{
		TLSClientConfig:     tlsCfg,
		ForceAttemptHTTP2:   true,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 10 * time.Second,
	}
	defer transport.CloseIdleConnections()

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   bootstrapJoinHTTPTimeout,
	}

	bodyBytes, err := json.Marshal(joinReq)
	if err != nil {
		return nil, fmt.Errorf("BootstrapJoin: failed to encode JoinRequest: %w", err)
	}

	reqCtx, cancel := context.WithTimeout(ctx, bootstrapJoinHTTPTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(reqCtx, http.MethodPost, seedBaseHTTPS+pathClusterJoin, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("BootstrapJoin: failed to construct HTTP request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("BootstrapJoin: join handshake to %s failed: %w", seedHostPort, err)
	}
	defer httpResp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, maxJoinBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("BootstrapJoin: failed reading join response from %s: %w", seedHostPort, err)
	}
	if httpResp.StatusCode != http.StatusOK {
		return nil, decodeClusterHTTPError(httpResp.StatusCode, respBytes, "BootstrapJoin rejected by seed peer")
	}

	var joinResp JoinResponse
	if err := json.Unmarshal(respBytes, &joinResp); err != nil {
		return nil, fmt.Errorf("BootstrapJoin: malformed JoinResponse JSON from %s: %w", seedHostPort, err)
	}

	// Cryptographically verify returned CACertPEM against the token's pinned SHA-256 fingerprint.
	caCert, caPool, err := parseCACertAndPoolFromPEM([]byte(joinResp.CACertPEM))
	if err != nil {
		return nil, fmt.Errorf("BootstrapJoin: invalid Root CA certificate in JoinResponse: %w", err)
	}
	returnedCAFP := pki.CertFingerprintSHA256(caCert)
	if subtle.ConstantTimeCompare([]byte(returnedCAFP), []byte(parsedToken.CAFingerprint)) != 1 {
		return nil, fmt.Errorf(
			"BootstrapJoin: JoinResponse Root CA fingerprint (%s) does not match token pin (%s)",
			returnedCAFP, parsedToken.CAFingerprint,
		)
	}

	// Verify returned CRLPEM against pinned Root CA before writing anything to disk.
	parsedCRL, err := pki.ParseAndVerifyCRL([]byte(joinResp.CRLPEM), caCert)
	if err != nil {
		return nil, fmt.Errorf("BootstrapJoin: invalid CRL in JoinResponse: %w", err)
	}
	now := time.Now().UTC()
	if parsedCRL.NextUpdate.IsZero() || now.After(parsedCRL.NextUpdate) {
		return nil, errors.New("BootstrapJoin: JoinResponse CRL is expired or missing nextUpdate")
	}

	var finalCert *x509.Certificate
	if mode == "csr-issued" {
		if strings.TrimSpace(joinResp.IssuedCertPEM) == "" {
			return nil, errors.New("BootstrapJoin: seed peer returned empty issued_cert_pem for CSR join")
		}
		issuedLeaf, certErr := parseSingleCertificatePEM([]byte(joinResp.IssuedCertPEM))
		if certErr != nil {
			return nil, fmt.Errorf("BootstrapJoin: invalid issued certificate in JoinResponse: %w", certErr)
		}
		if _, verifyErr := pki.VerifyPeerCertDualEKU([][]byte{issuedLeaf.Raw}, caPool, nil); verifyErr != nil {
			return nil, fmt.Errorf("BootstrapJoin: issued certificate failed CA chain verification: %w", verifyErr)
		}
		issuedPub, ok := issuedLeaf.PublicKey.(*ecdsa.PublicKey)
		if !ok || !generatedKey.PublicKey.Equal(issuedPub) {
			return nil, errors.New("BootstrapJoin: issued certificate public key does not match locally generated private key")
		}
		if isSerialInCRL(parsedCRL, issuedLeaf.SerialNumber) {
			return nil, errors.New("BootstrapJoin: issued certificate is already revoked in returned CRL")
		}
		finalCert = issuedLeaf
	} else {
		if _, verifyErr := pki.VerifyPeerCertDualEKU([][]byte{preIssuedCert.Raw}, caPool, nil); verifyErr != nil {
			return nil, fmt.Errorf("BootstrapJoin: pre-issued certificate does not chain to cluster Root CA: %w", verifyErr)
		}
		if isSerialInCRL(parsedCRL, preIssuedCert.SerialNumber) {
			return nil, fmt.Errorf("BootstrapJoin: pre-issued certificate [%s] is revoked in cluster CRL", pki.FormatSerialHex(preIssuedCert.SerialNumber))
		}
		finalCert = preIssuedCert
	}

	var effectivePolicy protocol.ExecutionPolicy
	if joinResp.SignedPolicy != nil {
		if err := joinResp.SignedPolicy.Verify(caCert, caPool, nil); err != nil {
			return nil, fmt.Errorf("BootstrapJoin: JoinResponse SignedPolicy failed signature verification: %w", err)
		}
		if signerCert, sigCertErr := parseSingleCertificatePEM([]byte(joinResp.SignedPolicy.SignerCertPEM)); sigCertErr == nil {
			if !signerCert.IsCA && isSerialInCRL(parsedCRL, signerCert.SerialNumber) {
				return nil, errors.New("BootstrapJoin: JoinResponse SignedPolicy was signed by a revoked certificate")
			}
		}
		effectivePolicy = joinResp.SignedPolicy.Policy
	}

	// Atomically persist PKI artifacts and initial cluster state.
	if mode == "csr-issued" {
		if err := pki.WriteFileAtomic(keyPath, generatedKeyPM, 0o600); err != nil {
			return nil, fmt.Errorf("BootstrapJoin: failed to write node private key %q: %w", keyPath, err)
		}
		if err := pki.WriteFileAtomic(certPath, []byte(joinResp.IssuedCertPEM), 0o644); err != nil {
			return nil, fmt.Errorf("BootstrapJoin: failed to write issued certificate %q: %w", certPath, err)
		}
		if err := pki.WriteFileAtomic(caPath, []byte(joinResp.CACertPEM), 0o644); err != nil {
			return nil, fmt.Errorf("BootstrapJoin: failed to write Root CA certificate %q: %w", caPath, err)
		}
	} else if !caExists {
		if err := pki.WriteFileAtomic(caPath, []byte(joinResp.CACertPEM), 0o644); err != nil {
			return nil, fmt.Errorf("BootstrapJoin: failed to write Root CA certificate %q: %w", caPath, err)
		}
	}

	shouldWriteCRL := true
	if crlExists {
		if existingCRL, loadErr := pki.LoadCRL(crlPath, caCert); loadErr == nil &&
			existingCRL.Number != nil && parsedCRL.Number != nil &&
			parsedCRL.Number.Cmp(existingCRL.Number) <= 0 {
			shouldWriteCRL = false
		}
	}
	if shouldWriteCRL {
		if err := pki.WriteFileAtomic(crlPath, []byte(joinResp.CRLPEM), 0o644); err != nil {
			return nil, fmt.Errorf("BootstrapJoin: failed to write CRL %q: %w", crlPath, err)
		}
	}

	persistedPeers := make([]PeerInfo, 0, len(joinResp.Peers))
	var selfJoinedAt int64
	for _, p := range joinResp.Peers {
		cp := p.Clone()
		cp.IsSelf = false
		cp.IsLeader = false
		if cp.NodeID == nodeID && cp.JoinedAtUnix > 0 {
			selfJoinedAt = cp.JoinedAtUnix
		}
		persistedPeers = append(persistedPeers, cp)
	}
	if selfJoinedAt <= 0 {
		selfJoinedAt = now.Unix()
	}

	initialState := &persistedClusterState{
		SchemaVersion: currentStateSchemaVersion,
		Bootstrapped:  true,
		NodeID:        nodeID,
		Incarnation:   1,
		JoinedAtUnix:  selfJoinedAt,
		SignedPolicy:  joinResp.SignedPolicy.Clone(),
		Peers:         persistedPeers,
	}
	if err := savePersistedState(statePath, initialState); err != nil {
		return nil, err
	}

	serialHex := pki.FormatSerialHex(finalCert.SerialNumber)
	return &BootstrapJoinResult{
		AlreadyBootstrapped: false,
		Mode:                mode,
		NodeID:              nodeID,
		ClusterAddr:         clusterAddr,
		CertSerialHex:       serialHex,
		SeedAddr:            seedHostPort,
		Peers:               joinResp.Peers,
		Policy:              effectivePolicy,
	}, nil
}

func validateAlreadyBootstrapped(
	rawJoinAddr string,
	nodeID string,
	clusterAddr string,
	certPath string,
	keyPath string,
	caPath string,
	crlPath string,
	persisted *persistedClusterState,
) (*BootstrapJoinResult, bool) {
	tlsPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil || len(tlsPair.Certificate) == 0 {
		return nil, false
	}
	leafCert, err := x509.ParseCertificate(tlsPair.Certificate[0])
	if err != nil {
		return nil, false
	}
	caCert, caPool, err := pki.LoadCACertPool(caPath)
	if err != nil {
		return nil, false
	}
	loadedCRL, err := pki.LoadCRL(crlPath, caCert)
	if err != nil {
		return nil, false
	}
	if isSerialInCRL(loadedCRL, leafCert.SerialNumber) {
		return nil, false
	}
	if !hasExtKeyUsage(leafCert, x509.ExtKeyUsageServerAuth) {
		return nil, false
	}
	if _, err := pki.VerifyPeerCertDualEKU([][]byte{leafCert.Raw}, caPool, nil); err != nil {
		return nil, false
	}

	seedAddr := strings.TrimSpace(rawJoinAddr)
	if normSeed, _, normErr := config.NormalizeClusterAddr(rawJoinAddr); normErr == nil {
		seedAddr = normSeed
	}
	var pol protocol.ExecutionPolicy
	if persisted.SignedPolicy != nil {
		if verifyErr := persisted.SignedPolicy.Verify(caCert, caPool, nil); verifyErr == nil {
			signerRevoked := false
			if signerCert, sigCertErr := parseSingleCertificatePEM([]byte(persisted.SignedPolicy.SignerCertPEM)); sigCertErr == nil {
				if !signerCert.IsCA && isSerialInCRL(loadedCRL, signerCert.SerialNumber) {
					signerRevoked = true
				}
			}
			if !signerRevoked {
				pol = persisted.SignedPolicy.Policy
			}
		}
	}

	return &BootstrapJoinResult{
		AlreadyBootstrapped: true,
		Mode:                "already-bootstrapped",
		NodeID:              nodeID,
		ClusterAddr:         clusterAddr,
		CertSerialHex:       pki.FormatSerialHex(leafCert.SerialNumber),
		SeedAddr:            seedAddr,
		Peers:               append([]PeerInfo(nil), persisted.Peers...),
		Policy:              pol,
	}, true
}

func buildBootstrapClientTLSConfig(
	expectedCAFingerprint string,
	diskCACert *x509.Certificate,
	diskCAPool *x509.CertPool,
	clientCert *tls.Certificate,
) *tls.Config {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Strictly paired with cryptographic CA-pin + chain verification in VerifyPeerCertificate below.
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return errors.New("TLS Handshake Rejected: seed peer presented no certificates")
			}

			leaf, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("TLS Handshake Rejected: malformed seed leaf certificate: %w", err)
			}
			if leaf.IsCA {
				return errors.New("TLS Handshake Rejected: seed leaf certificate cannot be a CA")
			}
			if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
				return errors.New("TLS Handshake Rejected: seed certificate lacks ServerAuth extended key usage")
			}

			intermediates := x509.NewCertPool()
			var pinnedPool *x509.CertPool
			if diskCAPool != nil && diskCACert != nil {
				actualFP := pki.CertFingerprintSHA256(diskCACert)
				if subtle.ConstantTimeCompare([]byte(actualFP), []byte(expectedCAFingerprint)) != 1 {
					return errors.New("TLS Handshake Rejected: local Root CA fingerprint does not match join token")
				}
				pinnedPool = diskCAPool
				for _, rawIC := range rawCerts[1:] {
					if ic, parseErr := x509.ParseCertificate(rawIC); parseErr == nil && !ic.IsCA {
						intermediates.AddCert(ic)
					}
				}
			} else {
				var matchedCA *x509.Certificate
				now := time.Now().UTC()
				for _, rawCert := range rawCerts[1:] {
					candidate, parseErr := x509.ParseCertificate(rawCert)
					if parseErr != nil {
						return fmt.Errorf("TLS Handshake Rejected: malformed certificate in seed chain: %w", parseErr)
					}
					if candidate.IsCA {
						candFP := pki.CertFingerprintSHA256(candidate)
						if subtle.ConstantTimeCompare([]byte(candFP), []byte(expectedCAFingerprint)) == 1 {
							if err := candidate.CheckSignatureFrom(candidate); err != nil {
								return fmt.Errorf("TLS Handshake Rejected: pinned Root CA self-signature invalid: %w", err)
							}
							if now.Before(candidate.NotBefore) || now.After(candidate.NotAfter) {
								return errors.New("TLS Handshake Rejected: pinned Root CA certificate is outside validity window")
							}
							matchedCA = candidate
						}
					} else {
						intermediates.AddCert(candidate)
					}
				}
				if matchedCA == nil {
					return errors.New("TLS Handshake Rejected: seed peer Root CA fingerprint does not match join token")
				}
				pinnedPool = x509.NewCertPool()
				pinnedPool.AddCert(matchedCA)
			}

			if _, err := leaf.Verify(x509.VerifyOptions{
				Roots:         pinnedPool,
				Intermediates: intermediates,
				KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			}); err != nil {
				return fmt.Errorf("TLS Handshake Rejected: seed certificate chain verification failed: %w", err)
			}
			return nil
		},
	}

	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	return cfg
}

// handleJoin processes POST /cluster/v1/join requests from enrolling nodes (Mode A CSR or Mode B pre-issued cert).
func (e *Engine) handleJoin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if e.closed.Load() {
		writeJSONError(w, http.StatusServiceUnavailable, "cluster engine is shutting down")
		return
	}

	var req JoinRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid JoinRequest JSON: %v", err))
		return
	}

	observedRemoteIP := extractRemoteIP(r.RemoteAddr)
	resp, statusCode, err := e.processJoinRequest(r.Context(), req, observedRemoteIP, nil, true)
	if err != nil {
		writeJSONError(w, statusCode, err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, resp)
}

// handleSignJoin processes peer-forwarded CSR join requests over authenticated mTLS 1.3 on an authority node holding ca.key.
func (e *Engine) handleSignJoin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if e.closed.Load() {
		writeJSONError(w, http.StatusServiceUnavailable, "cluster engine is shutting down")
		return
	}

	var fwd signJoinForwardRequest
	if err := decodeJSONBody(w, r, &fwd); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid forwarded join payload: %v", err))
		return
	}

	if !e.hasCAKey || e.caKey == nil {
		writeJSONError(w, http.StatusBadRequest, "this node does not hold the Root CA private key (--ca-key)")
		return
	}

	resp, statusCode, err := e.processJoinRequest(r.Context(), fwd.JoinRequest, fwd.ObservedRemoteIP, fwd.TokenRecord, false)
	if err != nil {
		writeJSONError(w, statusCode, err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, resp)
}

func (e *Engine) processJoinRequest(
	ctx context.Context,
	req JoinRequest,
	observedRemoteIP string,
	forwardedToken *TokenRecord,
	allowForward bool,
) (*JoinResponse, int, error) {
	e.joinMu.Lock()
	defer e.joinMu.Unlock()

	status := e.Status()
	if status.Topology == TopologyMultiNodeQuorum && !status.HasQuorum {
		return nil, http.StatusServiceUnavailable, ErrNoQuorum
	}

	parsedTok, err := ParseJoinToken(req.Token)
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}

	expectedCAFP := pki.CertFingerprintSHA256(e.caCert)
	if subtle.ConstantTimeCompare([]byte(parsedTok.CAFingerprint), []byte(expectedCAFP)) != 1 {
		return nil, http.StatusUnauthorized, errors.New("join token Root CA fingerprint does not match cluster Root CA")
	}

	nodeID := strings.TrimSpace(req.NodeID)
	if nodeID == "" {
		return nil, http.StatusBadRequest, errors.New("join request node_id cannot be empty")
	}
	if nodeID == e.nodeID {
		return nil, http.StatusConflict, fmt.Errorf("cannot join cluster with node_id %q matching target seed node", nodeID)
	}

	normClusterAddr, err := normalizeBindOrAdvertiseAddr(req.ClusterAddr, config.DefaultClusterPort, true)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid join cluster_addr %q: %w", req.ClusterAddr, err)
	}
	req.ClusterAddr = normClusterAddr

	var normExecAddr string
	if strings.TrimSpace(req.ExecAddr) != "" {
		normExecAddr, err = normalizeBindOrAdvertiseAddr(req.ExecAddr, protocol.DefaultPort, true)
		if err != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("invalid join exec_addr %q: %w", req.ExecAddr, err)
		}
	}
	req.ExecAddr = normExecAddr
	req.NodeID = nodeID
	req.Hostname = strings.TrimSpace(req.Hostname)

	// Merge forwarded TokenRecord if delegated by a peer that minted the token locally.
	if forwardedToken != nil && forwardedToken.IsValidStructure() {
		e.mu.Lock()
		if cur, exists := e.tokens[forwardedToken.TokenID]; exists {
			if merged, changed := mergeTokenRecord(*cur, *forwardedToken); changed {
				*cur = merged
			}
		} else {
			cp := forwardedToken.Clone()
			e.tokens[cp.TokenID] = &cp
		}
		e.mu.Unlock()
	}

	// If token is unknown locally, perform an immediate pull across peers in case the token was minted milliseconds ago on another node.
	if !e.hasTokenID(parsedTok.TokenID) {
		e.pullFromAllPeers(ctx)
	}

	now := time.Now().UTC()
	tokSnapshot, statusCode, tokErr := e.validateJoinTokenCandidate(parsedTok, nodeID, now)
	if tokErr != nil {
		return nil, statusCode, tokErr
	}

	hasCSR := strings.TrimSpace(req.CSRPEM) != ""
	hasExisting := strings.TrimSpace(req.ExistingCertPEM) != ""
	if hasCSR == hasExisting {
		return nil, http.StatusBadRequest, errors.New("join request must supply exactly one of csr_pem or existing_cert_pem")
	}

	if hasCSR && (!e.hasCAKey || e.caKey == nil) {
		if !allowForward {
			return nil, http.StatusServiceUnavailable, errors.New(
				"cannot sign CSR on join: authority node lacks --ca-key; pass --ca-key on an authority node or pre-issue server.crt/server.key with 'agent-bridge ca issue'",
			)
		}
		return e.forwardJoinToAuthorityPeer(ctx, req, observedRemoteIP, &tokSnapshot)
	}

	var (
		issuedCertPEM string
		admittedCert  *x509.Certificate
	)

	if hasCSR {
		var extraIPs []string
		if observedRemoteIP != "" {
			extraIPs = append(extraIPs, observedRemoteIP)
		}
		if host, _, splitErr := net.SplitHostPort(normClusterAddr); splitErr == nil {
			if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
				extraIPs = append(extraIPs, ip.String())
			}
		}
		if normExecAddr != "" {
			if host, _, splitErr := net.SplitHostPort(normExecAddr); splitErr == nil {
				if ip := net.ParseIP(host); ip != nil && !ip.IsUnspecified() {
					extraIPs = append(extraIPs, ip.String())
				}
			}
		}

		var extraDNS []string
		if req.Hostname != "" && net.ParseIP(req.Hostname) == nil {
			extraDNS = append(extraDNS, req.Hostname)
		}

		signedPEM, signedCert, signErr := pki.SignNodeCSR(
			[]byte(req.CSRPEM),
			e.caCert,
			e.caKey,
			pki.SignCSROptions{
				ExtraIPs:           extraIPs,
				ExtraDNSNames:      extraDNS,
				ServerAndClientEKU: true,
			},
		)
		if signErr != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("CSR signing failed: %w", signErr)
		}
		issuedCertPEM = string(signedPEM)
		admittedCert = signedCert
	} else {
		existingCert, parseErr := parseSingleCertificatePEM([]byte(req.ExistingCertPEM))
		if parseErr != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("invalid existing_cert_pem: %w", parseErr)
		}
		if _, verifyErr := pki.VerifyPeerCertDualEKU([][]byte{existingCert.Raw}, e.caPool, e.crlWatcher); verifyErr != nil {
			return nil, http.StatusForbidden, fmt.Errorf("pre-issued certificate rejected: %w", verifyErr)
		}
		if !slices.Contains(existingCert.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
			return nil, http.StatusBadRequest, errors.New("pre-issued node certificate must include ServerAuth extended key usage")
		}
		if err := verifyJoinPoP(existingCert, parsedTok.TokenID, nodeID, normClusterAddr, req.PoPSignatureBase64); err != nil {
			return nil, http.StatusUnauthorized, fmt.Errorf("join proof-of-possession verification failed: %w", err)
		}
		admittedCert = existingCert
	}

	serialHex := pki.FormatSerialHex(admittedCert.SerialNumber)

	// Atomically consume the single-use join token and admit the peer into cluster state.
	var persistSnap *persistedClusterState
	var persistSeq uint64
	var signedPolCopy *SignedPolicyEnvelope
	var peersOut []PeerInfo

	e.mu.Lock()
	rec, ok := e.tokens[parsedTok.TokenID]
	if !ok {
		e.mu.Unlock()
		return nil, http.StatusUnauthorized, errors.New("join token not found")
	}
	if rec.Used {
		e.mu.Unlock()
		return nil, http.StatusUnauthorized, errors.New("join token has already been used")
	}
	if now.Unix() > rec.ExpiresAtUnix {
		e.mu.Unlock()
		return nil, http.StatusUnauthorized, errors.New("join token has expired")
	}
	rec.Used = true
	rec.UsedByNodeID = nodeID
	rec.UsedAtUnix = now.Unix()

	crlNumStr := e.currentCRLNumberString()
	polVer := uint64(0)
	if e.signedPolicy != nil {
		polVer = e.signedPolicy.Policy.Version
		signedPolCopy = e.signedPolicy.Clone()
	}

	incarnation := uint64(1)
	joinedAt := now.Unix()
	if prev, exists := e.peers[nodeID]; exists {
		incarnation = prev.Incarnation + 1
		if prev.CertSerialHex != "" && !strings.EqualFold(prev.CertSerialHex, serialHex) {
			if prev.JoinedAtUnix >= joinedAt {
				joinedAt = prev.JoinedAtUnix + 1
			}
		} else if prev.JoinedAtUnix > 0 {
			joinedAt = prev.JoinedAtUnix
		}
	}

	e.peers[nodeID] = &PeerInfo{
		NodeID:        nodeID,
		ClusterAddr:   normClusterAddr,
		ExecAddr:      normExecAddr,
		Hostname:      req.Hostname,
		CertSerialHex: serialHex,
		HasCAKey:      false,
		Incarnation:   incarnation,
		State:         PeerAlive,
		CRLNumber:     crlNumStr,
		PolicyVersion: polVer,
		JoinedAtUnix:  joinedAt,
		LastSeenUnix:  now.Unix(),
	}
	e.lastContact[nodeID] = now

	e.refreshSelfLocked(now)
	eval := EvaluateQuorum(e.nodeID, e.peersSliceLocked())
	peersOut = eval.Peers
	persistSnap, persistSeq = e.buildPersistedSnapshotLocked()
	e.mu.Unlock()

	if err := e.writePersistedSnapshot(persistSnap, persistSeq); err != nil {
		e.logf("warning: failed persisting cluster state after join of %s: %v", nodeID, err)
	}

	// Immediately broadcast token consumption + new peer admission to all existing peers asynchronously.
	e.triggerAsyncBroadcast(false)

	crlPEMBytes := e.crlWatcher.CRLPEM()
	return &JoinResponse{
		NodeID:        nodeID,
		CertSerialHex: serialHex,
		IssuedCertPEM: issuedCertPEM,
		CACertPEM:     e.caCertPEM,
		CRLPEM:        string(crlPEMBytes),
		SignedPolicy:  signedPolCopy,
		Peers:         peersOut,
	}, http.StatusOK, nil
}

func (e *Engine) forwardJoinToAuthorityPeer(
	ctx context.Context,
	req JoinRequest,
	observedRemoteIP string,
	tokSnapshot *TokenRecord,
) (*JoinResponse, int, error) {
	candidates := e.authorityPeersForCSR()
	if len(candidates) == 0 {
		return nil, http.StatusBadRequest, errors.New(
			"cannot sign CSR on join: no active cluster node holds Root CA private key (--ca-key); pass --ca-key on an authority node or pre-issue server.crt and server.key with 'agent-bridge ca issue'",
		)
	}

	fwdPayload := signJoinForwardRequest{
		JoinRequest:      req,
		ObservedRemoteIP: observedRemoteIP,
		TokenRecord:      tokSnapshot,
	}
	encoded, err := json.Marshal(fwdPayload)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed encoding sign-join request: %w", err)
	}

	var lastErr error
	for _, peer := range candidates {
		if !hasDialablePort(peer.ClusterAddr) {
			continue
		}
		_, baseHTTPS, normErr := config.NormalizeClusterAddr(peer.ClusterAddr)
		if normErr != nil {
			lastErr = normErr
			continue
		}

		reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		httpReq, reqErr := http.NewRequestWithContext(reqCtx, http.MethodPost, baseHTTPS+pathClusterSignJoin, bytes.NewReader(encoded))
		if reqErr != nil {
			cancel()
			lastErr = reqErr
			continue
		}
		httpReq.Header.Set("Content-Type", "application/json")

		httpResp, doErr := e.peerHTTPClient.Do(httpReq)
		if doErr != nil {
			cancel()
			lastErr = doErr
			continue
		}

		respBytes, readErr := io.ReadAll(io.LimitReader(httpResp.Body, maxJoinBodyBytes))
		_ = httpResp.Body.Close()
		cancel()
		if readErr != nil {
			lastErr = readErr
			continue
		}

		if httpResp.StatusCode != http.StatusOK {
			apiErr := decodeClusterHTTPError(httpResp.StatusCode, respBytes, "authority peer rejected CSR join")
			if httpResp.StatusCode >= 400 && httpResp.StatusCode < 500 {
				return nil, httpResp.StatusCode, apiErr
			}
			lastErr = apiErr
			continue
		}

		var joinResp JoinResponse
		if unmarshalErr := json.Unmarshal(respBytes, &joinResp); unmarshalErr != nil {
			lastErr = unmarshalErr
			continue
		}

		// Synchronously mark the token consumed and merge the newly admitted peer roster locally
		// before returning JoinResponse so immediate replay on this node is impossible.
		now := time.Now().UTC()
		var persistSnap *persistedClusterState
		var persistSeq uint64
		var mergedPeers []PeerInfo

		e.mu.Lock()
		if rec, ok := e.tokens[tokSnapshot.TokenID]; ok {
			rec.Used = true
			rec.UsedByNodeID = req.NodeID
			rec.UsedAtUnix = now.Unix()
		} else {
			cp := tokSnapshot.Clone()
			cp.Used = true
			cp.UsedByNodeID = req.NodeID
			cp.UsedAtUnix = now.Unix()
			e.tokens[cp.TokenID] = &cp
		}

		for _, p := range joinResp.Peers {
			if p.NodeID == "" || p.NodeID == e.nodeID {
				continue
			}
			cp := p.Clone()
			cp.IsSelf = false
			cp.IsLeader = false
			e.peers[cp.NodeID] = &cp
			if cp.State == PeerAlive {
				e.lastContact[cp.NodeID] = now
			}
		}
		e.lastContact[peer.NodeID] = now
		if authPeer, ok := e.peers[peer.NodeID]; ok {
			authPeer.State = PeerAlive
			authPeer.LastSeenUnix = now.Unix()
		}

		e.refreshSelfLocked(now)
		eval := EvaluateQuorum(e.nodeID, e.peersSliceLocked())
		mergedPeers = eval.Peers
		persistSnap, persistSeq = e.buildPersistedSnapshotLocked()
		e.mu.Unlock()

		_ = e.writePersistedSnapshot(persistSnap, persistSeq)
		joinResp.Peers = mergedPeers
		e.triggerAsyncBroadcast(false)
		return &joinResp, http.StatusOK, nil
	}

	if lastErr == nil {
		lastErr = errors.New("no reachable authority node with --ca-key")
	}
	return nil, http.StatusBadGateway, fmt.Errorf("failed forwarding CSR join to authority peer: %w", lastErr)
}

func (e *Engine) hasTokenID(tokenID string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.tokens[tokenID]
	return ok
}

func (e *Engine) validateJoinTokenCandidate(
	parsed *ParsedJoinToken,
	joiningNodeID string,
	now time.Time,
) (TokenRecord, int, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	rec, exists := e.tokens[parsed.TokenID]
	if !exists {
		return TokenRecord{}, http.StatusUnauthorized, errors.New("unknown or invalid join token")
	}
	if !rec.VerifySecret(parsed.SecretHex) {
		return TokenRecord{}, http.StatusUnauthorized, errors.New("invalid join token secret")
	}
	if rec.Used {
		return TokenRecord{}, http.StatusUnauthorized, errors.New("join token has already been used")
	}
	if now.Unix() > rec.ExpiresAtUnix {
		return TokenRecord{}, http.StatusUnauthorized, errors.New("join token has expired")
	}
	if rec.BoundNodeID != "" && rec.BoundNodeID != joiningNodeID {
		return TokenRecord{}, http.StatusForbidden, fmt.Errorf(
			"join token is bound to node %q, cannot enroll %q",
			rec.BoundNodeID, joiningNodeID,
		)
	}
	return rec.Clone(), http.StatusOK, nil
}

func (e *Engine) authorityPeersForCSR() []PeerInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var aliveAuth []PeerInfo
	var fallbackAuth []PeerInfo
	for _, p := range e.peers {
		if p.NodeID == e.nodeID || !p.HasCAKey {
			continue
		}
		if e.isPeerSerialRevoked(p.CertSerialHex) {
			continue
		}
		if p.State == PeerAlive {
			aliveAuth = append(aliveAuth, p.Clone())
		} else if p.State == PeerSuspect {
			fallbackAuth = append(fallbackAuth, p.Clone())
		}
	}
	slices.SortFunc(aliveAuth, CompareLeaderPriority)
	slices.SortFunc(fallbackAuth, CompareLeaderPriority)
	return append(aliveAuth, fallbackAuth...)
}

func signJoinPoP(priv *ecdsa.PrivateKey, tokenID, nodeID, clusterAddr string) (string, error) {
	if priv == nil {
		return "", errors.New("private key is nil")
	}
	msg := joinPoPDomainPrefix + strings.ToLower(strings.TrimSpace(tokenID)) + ":" + strings.TrimSpace(nodeID) + ":" + strings.TrimSpace(clusterAddr)
	digest := sha256.Sum256([]byte(msg))
	sigASN1, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sigASN1), nil
}

func verifyJoinPoP(cert *x509.Certificate, tokenID, nodeID, clusterAddr, sigBase64 string) error {
	if cert == nil {
		return errors.New("certificate is nil")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return errors.New("certificate does not hold an ECDSA P-256 public key")
	}
	if strings.TrimSpace(sigBase64) == "" {
		return errors.New("missing pop_signature_base64")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigBase64))
	if err != nil {
		return fmt.Errorf("malformed base64 PoP signature: %w", err)
	}
	msg := joinPoPDomainPrefix + strings.ToLower(strings.TrimSpace(tokenID)) + ":" + strings.TrimSpace(nodeID) + ":" + strings.TrimSpace(clusterAddr)
	digest := sha256.Sum256([]byte(msg))
	if !ecdsa.VerifyASN1(pub, digest[:], sigBytes) {
		return errors.New("ECDSA proof-of-possession signature mismatch")
	}
	return nil
}

func collectNodeSANs(
	clusterBindAddr string,
	advertiseAddr string,
	execBindAddr string,
	hostname string,
	extraIPs []string,
	extraDNS []string,
) (ips []string, dnsNames []string) {
	ipSeen := make(map[string]struct{})
	dnsSeen := make(map[string]struct{})

	addIP := func(raw string) {
		parsed := net.ParseIP(strings.TrimSpace(raw))
		if parsed == nil || parsed.IsUnspecified() {
			return
		}
		if ip4 := parsed.To4(); ip4 != nil {
			parsed = ip4
		}
		s := parsed.String()
		if _, exists := ipSeen[s]; !exists {
			ipSeen[s] = struct{}{}
			ips = append(ips, s)
		}
	}

	addDNS := func(raw string) {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || net.ParseIP(trimmed) != nil {
			return
		}
		lower := strings.ToLower(trimmed)
		if _, exists := dnsSeen[lower]; !exists {
			dnsSeen[lower] = struct{}{}
			dnsNames = append(dnsNames, trimmed)
		}
	}

	addHostFromEndpoint := func(rawEp string) {
		trimmed := strings.TrimSpace(rawEp)
		if trimmed == "" {
			return
		}
		if idx := strings.Index(trimmed, "://"); idx != -1 {
			trimmed = trimmed[idx+3:]
		}
		if slash := strings.IndexByte(trimmed, '/'); slash != -1 {
			trimmed = trimmed[:slash]
		}
		if host, _, err := net.SplitHostPort(trimmed); err == nil {
			if ip := net.ParseIP(host); ip != nil {
				addIP(host)
			} else {
				addDNS(host)
			}
			return
		}
		trimmedUnbracket := strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]")
		if ip := net.ParseIP(trimmedUnbracket); ip != nil {
			addIP(trimmedUnbracket)
		} else {
			addDNS(trimmedUnbracket)
		}
	}

	// Include loopback SANs so local loopback administration (127.0.0.1:8444) always validates cleanly.
	addIP("127.0.0.1")
	addDNS("localhost")

	addHostFromEndpoint(clusterBindAddr)
	addHostFromEndpoint(advertiseAddr)
	addHostFromEndpoint(execBindAddr)
	if hostname != "" {
		if ip := net.ParseIP(hostname); ip != nil {
			addIP(hostname)
		} else {
			addDNS(hostname)
		}
	}
	for _, raw := range extraIPs {
		for _, tok := range strings.Split(raw, ",") {
			addIP(tok)
		}
	}
	for _, raw := range extraDNS {
		for _, tok := range strings.Split(raw, ",") {
			addDNS(tok)
		}
	}

	return ips, dnsNames
}

func normalizeBindOrAdvertiseAddr(raw string, defaultPort int, allowZeroPort bool) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", errors.New("address cannot be empty")
	}
	working := trimmed
	if idx := strings.Index(working, "://"); idx != -1 {
		scheme := strings.ToLower(strings.TrimSpace(working[:idx]))
		if scheme != "https" && scheme != "wss" {
			return "", fmt.Errorf("unsupported or insecure scheme %q in %q", scheme+"://", raw)
		}
		working = working[idx+3:]
	}
	if slash := strings.IndexByte(working, '/'); slash != -1 {
		working = working[:slash]
	}
	if strings.HasPrefix(working, ":") {
		working = "0.0.0.0" + working
	}

	var host, portStr string
	if strings.HasPrefix(working, "[") {
		if strings.HasSuffix(working, "]") {
			host = working[1 : len(working)-1]
			portStr = strconv.Itoa(defaultPort)
		} else {
			h, p, err := net.SplitHostPort(working)
			if err != nil {
				return "", err
			}
			host, portStr = h, p
		}
	} else if ip := net.ParseIP(working); ip != nil {
		host = working
		portStr = strconv.Itoa(defaultPort)
	} else if strings.Count(working, ":") == 0 {
		host = working
		portStr = strconv.Itoa(defaultPort)
	} else {
		h, p, err := net.SplitHostPort(working)
		if err != nil {
			return "", err
		}
		host, portStr = h, p
	}

	if strings.TrimSpace(host) == "" {
		return "", fmt.Errorf("missing host in address %q", raw)
	}
	portNum, err := strconv.Atoi(portStr)
	if err != nil {
		return "", fmt.Errorf("invalid port %q in %q", portStr, raw)
	}
	minPort := 1
	if allowZeroPort {
		minPort = 0
	}
	if portNum < minPort || portNum > 65535 {
		return "", fmt.Errorf("port %d out of range [%d, 65535] in %q", portNum, minPort, raw)
	}
	return net.JoinHostPort(host, strconv.Itoa(portNum)), nil
}

func hasDialablePort(addr string) bool {
	_, portStr, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	return true
}

func extractRemoteIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		host = strings.TrimSpace(remoteAddr)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return ""
	}
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String()
	}
	return ip.String()
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func parseCACertAndPoolFromPEM(rawPEM []byte) (*x509.Certificate, *x509.CertPool, error) {
	pool := x509.NewCertPool()
	var primaryCA *x509.Certificate
	rest := rawPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, nil, fmt.Errorf("unexpected PEM block %q in Root CA payload", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse X.509 CA certificate: %w", err)
		}
		if !cert.IsCA {
			return nil, nil, fmt.Errorf("certificate CN=%q is not a CA certificate (IsCA=false)", cert.Subject.CommonName)
		}
		pool.AddCert(cert)
		if primaryCA == nil {
			primaryCA = cert
		}
	}
	if primaryCA == nil {
		return nil, nil, errors.New("no valid CERTIFICATE PEM block in Root CA payload")
	}
	return primaryCA, pool, nil
}

func parseSingleCertificatePEM(rawPEM []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(rawPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("payload does not contain a valid CERTIFICATE PEM block")
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		return nil, errors.New("payload contains unexpected trailing data after CERTIFICATE PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}
	return cert, nil
}

func isSerialInCRL(crl *x509.RevocationList, serial *big.Int) bool {
	if crl == nil || serial == nil {
		return false
	}
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber != nil && entry.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	for _, entry := range crl.RevokedCertificates {
		if entry.SerialNumber != nil && entry.SerialNumber.Cmp(serial) == 0 {
			return true
		}
	}
	return false
}
