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
	"crypto/x509/pkix"
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
	"github.com/kennyparsons/agent-bridge/internal/netbind"
	"github.com/kennyparsons/agent-bridge/internal/pki"
	"github.com/kennyparsons/agent-bridge/internal/protocol"
)

const (
	bootstrapJoinHTTPTimeout = 20 * time.Second
	maxJoinBodyBytes         = 1 << 20 // 1 MiB ceiling on join/control-plane JSON payloads
	crlClockSkewLeeway       = 5 * time.Minute
)

// BootstrapJoinOptions configures dual-mode cryptographic node enrollment (Mode A zero-touch CSR
// issuance when CertPath/KeyPath are absent on disk, or Mode B pre-issued certificate registration
// when CertPath/KeyPath already exist on disk).
type BootstrapJoinOptions struct {
	JoinAddr                 string
	JoinAddrs                []string
	JoinToken                string
	NodeID                   string
	ClusterBindAddr          string
	ClusterBindAddrs         []string
	AdvertiseAddr            string
	ExecBindAddr             string
	ExecBindAddrs            []string
	CertPath                 string
	KeyPath                  string
	CAPath                   string
	CRLPath                  string
	StatePath                string
	ExtraIPs                 []string
	ExtraDNSNames            []string
	AutoInterfaceSANs        bool
	DisableAutoInterfaceSANs bool
	InterfaceProvider        netbind.InterfaceProvider
	RouteSourceIP            func(seedAddr string) (net.IP, error)
}

// BootstrapJoinResult describes the completed (or idempotently skipped) node join outcome.
type BootstrapJoinResult struct {
	AlreadyBootstrapped bool                     `json:"already_bootstrapped"`
	Mode                string                   `json:"mode"`
	NodeID              string                   `json:"node_id"`
	ClusterAddr         string                   `json:"cluster_addr"`
	CertSerialHex       string                   `json:"cert_serial_hex,omitempty"`
	SeedAddr            string                   `json:"seed_addr"`
	SeedAddrs           []string                 `json:"seed_addrs,omitempty"`
	Peers               []PeerInfo               `json:"peers,omitempty"`
	Policy              protocol.ExecutionPolicy `json:"policy"`
}

// RenewOptions configures tokenless authenticated peer certificate renewal (`agent-bridge cluster rejoin`)
// over peer mTLS 1.3 in either Mode A (fresh ECDSA P-256 keypair + CSR) or Mode B (pre-issued NewCertPath + NewKeyPath).
type RenewOptions struct {
	JoinAddr                 string
	JoinAddrs                []string
	NodeID                   string
	ClusterBindAddr          string
	ClusterBindAddrs         []string
	AdvertiseAddr            string
	ExecBindAddr             string
	ExecBindAddrs            []string
	CertPath                 string
	KeyPath                  string
	NewCertPath              string
	NewKeyPath               string
	CAPath                   string
	CRLPath                  string
	StatePath                string
	ExtraIPs                 []string
	ExtraDNSNames            []string
	AutoInterfaceSANs        bool
	DisableAutoInterfaceSANs bool
	RevokeOldSerial          bool
	InterfaceProvider        netbind.InterfaceProvider
	RouteSourceIP            func(seedAddr string) (net.IP, error)
}

// RenewResult describes a completed tokenless peer certificate renewal.
type RenewResult struct {
	Mode             string                   `json:"mode"`
	NodeID           string                   `json:"node_id"`
	ClusterAddr      string                   `json:"cluster_addr"`
	OldCertSerialHex string                   `json:"old_cert_serial_hex"`
	CertSerialHex    string                   `json:"cert_serial_hex"`
	OldSerialRevoked bool                     `json:"old_serial_revoked"`
	SeedAddr         string                   `json:"seed_addr"`
	SeedAddrs        []string                 `json:"seed_addrs,omitempty"`
	JoinedAtUnix     int64                    `json:"joined_at_unix"`
	Incarnation      uint64                   `json:"incarnation"`
	Peers            []PeerInfo               `json:"peers,omitempty"`
	Policy           protocol.ExecutionPolicy `json:"policy"`
}

// NodeSANOptions configures CollectNodeSANs for node X.509 CSR/certificate SAN construction.
type NodeSANOptions struct {
	ClusterBindSpecs  []string
	AdvertiseAddr     string
	ExecBindSpecs     []string
	Hostname          string
	ExtraIPs          []string
	ExtraDNSNames     []string
	AutoInterfaceSANs bool
	InterfaceProvider netbind.InterfaceProvider
}

// ParseSeedAddrs parses, normalizes, and deduplicates comma-separated seed peer addresses into `host:port` form.
func ParseSeedAddrs(raw ...string) ([]string, error) {
	var out []string
	seen := make(map[string]struct{})
	for _, entry := range raw {
		for _, tok := range strings.Split(entry, ",") {
			trimmed := strings.TrimSpace(tok)
			if trimmed == "" {
				continue
			}
			normSeed, _, err := config.NormalizeClusterAddr(trimmed)
			if err != nil {
				return nil, fmt.Errorf("invalid seed peer address %q: %w", trimmed, err)
			}
			if _, exists := seen[normSeed]; !exists {
				seen[normSeed] = struct{}{}
				out = append(out, normSeed)
			}
		}
	}
	return out, nil
}

func orderSeedCandidates(
	seeds []string,
	provider netbind.InterfaceProvider,
	routeFn func(seedAddr string) (net.IP, error),
) (clean []string, hairpinned []*netbind.HairpinFinding) {
	for _, seed := range seeds {
		finding, _, err := netbind.DetectOutboundLANHairpin(seed, provider, routeFn)
		if err == nil && finding != nil {
			hairpinned = append(hairpinned, finding)
			continue
		}
		clean = append(clean, seed)
	}
	return clean, hairpinned
}

func formatHairpinError(f *netbind.HairpinFinding) error {
	if f == nil {
		return errors.New("outbound LAN hairpin route detected")
	}
	return fmt.Errorf(
		"outbound LAN hairpin detected toward seed %s: target IP %s belongs to local physical interface %q (%s) yet kernel UDP routing selected Tailscale egress IP %s; run 'tailscale set --accept-routes=false' or join via the seed's Tailscale 100.x address",
		f.SeedAddr, f.SeedIP, f.AttachedInterface, f.AttachedSubnet, f.SelectedEgressIP,
	)
}

func resolveCanonicalEndpoint(
	explicitAdv string,
	bindSpecs []string,
	defaultPort int,
	seedAddrs []string,
	provider netbind.InterfaceProvider,
	routeFn func(seedAddr string) (net.IP, error),
) (string, error) {
	if trimmedAdv := strings.TrimSpace(explicitAdv); trimmedAdv != "" {
		normAdv, err := normalizeBindOrAdvertiseAddr(trimmedAdv, defaultPort, true)
		if err != nil {
			return "", err
		}
		host, _, splitErr := net.SplitHostPort(normAdv)
		if splitErr != nil {
			return "", splitErr
		}
		lowerHost := strings.ToLower(strings.TrimSpace(host))
		if lowerHost == "all" || lowerHost == "*" || strings.Contains(lowerHost, "/") {
			return "", fmt.Errorf("advertise address %q cannot be a wildcard or CIDR selector", explicitAdv)
		}
		if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
			return "", fmt.Errorf("advertise address %q cannot be an unspecified wildcard IP (%s)", explicitAdv, ip.String())
		}
		return normAdv, nil
	}

	specs := netbind.SplitTokens(bindSpecs)
	if len(specs) == 0 {
		specs = []string{config.DefaultClusterEndpoint}
	}

	sels, err := netbind.ParseSpecs(specs, defaultPort, true)
	if err != nil {
		// Fallback for explicit DNS hostname bind specs (if any).
		if len(specs) == 1 {
			return normalizeBindOrAdvertiseAddr(specs[0], defaultPort, true)
		}
		return "", err
	}

	effPort := defaultPort
	allZero := len(sels) > 0
	for _, s := range sels {
		if s.Port != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		effPort = 0
	}

	return netbind.SelectCanonicalAdvertiseAddr(netbind.AdvertiseOptions{
		BoundAddrs:        specs,
		DefaultPort:       effPort,
		SeedAddrs:         seedAddrs,
		InterfaceProvider: provider,
		RouteSourceIP:     routeFn,
	})
}

func resolveExecEndpoint(
	rawExec string,
	defaultPort int,
	seedAddrs []string,
	provider netbind.InterfaceProvider,
	routeFn func(seedAddr string) (net.IP, error),
) (string, error) {
	specs := netbind.SplitTokens([]string{rawExec})
	if len(specs) == 0 {
		return "", nil
	}
	if len(specs) > 1 || netbind.ContainsWildcardOrCIDR(specs) {
		return resolveCanonicalEndpoint("", specs, defaultPort, seedAddrs, provider, routeFn)
	}
	return normalizeBindOrAdvertiseAddr(specs[0], defaultPort, true)
}

// BootstrapJoin enrolls the local node into an existing agent-bridge cluster using a single-use
// Root-CA-pinned join token (`abjt1.<ca_sha256>.<token_id>.<secret>`).
//
// Idempotent Restart & Leaf Serial Guard:
//   - If StatePath already records `Bootstrapped == true` AND the on-disk leaf certificate serial matches
//     the persisted cluster state's leaf serial, BootstrapJoin returns `AlreadyBootstrapped: true` immediately
//     without contacting any seed or consuming the single-use join token.
//   - If the on-disk certificate was replaced with a new serial:
//   - When `opts.JoinToken != ""` (Mode B re-keying), BootstrapJoin proceeds through Mode B PoP `/cluster/v1/join`
//     so the seed advances `JoinedAtUnix` and updates `cluster-state.json` without manual file deletion.
//   - When `opts.JoinToken == ""`, BootstrapJoin returns a clear actionable error suggesting `agent-bridge cluster rejoin`.
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

	rawSeedInputs := make([]string, 0, 1+len(opts.JoinAddrs))
	if strings.TrimSpace(opts.JoinAddr) != "" {
		rawSeedInputs = append(rawSeedInputs, opts.JoinAddr)
	}
	rawSeedInputs = append(rawSeedInputs, opts.JoinAddrs...)
	parsedSeeds, seedParseErr := ParseSeedAddrs(rawSeedInputs...)

	clusterBindSpecs := netbind.SplitTokens(opts.ClusterBindAddrs)
	if len(clusterBindSpecs) == 0 && strings.TrimSpace(opts.ClusterBindAddr) != "" {
		clusterBindSpecs = netbind.SplitTokens([]string{opts.ClusterBindAddr})
	}
	if len(clusterBindSpecs) == 0 {
		clusterBindSpecs = []string{config.DefaultClusterEndpoint}
	}

	clusterAddr, err := resolveCanonicalEndpoint(
		opts.AdvertiseAddr,
		clusterBindSpecs,
		config.DefaultClusterPort,
		parsedSeeds,
		opts.InterfaceProvider,
		opts.RouteSourceIP,
	)
	if err != nil {
		return nil, fmt.Errorf("BootstrapJoin: invalid cluster bind/advertise address: %w", err)
	}

	execBindSpecs := netbind.SplitTokens(opts.ExecBindAddrs)
	if len(execBindSpecs) == 0 && strings.TrimSpace(opts.ExecBindAddr) != "" {
		execBindSpecs = netbind.SplitTokens([]string{opts.ExecBindAddr})
	}
	var execAddr string
	if len(execBindSpecs) > 0 {
		normExec, execErr := resolveExecEndpoint(
			strings.Join(execBindSpecs, ","),
			protocol.DefaultPort,
			parsedSeeds,
			opts.InterfaceProvider,
			opts.RouteSourceIP,
		)
		if execErr != nil {
			return nil, fmt.Errorf("BootstrapJoin: invalid exec bind address: %w", execErr)
		}
		execAddr = normExec
	}

	persisted, stateErr := loadPersistedState(statePath)
	if certExists && keyExists && caExists && crlExists && stateErr == nil && persisted != nil && persisted.Bootstrapped {
		validRes, serialMismatchErr, ok := validateAlreadyBootstrapped(
			parsedSeeds,
			opts.JoinAddr,
			opts.JoinToken,
			nodeID,
			clusterAddr,
			certPath,
			keyPath,
			caPath,
			crlPath,
			persisted,
		)
		if serialMismatchErr != nil {
			return nil, serialMismatchErr
		}
		if ok {
			return validRes, nil
		}
	}

	if seedParseErr != nil {
		return nil, fmt.Errorf("BootstrapJoin: invalid --join address: %w", seedParseErr)
	}
	if len(parsedSeeds) == 0 {
		return nil, errors.New("BootstrapJoin: invalid --join address: cluster address cannot be empty")
	}

	parsedToken, err := ParseJoinToken(opts.JoinToken)
	if err != nil {
		return nil, err
	}

	cleanSeeds, hairpinnedSeeds := orderSeedCandidates(parsedSeeds, opts.InterfaceProvider, opts.RouteSourceIP)
	if len(cleanSeeds) == 0 && len(hairpinnedSeeds) > 0 {
		return nil, fmt.Errorf("BootstrapJoin: %w", formatHairpinError(hairpinnedSeeds[0]))
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

	autoSANs := opts.AutoInterfaceSANs || !opts.DisableAutoInterfaceSANs
	var (
		mode           string
		generatedKey   *ecdsa.PrivateKey
		generatedKeyPM []byte
		csrPEMBytes    []byte
		preIssuedCert  *x509.Certificate
		preIssuedKey   *ecdsa.PrivateKey
		preIssuedTLS   *tls.Certificate
		rawPreCertPEM  string
	)

	if !certExists {
		// Mode A: Zero-Touch CSR Certificate Issuance (private key generated locally and never transmitted).
		mode = "csr-issued"
		csrIPs, csrDNS := CollectNodeSANs(NodeSANOptions{
			ClusterBindSpecs:  clusterBindSpecs,
			AdvertiseAddr:     opts.AdvertiseAddr,
			ExecBindSpecs:     execBindSpecs,
			Hostname:          hostname,
			ExtraIPs:          opts.ExtraIPs,
			ExtraDNSNames:     opts.ExtraDNSNames,
			AutoInterfaceSANs: autoSANs,
			InterfaceProvider: opts.InterfaceProvider,
		})
		privKey, keyPEM, csrPEM, csrErr := pki.GenerateKeyAndCSR(nodeID, csrIPs, csrDNS)
		if csrErr != nil {
			return nil, fmt.Errorf("BootstrapJoin: failed to generate CSR: %w", csrErr)
		}
		generatedKey = privKey
		generatedKeyPM = keyPEM
		csrPEMBytes = csrPEM
	} else {
		// Mode B: Pre-Issued Certificate Registration (air-gapped / offline Root CA / manual cert replacement).
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
		rawCertBytes, readErr := os.ReadFile(certPath)
		if readErr != nil {
			return nil, fmt.Errorf("BootstrapJoin: failed to read existing certificate %q: %w", certPath, readErr)
		}
		preIssuedCert = leafCert
		preIssuedKey = leafKey
		preIssuedTLS = &tlsPair
		rawPreCertPEM = string(rawCertBytes)
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

	var (
		joinResp           JoinResponse
		winningSeed        string
		winningClusterAddr string
		seedErrs           []error
	)

	for _, hFinding := range hairpinnedSeeds {
		seedErrs = append(seedErrs, formatHairpinError(hFinding))
	}

	for _, seedCandidate := range cleanSeeds {
		seedHostPort, seedBaseHTTPS, normErr := config.NormalizeClusterAddr(seedCandidate)
		if normErr != nil {
			seedErrs = append(seedErrs, normErr)
			continue
		}

		attemptClusterAddr := clusterAddr
		if strings.TrimSpace(opts.AdvertiseAddr) == "" {
			if perSeedAdv, advErr := resolveCanonicalEndpoint(
				"",
				clusterBindSpecs,
				config.DefaultClusterPort,
				[]string{seedHostPort},
				opts.InterfaceProvider,
				opts.RouteSourceIP,
			); advErr == nil && perSeedAdv != "" {
				attemptClusterAddr = perSeedAdv
			}
		}

		var joinReq JoinRequest
		if mode == "csr-issued" {
			joinReq = JoinRequest{
				Token:         parsedToken.Raw,
				NodeID:        nodeID,
				ClusterAddr:   attemptClusterAddr,
				ExecAddr:      execAddr,
				Hostname:      hostname,
				CSRPEM:        string(csrPEMBytes),
				ExtraIPs:      opts.ExtraIPs,
				ExtraDNSNames: opts.ExtraDNSNames,
			}
		} else {
			popSig, popErr := signJoinPoP(preIssuedKey, parsedToken.TokenID, nodeID, attemptClusterAddr)
			if popErr != nil {
				return nil, fmt.Errorf("BootstrapJoin: failed to sign join proof-of-possession: %w", popErr)
			}
			joinReq = JoinRequest{
				Token:              parsedToken.Raw,
				NodeID:             nodeID,
				ClusterAddr:        attemptClusterAddr,
				ExecAddr:           execAddr,
				Hostname:           hostname,
				ExistingCertPEM:    rawPreCertPEM,
				PoPSignatureBase64: popSig,
			}
		}

		bodyBytes, marshalErr := json.Marshal(joinReq)
		if marshalErr != nil {
			return nil, fmt.Errorf("BootstrapJoin: failed to encode JoinRequest: %w", marshalErr)
		}

		reqCtx, cancel := context.WithTimeout(ctx, bootstrapJoinHTTPTimeout)
		httpReq, reqErr := http.NewRequestWithContext(reqCtx, http.MethodPost, seedBaseHTTPS+pathClusterJoin, bytes.NewReader(bodyBytes))
		if reqErr != nil {
			cancel()
			return nil, fmt.Errorf("BootstrapJoin: failed to construct HTTP request: %w", reqErr)
		}
		httpReq.Header.Set("Content-Type", "application/json")

		httpResp, doErr := httpClient.Do(httpReq)
		if doErr != nil {
			cancel()
			seedErrs = append(seedErrs, fmt.Errorf("BootstrapJoin: join handshake to %s failed: %w", seedHostPort, doErr))
			continue
		}

		respBytes, readErr := io.ReadAll(io.LimitReader(httpResp.Body, maxJoinBodyBytes))
		_ = httpResp.Body.Close()
		cancel()
		if readErr != nil {
			seedErrs = append(seedErrs, fmt.Errorf("BootstrapJoin: failed reading join response from %s: %w", seedHostPort, readErr))
			continue
		}
		if httpResp.StatusCode != http.StatusOK {
			apiErr := decodeClusterHTTPError(httpResp.StatusCode, respBytes, "BootstrapJoin rejected by seed peer")
			seedErrs = append(seedErrs, apiErr)
			continue
		}

		var decoded JoinResponse
		if unmarshalErr := json.Unmarshal(respBytes, &decoded); unmarshalErr != nil {
			seedErrs = append(seedErrs, fmt.Errorf("BootstrapJoin: malformed JoinResponse JSON from %s: %w", seedHostPort, unmarshalErr))
			continue
		}

		joinResp = decoded
		winningSeed = seedHostPort
		winningClusterAddr = attemptClusterAddr
		break
	}

	if winningSeed == "" {
		if len(seedErrs) == 1 {
			return nil, seedErrs[0]
		}
		parts := make([]string, 0, len(seedErrs))
		for _, e := range seedErrs {
			parts = append(parts, e.Error())
		}
		return nil, fmt.Errorf("BootstrapJoin failed across all %d candidate seed(s): %s", len(parsedSeeds), strings.Join(parts, "; "))
	}

	clusterAddr = winningClusterAddr

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
	var selfIncarnation uint64 = 1
	if persisted != nil && persisted.Incarnation >= 1 {
		selfIncarnation = persisted.Incarnation + 1
	}
	for _, p := range joinResp.Peers {
		cp := p.Clone()
		cp.IsSelf = false
		cp.IsLeader = false
		if cp.NodeID == nodeID {
			if cp.JoinedAtUnix > 0 {
				selfJoinedAt = cp.JoinedAtUnix
			}
			if cp.Incarnation > selfIncarnation {
				selfIncarnation = cp.Incarnation
			}
		}
		persistedPeers = append(persistedPeers, cp)
	}
	if selfJoinedAt <= 0 {
		selfJoinedAt = now.Unix()
	}

	recordedSeeds := mergeUniqueStrings([]string{winningSeed}, cleanSeeds)
	serialHex := pki.FormatSerialHex(finalCert.SerialNumber)

	var persistedTokens []TokenRecord
	if persisted != nil && len(persisted.Tokens) > 0 {
		persistedTokens = append([]TokenRecord(nil), persisted.Tokens...)
	}

	initialState := &persistedClusterState{
		SchemaVersion: currentStateSchemaVersion,
		Bootstrapped:  true,
		NodeID:        nodeID,
		CertSerialHex: serialHex,
		Incarnation:   selfIncarnation,
		JoinedAtUnix:  selfJoinedAt,
		SeedPeers:     recordedSeeds,
		SignedPolicy:  joinResp.SignedPolicy.Clone(),
		Peers:         persistedPeers,
		Tokens:        persistedTokens,
	}
	if err := savePersistedState(statePath, initialState); err != nil {
		return nil, err
	}

	return &BootstrapJoinResult{
		AlreadyBootstrapped: false,
		Mode:                mode,
		NodeID:              nodeID,
		ClusterAddr:         clusterAddr,
		CertSerialHex:       serialHex,
		SeedAddr:            winningSeed,
		SeedAddrs:           recordedSeeds,
		Peers:               joinResp.Peers,
		Policy:              effectivePolicy,
	}, nil
}

func validateAlreadyBootstrapped(
	parsedSeeds []string,
	rawJoinAddr string,
	rawJoinToken string,
	nodeID string,
	clusterAddr string,
	certPath string,
	keyPath string,
	caPath string,
	crlPath string,
	persisted *persistedClusterState,
) (*BootstrapJoinResult, error, bool) {
	tlsPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil || len(tlsPair.Certificate) == 0 {
		return nil, nil, false
	}
	leafCert, err := x509.ParseCertificate(tlsPair.Certificate[0])
	if err != nil {
		return nil, nil, false
	}
	caCert, caPool, err := pki.LoadCACertPool(caPath)
	if err != nil {
		return nil, nil, false
	}
	loadedCRL, err := pki.LoadCRL(crlPath, caCert)
	if err != nil {
		return nil, nil, false
	}
	if isSerialInCRL(loadedCRL, leafCert.SerialNumber) {
		return nil, nil, false
	}
	if !hasExtKeyUsage(leafCert, x509.ExtKeyUsageServerAuth) {
		return nil, nil, false
	}
	if _, err := pki.VerifyPeerCertDualEKU([][]byte{leafCert.Raw}, caPool, nil); err != nil {
		return nil, nil, false
	}

	diskSerialHex := pki.FormatSerialHex(leafCert.SerialNumber)
	persistedSerialHex := persistedSelfSerialHex(persisted, nodeID)
	if persistedSerialHex != "" && !strings.EqualFold(diskSerialHex, persistedSerialHex) {
		if strings.TrimSpace(rawJoinToken) != "" {
			// Mode B re-keying with an explicit join token: do NOT short-circuit to AlreadyBootstrapped;
			// proceed through Mode B PoP /cluster/v1/join so the cluster updates CertSerialHex and JoinedAtUnix!
			return nil, nil, false
		}
		return nil, fmt.Errorf(
			"BootstrapJoin: on-disk leaf certificate serial [%s] differs from persisted cluster state serial [%s] for node %q; run 'agent-bridge cluster rejoin' (or pass a fresh --join-token) to register the replacement certificate",
			diskSerialHex, persistedSerialHex, nodeID,
		), false
	}

	seedAddrs := mergeUniqueStrings(parsedSeeds, persisted.SeedPeers)
	seedAddr := ""
	if len(seedAddrs) > 0 {
		seedAddr = seedAddrs[0]
	} else if trimmed := strings.TrimSpace(rawJoinAddr); trimmed != "" {
		seedAddr = trimmed
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
		CertSerialHex:       diskSerialHex,
		SeedAddr:            seedAddr,
		SeedAddrs:           seedAddrs,
		Peers:               append([]PeerInfo(nil), persisted.Peers...),
		Policy:              pol,
	}, nil, true
}

// RenewPeerCert performs tokenless authenticated peer certificate rotation (`POST /cluster/v1/renew`)
// using the node's existing unrevoked mTLS leaf certificate, harvesting active NIC SANs (Mode A CSR)
// or proving possession of a replacement pre-issued keypair (Mode B), and atomically updating
// `CertPath`, `KeyPath`, `CRLPath`, and `StatePath` on disk.
func RenewPeerCert(ctx context.Context, opts RenewOptions) (*RenewResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	certPath := strings.TrimSpace(opts.CertPath)
	keyPath := strings.TrimSpace(opts.KeyPath)
	caPath := strings.TrimSpace(opts.CAPath)
	crlPath := strings.TrimSpace(opts.CRLPath)
	if certPath == "" {
		return nil, errors.New("RenewPeerCert: CertPath is required")
	}
	if keyPath == "" {
		return nil, errors.New("RenewPeerCert: KeyPath is required")
	}
	if caPath == "" {
		return nil, errors.New("RenewPeerCert: CAPath is required")
	}
	if crlPath == "" {
		return nil, errors.New("RenewPeerCert: CRLPath is required")
	}

	oldTLSPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil || len(oldTLSPair.Certificate) == 0 {
		return nil, fmt.Errorf("RenewPeerCert: failed to load active peer certificate/key pair: %w", err)
	}
	oldLeafCert, err := x509.ParseCertificate(oldTLSPair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("RenewPeerCert: failed to parse active peer leaf certificate: %w", err)
	}
	oldSerialHex := pki.FormatSerialHex(oldLeafCert.SerialNumber)

	caCert, caPool, err := pki.LoadCACertPool(caPath)
	if err != nil {
		return nil, fmt.Errorf("RenewPeerCert: failed to load Root CA certificate %q: %w", caPath, err)
	}
	if _, verifyErr := pki.VerifyPeerCertDualEKU([][]byte{oldLeafCert.Raw}, caPool, nil); verifyErr != nil {
		return nil, fmt.Errorf("RenewPeerCert: active peer certificate failed CA verification: %w", verifyErr)
	}
	if !hasExtKeyUsage(oldLeafCert, x509.ExtKeyUsageServerAuth) {
		return nil, errors.New("RenewPeerCert: active peer certificate lacks ServerAuth extended key usage")
	}

	hostname, _ := os.Hostname()
	hostname = strings.TrimSpace(hostname)

	nodeID := strings.TrimSpace(opts.NodeID)
	if nodeID == "" {
		nodeID = strings.TrimSpace(oldLeafCert.Subject.CommonName)
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
	persisted, _ := loadPersistedState(statePath)

	rawSeedInputs := make([]string, 0, 2+len(opts.JoinAddrs))
	if strings.TrimSpace(opts.JoinAddr) != "" {
		rawSeedInputs = append(rawSeedInputs, opts.JoinAddr)
	}
	rawSeedInputs = append(rawSeedInputs, opts.JoinAddrs...)
	parsedSeeds, err := ParseSeedAddrs(rawSeedInputs...)
	if err != nil {
		return nil, fmt.Errorf("RenewPeerCert: %w", err)
	}
	if len(parsedSeeds) == 0 && persisted != nil {
		var fallbackSeeds []string
		fallbackSeeds = append(fallbackSeeds, persisted.SeedPeers...)
		for _, p := range persisted.Peers {
			if p.NodeID != nodeID && hasDialablePort(p.ClusterAddr) {
				fallbackSeeds = append(fallbackSeeds, p.ClusterAddr)
			}
		}
		if fallbackParsed, fbErr := ParseSeedAddrs(fallbackSeeds...); fbErr == nil {
			parsedSeeds = fallbackParsed
		}
	}
	if len(parsedSeeds) == 0 {
		return nil, errors.New("RenewPeerCert: at least one target cluster peer address (--join / SeedPeers) is required")
	}

	cleanSeeds, hairpinnedSeeds := orderSeedCandidates(parsedSeeds, opts.InterfaceProvider, opts.RouteSourceIP)
	if len(cleanSeeds) == 0 && len(hairpinnedSeeds) > 0 {
		return nil, fmt.Errorf("RenewPeerCert: %w", formatHairpinError(hairpinnedSeeds[0]))
	}

	clusterBindSpecs := netbind.SplitTokens(opts.ClusterBindAddrs)
	if len(clusterBindSpecs) == 0 && strings.TrimSpace(opts.ClusterBindAddr) != "" {
		clusterBindSpecs = netbind.SplitTokens([]string{opts.ClusterBindAddr})
	}
	if len(clusterBindSpecs) == 0 {
		clusterBindSpecs = []string{config.DefaultClusterEndpoint}
	}

	clusterAddr, err := resolveCanonicalEndpoint(
		opts.AdvertiseAddr,
		clusterBindSpecs,
		config.DefaultClusterPort,
		cleanSeeds,
		opts.InterfaceProvider,
		opts.RouteSourceIP,
	)
	if err != nil {
		return nil, fmt.Errorf("RenewPeerCert: invalid cluster bind/advertise address: %w", err)
	}

	execBindSpecs := netbind.SplitTokens(opts.ExecBindAddrs)
	if len(execBindSpecs) == 0 && strings.TrimSpace(opts.ExecBindAddr) != "" {
		execBindSpecs = netbind.SplitTokens([]string{opts.ExecBindAddr})
	}
	var execAddr string
	if len(execBindSpecs) > 0 {
		normExec, execErr := resolveExecEndpoint(
			strings.Join(execBindSpecs, ","),
			protocol.DefaultPort,
			cleanSeeds,
			opts.InterfaceProvider,
			opts.RouteSourceIP,
		)
		if execErr != nil {
			return nil, fmt.Errorf("RenewPeerCert: invalid exec bind address: %w", execErr)
		}
		execAddr = normExec
	}

	newCertPath := strings.TrimSpace(opts.NewCertPath)
	newKeyPath := strings.TrimSpace(opts.NewKeyPath)
	if (newCertPath == "") != (newKeyPath == "") {
		return nil, errors.New("RenewPeerCert: NewCertPath and NewKeyPath must be provided together for pre-issued renewal")
	}

	autoSANs := opts.AutoInterfaceSANs || !opts.DisableAutoInterfaceSANs
	var (
		mode           string
		generatedKey   *ecdsa.PrivateKey
		generatedKeyPM []byte
		csrPEMBytes    []byte
		replacementCrt *x509.Certificate
		replacementKey *ecdsa.PrivateKey
		rawNewCertPEM  []byte
		rawNewKeyPEM   []byte
	)

	if newCertPath == "" {
		mode = "csr-renewed"
		csrIPs, csrDNS := CollectNodeSANs(NodeSANOptions{
			ClusterBindSpecs:  clusterBindSpecs,
			AdvertiseAddr:     opts.AdvertiseAddr,
			ExecBindSpecs:     execBindSpecs,
			Hostname:          hostname,
			ExtraIPs:          opts.ExtraIPs,
			ExtraDNSNames:     opts.ExtraDNSNames,
			AutoInterfaceSANs: autoSANs,
			InterfaceProvider: opts.InterfaceProvider,
		})
		privKey, keyPEM, csrPEM, csrErr := pki.GenerateKeyAndCSR(nodeID, csrIPs, csrDNS)
		if csrErr != nil {
			return nil, fmt.Errorf("RenewPeerCert: failed to generate CSR: %w", csrErr)
		}
		generatedKey = privKey
		generatedKeyPM = keyPEM
		csrPEMBytes = csrPEM
	} else {
		mode = "pre-issued-renewed"
		newPair, pairErr := tls.LoadX509KeyPair(newCertPath, newKeyPath)
		if pairErr != nil || len(newPair.Certificate) == 0 {
			return nil, fmt.Errorf("RenewPeerCert: failed to load replacement certificate/key pair: %w", pairErr)
		}
		parsedNewLeaf, parseErr := x509.ParseCertificate(newPair.Certificate[0])
		if parseErr != nil {
			return nil, fmt.Errorf("RenewPeerCert: failed to parse replacement leaf certificate %q: %w", newCertPath, parseErr)
		}
		loadedNewKey, keyErr := pki.LoadPrivateKey(newKeyPath)
		if keyErr != nil {
			return nil, fmt.Errorf("RenewPeerCert: failed to load replacement private key %q: %w", newKeyPath, keyErr)
		}
		certBytes, readCertErr := os.ReadFile(newCertPath)
		if readCertErr != nil {
			return nil, fmt.Errorf("RenewPeerCert: failed to read replacement certificate %q: %w", newCertPath, readCertErr)
		}
		keyBytes, readKeyErr := os.ReadFile(newKeyPath)
		if readKeyErr != nil {
			return nil, fmt.Errorf("RenewPeerCert: failed to read replacement private key %q: %w", newKeyPath, readKeyErr)
		}
		replacementCrt = parsedNewLeaf
		replacementKey = loadedNewKey
		rawNewCertPEM = certBytes
		rawNewKeyPEM = keyBytes
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{oldTLSPair},
		InsecureSkipVerify: true, // Strictly paired with VerifyPeerCertDualEKU + ServerAuth check below.
		VerifyConnection: func(cs tls.ConnectionState) error {
			rawCerts := certsToRawDER(cs.PeerCertificates)
			leaf, verifyErr := pki.VerifyPeerCertDualEKU(rawCerts, caPool, nil)
			if verifyErr != nil {
				return verifyErr
			}
			if !hasExtKeyUsage(leaf, x509.ExtKeyUsageServerAuth) {
				return errors.New("TLS Handshake Rejected: cluster server certificate lacks ServerAuth extended key usage")
			}
			return nil
		},
	}

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

	var (
		renewResp          RenewResponse
		winningSeed        string
		winningClusterAddr string
		seedErrs           []error
	)

	for _, hFinding := range hairpinnedSeeds {
		seedErrs = append(seedErrs, formatHairpinError(hFinding))
	}

	for _, seedCandidate := range cleanSeeds {
		seedHostPort, seedBaseHTTPS, normErr := config.NormalizeClusterAddr(seedCandidate)
		if normErr != nil {
			seedErrs = append(seedErrs, normErr)
			continue
		}

		attemptClusterAddr := clusterAddr
		if strings.TrimSpace(opts.AdvertiseAddr) == "" {
			if perSeedAdv, advErr := resolveCanonicalEndpoint(
				"",
				clusterBindSpecs,
				config.DefaultClusterPort,
				[]string{seedHostPort},
				opts.InterfaceProvider,
				opts.RouteSourceIP,
			); advErr == nil && perSeedAdv != "" {
				attemptClusterAddr = perSeedAdv
			}
		}

		var renewReq RenewRequest
		if mode == "csr-renewed" {
			renewReq = RenewRequest{
				NodeID:          nodeID,
				ClusterAddr:     attemptClusterAddr,
				ExecAddr:        execAddr,
				Hostname:        hostname,
				CSRPEM:          string(csrPEMBytes),
				ExtraIPs:        opts.ExtraIPs,
				ExtraDNSNames:   opts.ExtraDNSNames,
				RevokeOldSerial: opts.RevokeOldSerial,
			}
		} else {
			popSig, popErr := signRenewPoP(replacementKey, oldSerialHex, nodeID, attemptClusterAddr)
			if popErr != nil {
				return nil, fmt.Errorf("RenewPeerCert: failed to sign renew proof-of-possession: %w", popErr)
			}
			renewReq = RenewRequest{
				NodeID:             nodeID,
				ClusterAddr:        attemptClusterAddr,
				ExecAddr:           execAddr,
				Hostname:           hostname,
				ExistingCertPEM:    string(rawNewCertPEM),
				PoPSignatureBase64: popSig,
				ExtraIPs:           opts.ExtraIPs,
				ExtraDNSNames:      opts.ExtraDNSNames,
				RevokeOldSerial:    opts.RevokeOldSerial,
			}
		}

		bodyBytes, marshalErr := json.Marshal(renewReq)
		if marshalErr != nil {
			return nil, fmt.Errorf("RenewPeerCert: failed to encode RenewRequest: %w", marshalErr)
		}

		reqCtx, cancel := context.WithTimeout(ctx, bootstrapJoinHTTPTimeout)
		httpReq, reqErr := http.NewRequestWithContext(reqCtx, http.MethodPost, seedBaseHTTPS+pathClusterRenew, bytes.NewReader(bodyBytes))
		if reqErr != nil {
			cancel()
			return nil, fmt.Errorf("RenewPeerCert: failed to construct HTTP request: %w", reqErr)
		}
		httpReq.Header.Set("Content-Type", "application/json")

		httpResp, doErr := httpClient.Do(httpReq)
		if doErr != nil {
			cancel()
			seedErrs = append(seedErrs, fmt.Errorf("RenewPeerCert: renew handshake to %s failed: %w", seedHostPort, doErr))
			continue
		}

		respBytes, readErr := io.ReadAll(io.LimitReader(httpResp.Body, maxJoinBodyBytes))
		_ = httpResp.Body.Close()
		cancel()
		if readErr != nil {
			seedErrs = append(seedErrs, fmt.Errorf("RenewPeerCert: failed reading renew response from %s: %w", seedHostPort, readErr))
			continue
		}
		if httpResp.StatusCode != http.StatusOK {
			apiErr := decodeClusterHTTPError(httpResp.StatusCode, respBytes, "RenewPeerCert rejected by cluster peer")
			seedErrs = append(seedErrs, apiErr)
			continue
		}

		var decoded RenewResponse
		if unmarshalErr := json.Unmarshal(respBytes, &decoded); unmarshalErr != nil {
			seedErrs = append(seedErrs, fmt.Errorf("RenewPeerCert: malformed RenewResponse JSON from %s: %w", seedHostPort, unmarshalErr))
			continue
		}

		renewResp = decoded
		winningSeed = seedHostPort
		winningClusterAddr = attemptClusterAddr
		break
	}

	if winningSeed == "" {
		if len(seedErrs) == 1 {
			return nil, seedErrs[0]
		}
		parts := make([]string, 0, len(seedErrs))
		for _, e := range seedErrs {
			parts = append(parts, e.Error())
		}
		return nil, fmt.Errorf("RenewPeerCert failed across all %d candidate peer(s): %s", len(parsedSeeds), strings.Join(parts, "; "))
	}

	clusterAddr = winningClusterAddr

	parsedCRL, err := pki.ParseAndVerifyCRL([]byte(renewResp.CRLPEM), caCert)
	if err != nil {
		return nil, fmt.Errorf("RenewPeerCert: invalid CRL in RenewResponse: %w", err)
	}
	now := time.Now().UTC()
	if parsedCRL.NextUpdate.IsZero() || now.After(parsedCRL.NextUpdate) {
		return nil, errors.New("RenewPeerCert: RenewResponse CRL is expired or missing nextUpdate")
	}

	var finalCert *x509.Certificate
	var certBytesToWrite []byte
	var keyBytesToWrite []byte

	if mode == "csr-renewed" {
		if strings.TrimSpace(renewResp.IssuedCertPEM) == "" {
			return nil, errors.New("RenewPeerCert: peer returned empty issued_cert_pem for CSR renewal")
		}
		issuedLeaf, certErr := parseSingleCertificatePEM([]byte(renewResp.IssuedCertPEM))
		if certErr != nil {
			return nil, fmt.Errorf("RenewPeerCert: invalid issued certificate in RenewResponse: %w", certErr)
		}
		if _, verifyErr := pki.VerifyPeerCertDualEKU([][]byte{issuedLeaf.Raw}, caPool, nil); verifyErr != nil {
			return nil, fmt.Errorf("RenewPeerCert: issued certificate failed CA chain verification: %w", verifyErr)
		}
		issuedPub, ok := issuedLeaf.PublicKey.(*ecdsa.PublicKey)
		if !ok || !generatedKey.PublicKey.Equal(issuedPub) {
			return nil, errors.New("RenewPeerCert: issued certificate public key does not match locally generated private key")
		}
		if isSerialInCRL(parsedCRL, issuedLeaf.SerialNumber) {
			return nil, errors.New("RenewPeerCert: newly issued certificate is already revoked in returned CRL")
		}
		finalCert = issuedLeaf
		certBytesToWrite = []byte(renewResp.IssuedCertPEM)
		keyBytesToWrite = generatedKeyPM
	} else {
		if _, verifyErr := pki.VerifyPeerCertDualEKU([][]byte{replacementCrt.Raw}, caPool, nil); verifyErr != nil {
			return nil, fmt.Errorf("RenewPeerCert: replacement certificate failed CA chain verification: %w", verifyErr)
		}
		if isSerialInCRL(parsedCRL, replacementCrt.SerialNumber) {
			return nil, fmt.Errorf("RenewPeerCert: replacement certificate [%s] is revoked in returned CRL", pki.FormatSerialHex(replacementCrt.SerialNumber))
		}
		finalCert = replacementCrt
		certBytesToWrite = rawNewCertPEM
		keyBytesToWrite = rawNewKeyPEM
	}

	var effectivePolicy protocol.ExecutionPolicy
	if renewResp.SignedPolicy != nil {
		if err := renewResp.SignedPolicy.Verify(caCert, caPool, nil); err != nil {
			return nil, fmt.Errorf("RenewPeerCert: RenewResponse SignedPolicy failed signature verification: %w", err)
		}
		if signerCert, sigCertErr := parseSingleCertificatePEM([]byte(renewResp.SignedPolicy.SignerCertPEM)); sigCertErr == nil {
			if !signerCert.IsCA && isSerialInCRL(parsedCRL, signerCert.SerialNumber) {
				return nil, errors.New("RenewPeerCert: RenewResponse SignedPolicy was signed by a revoked certificate")
			}
		}
		effectivePolicy = renewResp.SignedPolicy.Policy
	}

	if err := pki.WriteFileAtomic(keyPath, keyBytesToWrite, 0o600); err != nil {
		return nil, fmt.Errorf("RenewPeerCert: failed to write rotated private key %q: %w", keyPath, err)
	}
	if err := pki.WriteFileAtomic(certPath, certBytesToWrite, 0o644); err != nil {
		return nil, fmt.Errorf("RenewPeerCert: failed to write rotated certificate %q: %w", certPath, err)
	}

	shouldWriteCRL := true
	if fileExists(crlPath) {
		if existingCRL, loadErr := pki.LoadCRL(crlPath, caCert); loadErr == nil &&
			existingCRL.Number != nil && parsedCRL.Number != nil &&
			parsedCRL.Number.Cmp(existingCRL.Number) <= 0 {
			shouldWriteCRL = false
		}
	}
	if shouldWriteCRL {
		if err := pki.WriteFileAtomic(crlPath, []byte(renewResp.CRLPEM), 0o644); err != nil {
			return nil, fmt.Errorf("RenewPeerCert: failed to write CRL %q: %w", crlPath, err)
		}
	}

	newSerialHex := pki.FormatSerialHex(finalCert.SerialNumber)
	selfJoinedAt := renewResp.JoinedAtUnix
	var selfIncarnation uint64 = 1
	if persisted != nil && persisted.Incarnation >= 1 {
		selfIncarnation = persisted.Incarnation + 1
	}
	if renewResp.Incarnation > selfIncarnation {
		selfIncarnation = renewResp.Incarnation
	}

	persistedPeers := make([]PeerInfo, 0, len(renewResp.Peers))
	for _, p := range renewResp.Peers {
		cp := p.Clone()
		cp.IsSelf = false
		cp.IsLeader = false
		if cp.NodeID == nodeID {
			if cp.JoinedAtUnix > selfJoinedAt {
				selfJoinedAt = cp.JoinedAtUnix
			}
			if cp.Incarnation > selfIncarnation {
				selfIncarnation = cp.Incarnation
			}
		}
		persistedPeers = append(persistedPeers, cp)
	}
	if selfJoinedAt <= 0 {
		selfJoinedAt = now.Unix()
	}

	var prevSeeds []string
	var persistedTokens []TokenRecord
	var signedPolToSave *SignedPolicyEnvelope
	if renewResp.SignedPolicy != nil {
		signedPolToSave = renewResp.SignedPolicy.Clone()
	}
	if persisted != nil {
		prevSeeds = persisted.SeedPeers
		if len(persisted.Tokens) > 0 {
			persistedTokens = append([]TokenRecord(nil), persisted.Tokens...)
		}
		if signedPolToSave == nil && persisted.SignedPolicy != nil {
			signedPolToSave = persisted.SignedPolicy.Clone()
			effectivePolicy = signedPolToSave.Policy
		}
	}

	recordedSeeds := mergeUniqueStrings(mergeUniqueStrings([]string{winningSeed}, cleanSeeds), prevSeeds)

	updatedState := &persistedClusterState{
		SchemaVersion: currentStateSchemaVersion,
		Bootstrapped:  true,
		NodeID:        nodeID,
		CertSerialHex: newSerialHex,
		Incarnation:   selfIncarnation,
		JoinedAtUnix:  selfJoinedAt,
		SeedPeers:     recordedSeeds,
		SignedPolicy:  signedPolToSave,
		Peers:         persistedPeers,
		Tokens:        persistedTokens,
	}
	if err := savePersistedState(statePath, updatedState); err != nil {
		return nil, err
	}

	return &RenewResult{
		Mode:             mode,
		NodeID:           nodeID,
		ClusterAddr:      clusterAddr,
		OldCertSerialHex: oldSerialHex,
		CertSerialHex:    newSerialHex,
		OldSerialRevoked: renewResp.OldSerialRevoked,
		SeedAddr:         winningSeed,
		SeedAddrs:        recordedSeeds,
		JoinedAtUnix:     selfJoinedAt,
		Incarnation:      selfIncarnation,
		Peers:            renewResp.Peers,
		Policy:           effectivePolicy,
	}, nil
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

// handleRenew processes authenticated peer mTLS 1.3 POST /cluster/v1/renew requests for tokenless leaf rotation.
func (e *Engine) handleRenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if e.closed.Load() {
		writeJSONError(w, http.StatusServiceUnavailable, "cluster engine is shutting down")
		return
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0] == nil {
		writeJSONError(w, http.StatusUnauthorized, "peer mTLS certificate required")
		return
	}

	var req RenewRequest
	if err := decodeJSONBody(w, r, &req); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid RenewRequest JSON: %v", err))
		return
	}

	callerLeaf := r.TLS.PeerCertificates[0]
	callerCN := strings.TrimSpace(callerLeaf.Subject.CommonName)
	if strings.TrimSpace(req.NodeID) == "" {
		req.NodeID = callerCN
	}
	if strings.TrimSpace(req.NodeID) != callerCN {
		writeJSONError(w, http.StatusForbidden, fmt.Sprintf("caller certificate CommonName %q does not match renew node_id %q", callerCN, strings.TrimSpace(req.NodeID)))
		return
	}
	callerSerialHex := pki.FormatSerialHex(callerLeaf.SerialNumber)
	observedRemoteIP := extractRemoteIP(r.RemoteAddr)

	resp, statusCode, err := e.processRenewRequest(r.Context(), req, callerSerialHex, callerCN, observedRemoteIP, true)
	if err != nil {
		writeJSONError(w, statusCode, err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, resp)
}

// handleSignJoin processes peer-forwarded CSR join or renew requests over authenticated mTLS 1.3 on an authority node holding ca.key.
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
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid forwarded join/renew payload: %v", err))
		return
	}

	if !e.hasCAKey || e.caKey == nil {
		writeJSONError(w, http.StatusBadRequest, "this node does not hold the Root CA private key (--ca-key)")
		return
	}

	if fwd.RenewRequest != nil {
		resp, statusCode, err := e.processRenewRequest(r.Context(), *fwd.RenewRequest, fwd.CallerCertSerial, fwd.CallerCertCN, fwd.ObservedRemoteIP, false)
		if err != nil {
			writeJSONError(w, statusCode, err.Error())
			return
		}
		writeJSONResponse(w, http.StatusOK, resp)
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

	var preValidatedCert *x509.Certificate
	if hasCSR {
		csrCN, csrErr := parseCSRCommonName([]byte(req.CSRPEM))
		if csrErr != nil || strings.TrimSpace(csrCN) != nodeID {
			if csrErr != nil {
				return nil, http.StatusForbidden, fmt.Errorf("invalid join CSR CommonName: %w", csrErr)
			}
			return nil, http.StatusForbidden, fmt.Errorf("CSR CommonName %q must match join node_id %q", csrCN, nodeID)
		}
	} else {
		existingCert, parseErr := parseSingleCertificatePEM([]byte(req.ExistingCertPEM))
		if parseErr != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("invalid existing_cert_pem: %w", parseErr)
		}
		if strings.TrimSpace(existingCert.Subject.CommonName) != nodeID {
			return nil, http.StatusForbidden, fmt.Errorf(
				"pre-issued certificate CommonName %q must match join node_id %q",
				existingCert.Subject.CommonName, nodeID,
			)
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
		preValidatedCert = existingCert
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
		extraIPs, extraDNS := buildServerSideExtraSANs(observedRemoteIP, normClusterAddr, normExecAddr, req.Hostname, req.ExtraIPs, req.ExtraDNSNames)
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
		admittedCert = preValidatedCert
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

func (e *Engine) processRenewRequest(
	ctx context.Context,
	req RenewRequest,
	callerSerialHex string,
	callerCN string,
	observedRemoteIP string,
	allowForward bool,
) (*RenewResponse, int, error) {
	e.joinMu.Lock()
	defer e.joinMu.Unlock()

	status := e.Status()
	if status.Topology == TopologyMultiNodeQuorum && !status.HasQuorum {
		return nil, http.StatusServiceUnavailable, ErrNoQuorum
	}

	nodeID := strings.TrimSpace(req.NodeID)
	if nodeID == "" {
		return nil, http.StatusBadRequest, errors.New("renew request node_id cannot be empty")
	}
	callerSerialHex = strings.TrimSpace(callerSerialHex)
	if callerSerialHex == "" {
		return nil, http.StatusUnauthorized, errors.New("missing authenticated peer certificate serial")
	}
	callerCN = strings.TrimSpace(callerCN)
	if callerCN == "" || callerCN != nodeID {
		return nil, http.StatusForbidden, fmt.Errorf(
			"caller certificate CommonName %q does not match renew node_id %q",
			callerCN, nodeID,
		)
	}

	normClusterAddr, err := normalizeBindOrAdvertiseAddr(req.ClusterAddr, config.DefaultClusterPort, true)
	if err != nil {
		return nil, http.StatusBadRequest, fmt.Errorf("invalid renew cluster_addr %q: %w", req.ClusterAddr, err)
	}
	req.ClusterAddr = normClusterAddr

	var normExecAddr string
	if strings.TrimSpace(req.ExecAddr) != "" {
		normExecAddr, err = normalizeBindOrAdvertiseAddr(req.ExecAddr, protocol.DefaultPort, true)
		if err != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("invalid renew exec_addr %q: %w", req.ExecAddr, err)
		}
	}
	req.ExecAddr = normExecAddr
	req.NodeID = nodeID
	req.Hostname = strings.TrimSpace(req.Hostname)

	// Verify caller leaf certificate serial matches registered e.peers[nodeID].CertSerialHex!
	if !e.peerMatchesSerial(nodeID, callerSerialHex) {
		e.pullFromAllPeers(ctx)
	}
	e.mu.RLock()
	registeredPeer, peerExists := e.peers[nodeID]
	var registeredSerial string
	if peerExists && registeredPeer != nil {
		registeredSerial = strings.TrimSpace(registeredPeer.CertSerialHex)
	}
	e.mu.RUnlock()

	if !peerExists || registeredPeer == nil {
		return nil, http.StatusForbidden, fmt.Errorf("node %q is not a registered cluster peer; use 'agent-bridge cluster token create' + '--join-token' for initial enrollment", nodeID)
	}
	if registeredSerial == "" || !strings.EqualFold(registeredSerial, callerSerialHex) {
		return nil, http.StatusForbidden, fmt.Errorf(
			"caller certificate serial [%s] does not match registered peer %q certificate serial [%s]",
			callerSerialHex, nodeID, registeredSerial,
		)
	}

	hasCSR := strings.TrimSpace(req.CSRPEM) != ""
	hasExisting := strings.TrimSpace(req.ExistingCertPEM) != ""
	if hasCSR == hasExisting {
		return nil, http.StatusBadRequest, errors.New("renew request must supply exactly one of csr_pem or existing_cert_pem")
	}

	var preValidatedReplacement *x509.Certificate
	if hasCSR {
		csrCN, csrErr := parseCSRCommonName([]byte(req.CSRPEM))
		if csrErr != nil {
			return nil, http.StatusBadRequest, csrErr
		}
		if strings.TrimSpace(csrCN) != nodeID {
			return nil, http.StatusForbidden, fmt.Errorf("CSR CommonName %q must match renewing peer node_id %q", csrCN, nodeID)
		}
	} else {
		existingCert, parseErr := parseSingleCertificatePEM([]byte(req.ExistingCertPEM))
		if parseErr != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("invalid existing_cert_pem: %w", parseErr)
		}
		if strings.TrimSpace(existingCert.Subject.CommonName) != nodeID {
			return nil, http.StatusForbidden, fmt.Errorf(
				"replacement certificate CommonName %q must match renewing peer node_id %q",
				existingCert.Subject.CommonName, nodeID,
			)
		}
		if _, verifyErr := pki.VerifyPeerCertDualEKU([][]byte{existingCert.Raw}, e.caPool, e.crlWatcher); verifyErr != nil {
			return nil, http.StatusForbidden, fmt.Errorf("replacement certificate rejected: %w", verifyErr)
		}
		if !hasExtKeyUsage(existingCert, x509.ExtKeyUsageServerAuth) {
			return nil, http.StatusBadRequest, errors.New("replacement peer certificate must include ServerAuth extended key usage")
		}
		if strings.EqualFold(pki.FormatSerialHex(existingCert.SerialNumber), callerSerialHex) {
			return nil, http.StatusBadRequest, fmt.Errorf(
				"replacement certificate serial [%s] must differ from active peer certificate serial",
				callerSerialHex,
			)
		}
		if err := verifyRenewPoP(existingCert, callerSerialHex, nodeID, normClusterAddr, req.PoPSignatureBase64); err != nil {
			return nil, http.StatusUnauthorized, fmt.Errorf("renew proof-of-possession verification failed: %w", err)
		}
		preValidatedReplacement = existingCert
	}

	if (hasCSR || req.RevokeOldSerial) && (!e.hasCAKey || e.caKey == nil) {
		if !allowForward {
			if hasCSR {
				return nil, http.StatusServiceUnavailable, errors.New(
					"cannot sign CSR on renew: authority node lacks --ca-key; pass --ca-key on an authority node or pre-issue replacement cert/key with 'agent-bridge ca issue'",
				)
			}
			return nil, http.StatusServiceUnavailable, errors.New(
				"cannot revoke old certificate serial on renew: authority node lacks --ca-key",
			)
		}
		return e.forwardRenewToAuthorityPeer(ctx, req, callerSerialHex, callerCN, observedRemoteIP)
	}

	var (
		issuedCertPEM string
		admittedCert  *x509.Certificate
	)

	if hasCSR {
		extraIPs, extraDNS := buildServerSideExtraSANs(observedRemoteIP, normClusterAddr, normExecAddr, req.Hostname, req.ExtraIPs, req.ExtraDNSNames)
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
			return nil, http.StatusBadRequest, fmt.Errorf("CSR renewal signing failed: %w", signErr)
		}
		issuedCertPEM = string(signedPEM)
		admittedCert = signedCert
	} else {
		admittedCert = preValidatedReplacement
	}

	newSerialHex := pki.FormatSerialHex(admittedCert.SerialNumber)
	now := time.Now().UTC()

	var (
		persistSnap   *persistedClusterState
		persistSeq    uint64
		signedPolCopy *SignedPolicyEnvelope
		peersOut      []PeerInfo
		joinedAt      int64
		incarnation   uint64
	)

	e.mu.Lock()
	curPeer, stillExists := e.peers[nodeID]
	if !stillExists || curPeer == nil || !strings.EqualFold(curPeer.CertSerialHex, callerSerialHex) {
		e.mu.Unlock()
		return nil, http.StatusConflict, errors.New("peer certificate state changed concurrently during renewal")
	}

	joinedAt = now.Unix()
	if curPeer.JoinedAtUnix >= joinedAt {
		joinedAt = curPeer.JoinedAtUnix + 1
	}
	incarnation = curPeer.Incarnation + 1

	polVer := uint64(0)
	if e.signedPolicy != nil {
		if req.RevokeOldSerial && e.hasCAKey && e.caKey != nil && nodeID != e.nodeID &&
			policySignerMatchesSerial(e.signedPolicy, callerSerialHex) {
			if reSigned, reSignErr := e.reSignPolicyWithCALocked(e.signedPolicy, now); reSignErr == nil {
				e.signedPolicy = reSigned
				e.storePolicySnapshotLocked(reSigned.Policy)
			} else {
				e.logf("warning: failed re-signing cluster policy with Root CA before revoking %s [%s]: %v", nodeID, callerSerialHex, reSignErr)
			}
		}
		polVer = e.signedPolicy.Policy.Version
		signedPolCopy = e.signedPolicy.Clone()
	}

	preservedHasCAKey := curPeer.HasCAKey
	execToStore := normExecAddr
	if execToStore == "" {
		execToStore = curPeer.ExecAddr
	}
	hostToStore := req.Hostname
	if hostToStore == "" {
		hostToStore = curPeer.Hostname
	}

	if nodeID == e.nodeID {
		e.selfJoinedAt = joinedAt
		e.selfIncarnation = incarnation
	}

	e.peers[nodeID] = &PeerInfo{
		NodeID:        nodeID,
		ClusterAddr:   normClusterAddr,
		ExecAddr:      execToStore,
		Hostname:      hostToStore,
		CertSerialHex: newSerialHex,
		HasCAKey:      preservedHasCAKey,
		Incarnation:   incarnation,
		State:         PeerAlive,
		CRLNumber:     e.currentCRLNumberString(),
		PolicyVersion: polVer,
		JoinedAtUnix:  joinedAt,
		LastSeenUnix:  now.Unix(),
	}
	e.lastContact[nodeID] = now

	if nodeID != e.nodeID {
		e.refreshSelfLocked(now)
	}
	eval := EvaluateQuorum(e.nodeID, e.peersSliceLocked())
	peersOut = eval.Peers
	persistSnap, persistSeq = e.buildPersistedSnapshotLocked()
	e.mu.Unlock()

	if err := e.writePersistedSnapshot(persistSnap, persistSeq); err != nil {
		e.logf("warning: failed persisting cluster state after renewal of %s: %v", nodeID, err)
	}

	oldSerialRevoked := false
	if req.RevokeOldSerial && e.hasCAKey && e.caKey != nil && nodeID != e.nodeID {
		revoked, revErr := e.revokeSerialInClusterCRL(callerSerialHex, now)
		if revErr != nil {
			e.logf("warning: failed revoking old peer serial [%s] during renew of %s: %v", callerSerialHex, nodeID, revErr)
		} else {
			oldSerialRevoked = revoked
			// Refresh CRLNumber on self/peers snapshot after CRL bump, and ensure active
			// SignedPolicy remains verifiable against the updated CRL (re-signing with CA if needed).
			e.mu.Lock()
			if e.signedPolicy != nil && (policySignerMatchesSerial(e.signedPolicy, callerSerialHex) ||
				e.signedPolicy.Verify(e.caCert, e.caPool, e.crlWatcher) != nil) {
				if reSigned, reSignErr := e.reSignPolicyWithCALocked(e.signedPolicy, now); reSignErr == nil {
					e.signedPolicy = reSigned
					e.storePolicySnapshotLocked(reSigned.Policy)
				} else {
					e.logf("warning: failed re-signing cluster policy with Root CA after revoking %s [%s]: %v", nodeID, callerSerialHex, reSignErr)
				}
			}
			if e.signedPolicy != nil {
				polVer = e.signedPolicy.Policy.Version
				signedPolCopy = e.signedPolicy.Clone()
			}
			if p, ok := e.peers[nodeID]; ok && p != nil {
				p.CRLNumber = e.currentCRLNumberString()
				p.PolicyVersion = polVer
			}
			e.refreshSelfLocked(now)
			eval = EvaluateQuorum(e.nodeID, e.peersSliceLocked())
			peersOut = eval.Peers
			persistSnap, persistSeq = e.buildPersistedSnapshotLocked()
			e.mu.Unlock()
			_ = e.writePersistedSnapshot(persistSnap, persistSeq)
		}
	}

	e.triggerAsyncBroadcast(oldSerialRevoked)

	crlPEMBytes := e.crlWatcher.CRLPEM()
	return &RenewResponse{
		NodeID:           nodeID,
		OldCertSerialHex: callerSerialHex,
		CertSerialHex:    newSerialHex,
		IssuedCertPEM:    issuedCertPEM,
		CACertPEM:        e.caCertPEM,
		CRLPEM:           string(crlPEMBytes),
		OldSerialRevoked: oldSerialRevoked,
		JoinedAtUnix:     joinedAt,
		Incarnation:      incarnation,
		SignedPolicy:     signedPolCopy,
		Peers:            peersOut,
	}, http.StatusOK, nil
}

func (e *Engine) peerMatchesSerial(nodeID, serialHex string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	p, ok := e.peers[nodeID]
	return ok && p != nil && strings.EqualFold(strings.TrimSpace(p.CertSerialHex), strings.TrimSpace(serialHex))
}

func policySignerMatchesSerial(env *SignedPolicyEnvelope, serialHex string) bool {
	if env == nil || strings.TrimSpace(env.SignerCertPEM) == "" || strings.TrimSpace(serialHex) == "" {
		return false
	}
	cert, err := parseSingleCertificatePEM([]byte(env.SignerCertPEM))
	if err != nil || cert.IsCA || cert.SerialNumber == nil {
		return false
	}
	return strings.EqualFold(pki.FormatSerialHex(cert.SerialNumber), strings.TrimSpace(serialHex))
}

// reSignPolicyWithCALocked re-signs curEnv.Policy using the Root CA certificate and private key,
// advancing UpdatedAtUnix by at least +1 so ComparePolicyEnvelope(reSigned, curEnv) > 0 across all nodes.
// Caller must hold e.mu.Lock() and ensure e.hasCAKey && e.caKey != nil && curEnv != nil.
func (e *Engine) reSignPolicyWithCALocked(curEnv *SignedPolicyEnvelope, now time.Time) (*SignedPolicyEnvelope, error) {
	nextPol := curEnv.Policy
	nextUpdated := now.Unix()
	if nextUpdated <= curEnv.Policy.UpdatedAtUnix {
		nextUpdated = curEnv.Policy.UpdatedAtUnix + 1
	}
	nextPol.UpdatedAtUnix = nextUpdated
	return SignPolicyEnvelope(nextPol, e.nodeID, e.caCert, e.caKey)
}

func (e *Engine) revokeSerialInClusterCRL(serialHex string, now time.Time) (bool, error) {
	if !e.hasCAKey || e.caKey == nil || e.caCert == nil || e.crlWatcher == nil {
		return false, errors.New("Root CA private key or CRLWatcher unavailable")
	}
	targetSerial, err := pki.ParseSerialHex(serialHex)
	if err != nil {
		return false, err
	}

	existingCRL, err := pki.ParseAndVerifyCRL(e.crlWatcher.CRLPEM(), e.caCert)
	if err != nil {
		return false, fmt.Errorf("failed parsing active CRL: %w", err)
	}

	nextCRLNum := big.NewInt(1)
	if existingCRL.Number != nil && existingCRL.Number.Sign() > 0 {
		nextCRLNum = new(big.Int).Add(existingCRL.Number, big.NewInt(1))
	}

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
		nextUpdate = e.caCert.NotAfter
	}
	if !nextUpdate.After(now) {
		return false, errors.New("cannot issue updated CRL: Root CA certificate has expired")
	}

	tmpl := &x509.RevocationList{
		SignatureAlgorithm:        x509.ECDSAWithSHA256,
		RevokedCertificateEntries: entries,
		Number:                    nextCRLNum,
		ThisUpdate:                now.Add(-crlClockSkewLeeway),
		NextUpdate:                nextUpdate,
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, tmpl, e.caCert, e.caKey)
	if err != nil {
		return false, fmt.Errorf("failed signing updated CRL: %w", err)
	}
	crlPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: crlDER,
	})
	if _, _, err := e.crlWatcher.ApplyCRLPEM(crlPEM); err != nil {
		return false, fmt.Errorf("failed applying updated CRL: %w", err)
	}
	return true, nil
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

func (e *Engine) forwardRenewToAuthorityPeer(
	ctx context.Context,
	req RenewRequest,
	callerSerialHex string,
	callerCN string,
	observedRemoteIP string,
) (*RenewResponse, int, error) {
	candidates := e.authorityPeersForCSR()
	if len(candidates) == 0 {
		if strings.TrimSpace(req.CSRPEM) != "" {
			return nil, http.StatusBadRequest, errors.New(
				"cannot sign CSR on renew: no active cluster node holds Root CA private key (--ca-key); pass --ca-key on an authority node or pre-issue replacement server.crt and server.key with 'agent-bridge ca issue'",
			)
		}
		return nil, http.StatusBadRequest, errors.New(
			"cannot revoke old certificate serial on renew: no active cluster node holds Root CA private key (--ca-key)",
		)
	}

	reqCopy := req
	fwdPayload := signJoinForwardRequest{
		RenewRequest:     &reqCopy,
		CallerCertSerial: callerSerialHex,
		CallerCertCN:     callerCN,
		ObservedRemoteIP: observedRemoteIP,
	}
	encoded, err := json.Marshal(fwdPayload)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed encoding sign-join renew request: %w", err)
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
			apiErr := decodeClusterHTTPError(httpResp.StatusCode, respBytes, "authority peer rejected renew")
			if httpResp.StatusCode >= 400 && httpResp.StatusCode < 500 {
				return nil, httpResp.StatusCode, apiErr
			}
			lastErr = apiErr
			continue
		}

		var renewResp RenewResponse
		if unmarshalErr := json.Unmarshal(respBytes, &renewResp); unmarshalErr != nil {
			lastErr = unmarshalErr
			continue
		}

		if strings.TrimSpace(renewResp.CRLPEM) != "" && e.crlWatcher != nil {
			_, _, _ = e.crlWatcher.ApplyCRLPEM([]byte(renewResp.CRLPEM))
		}

		var verifiedRenewPol *SignedPolicyEnvelope
		if renewResp.SignedPolicy != nil {
			if err := renewResp.SignedPolicy.Verify(e.caCert, e.caPool, e.crlWatcher); err == nil {
				verifiedRenewPol = renewResp.SignedPolicy.Clone()
			}
		}

		now := time.Now().UTC()
		var persistSnap *persistedClusterState
		var persistSeq uint64
		var mergedPeers []PeerInfo

		e.mu.Lock()
		if verifiedRenewPol != nil && (e.signedPolicy == nil ||
			verifiedRenewPol.IsNewerThan(e.signedPolicy) ||
			e.signedPolicy.Verify(e.caCert, e.caPool, e.crlWatcher) != nil) {
			e.signedPolicy = verifiedRenewPol
			e.storePolicySnapshotLocked(verifiedRenewPol.Policy)
		}
		for _, p := range renewResp.Peers {
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
		if authPeer, ok := e.peers[peer.NodeID]; ok && authPeer != nil {
			authPeer.State = PeerAlive
			authPeer.LastSeenUnix = now.Unix()
		}

		e.refreshSelfLocked(now)
		eval := EvaluateQuorum(e.nodeID, e.peersSliceLocked())
		mergedPeers = eval.Peers
		persistSnap, persistSeq = e.buildPersistedSnapshotLocked()
		e.mu.Unlock()

		_ = e.writePersistedSnapshot(persistSnap, persistSeq)

		renewResp.Peers = mergedPeers
		e.triggerAsyncBroadcast(renewResp.OldSerialRevoked)
		return &renewResp, http.StatusOK, nil
	}

	if lastErr == nil {
		lastErr = errors.New("no reachable authority node with --ca-key")
	}
	return nil, http.StatusBadGateway, fmt.Errorf("failed forwarding renew to authority peer: %w", lastErr)
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

func signRenewPoP(priv *ecdsa.PrivateKey, oldSerialHex, nodeID, clusterAddr string) (string, error) {
	if priv == nil {
		return "", errors.New("private key is nil")
	}
	msg := renewPoPDomainPrefix + strings.ToLower(strings.TrimSpace(oldSerialHex)) + ":" + strings.TrimSpace(nodeID) + ":" + strings.TrimSpace(clusterAddr)
	digest := sha256.Sum256([]byte(msg))
	sigASN1, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sigASN1), nil
}

func verifyRenewPoP(cert *x509.Certificate, oldSerialHex, nodeID, clusterAddr, sigBase64 string) error {
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
	msg := renewPoPDomainPrefix + strings.ToLower(strings.TrimSpace(oldSerialHex)) + ":" + strings.TrimSpace(nodeID) + ":" + strings.TrimSpace(clusterAddr)
	digest := sha256.Sum256([]byte(msg))
	if !ecdsa.VerifyASN1(pub, digest[:], sigBytes) {
		return errors.New("ECDSA renew proof-of-possession signature mismatch")
	}
	return nil
}

func buildServerSideExtraSANs(
	observedRemoteIP string,
	normClusterAddr string,
	normExecAddr string,
	hostname string,
	reqExtraIPs []string,
	reqExtraDNS []string,
) (extraIPs []string, extraDNS []string) {
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
	for _, raw := range reqExtraIPs {
		for _, tok := range strings.Split(raw, ",") {
			if ip := net.ParseIP(strings.TrimSpace(tok)); ip != nil && !ip.IsUnspecified() {
				extraIPs = append(extraIPs, ip.String())
			}
		}
	}

	if trimmedHost := strings.TrimSpace(hostname); trimmedHost != "" && net.ParseIP(trimmedHost) == nil {
		extraDNS = append(extraDNS, trimmedHost)
		if dot := strings.IndexByte(trimmedHost, '.'); dot > 0 {
			if shortLabel := strings.TrimSpace(trimmedHost[:dot]); shortLabel != "" {
				extraDNS = append(extraDNS, shortLabel)
			}
		}
	}
	for _, raw := range reqExtraDNS {
		for _, tok := range strings.Split(raw, ",") {
			trimmed := strings.TrimSpace(tok)
			if trimmed != "" && net.ParseIP(trimmed) == nil {
				extraDNS = append(extraDNS, trimmed)
			}
		}
	}
	return extraIPs, extraDNS
}

func parseCSRCommonName(csrPEM []byte) (string, error) {
	block, rest := pem.Decode(csrPEM)
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		return "", errors.New("csr_pem does not contain a valid CERTIFICATE REQUEST PEM block")
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		return "", errors.New("csr_pem contains unexpected trailing data after CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("CSR signature verification failed: %w", err)
	}
	return strings.TrimSpace(csr.Subject.CommonName), nil
}

// CollectNodeSANs computes deduplicated IP and DNS Subject Alternative Names for a cluster/exec node,
// including `127.0.0.1`, `localhost`, concrete/CIDR bound IPs, AdvertiseAddr, ExecBindSpecs, Hostname
// (+ short label before first dot), ExtraIPs/ExtraDNSNames, and active host interface IPs when
// AutoInterfaceSANs is enabled or wildcard/CIDR bind selectors are present.
func CollectNodeSANs(opts NodeSANOptions) (ips []string, dnsNames []string) {
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
		if lower == "all" || lower == "*" || strings.Contains(lower, "/") {
			return
		}
		if _, exists := dnsSeen[lower]; !exists {
			dnsSeen[lower] = struct{}{}
			dnsNames = append(dnsNames, trimmed)
		}
	}

	addHostFromEndpoint := func(rawEp string) {
		for _, tok := range netbind.SplitTokens([]string{rawEp}) {
			trimmed := tok
			if idx := strings.Index(trimmed, "://"); idx != -1 {
				trimmed = trimmed[idx+3:]
			}
			if slash := strings.IndexByte(trimmed, '/'); slash != -1 {
				// CIDR token handled separately via HarvestSelectorConcreteIPs.
				continue
			}
			if host, _, err := net.SplitHostPort(trimmed); err == nil {
				if ip := net.ParseIP(host); ip != nil {
					addIP(host)
				} else {
					addDNS(host)
				}
				continue
			}
			trimmedUnbracket := strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]")
			if ip := net.ParseIP(trimmedUnbracket); ip != nil {
				addIP(trimmedUnbracket)
			} else {
				addDNS(trimmedUnbracket)
			}
		}
	}

	// Always include loopback SANs so local loopback administration (127.0.0.1:8444) validates cleanly.
	addIP("127.0.0.1")
	addDNS("localhost")

	provider := opts.InterfaceProvider
	if provider == nil {
		provider = netbind.OSInterfaceProvider()
	}

	for _, ip := range netbind.HarvestSelectorConcreteIPs(opts.ClusterBindSpecs, provider) {
		addIP(ip)
	}
	for _, spec := range opts.ClusterBindSpecs {
		addHostFromEndpoint(spec)
	}

	addHostFromEndpoint(opts.AdvertiseAddr)

	for _, ip := range netbind.HarvestSelectorConcreteIPs(opts.ExecBindSpecs, provider) {
		addIP(ip)
	}
	for _, spec := range opts.ExecBindSpecs {
		addHostFromEndpoint(spec)
	}

	autoHarvest := opts.AutoInterfaceSANs ||
		netbind.ContainsWildcardOrCIDR(opts.ClusterBindSpecs) ||
		netbind.ContainsWildcardOrCIDR(opts.ExecBindSpecs)
	if autoHarvest {
		if harvested, err := netbind.HarvestInterfaceIPs(provider); err == nil {
			for _, ip := range harvested {
				addIP(ip)
			}
		}
	}

	if trimmedHost := strings.TrimSpace(opts.Hostname); trimmedHost != "" {
		if ip := net.ParseIP(trimmedHost); ip != nil {
			addIP(trimmedHost)
		} else {
			addDNS(trimmedHost)
			if dot := strings.IndexByte(trimmedHost, '.'); dot > 0 {
				if shortLabel := strings.TrimSpace(trimmedHost[:dot]); shortLabel != "" {
					addDNS(shortLabel)
				}
			}
		}
	}

	for _, raw := range opts.ExtraIPs {
		for _, tok := range strings.Split(raw, ",") {
			addIP(tok)
		}
	}
	for _, raw := range opts.ExtraDNSNames {
		for _, tok := range strings.Split(raw, ",") {
			addDNS(tok)
		}
	}

	return ips, dnsNames
}

func collectNodeSANs(
	clusterBindAddr string,
	advertiseAddr string,
	execBindAddr string,
	hostname string,
	extraIPs []string,
	extraDNS []string,
) (ips []string, dnsNames []string) {
	return CollectNodeSANs(NodeSANOptions{
		ClusterBindSpecs:  []string{clusterBindAddr},
		AdvertiseAddr:     advertiseAddr,
		ExecBindSpecs:     []string{execBindAddr},
		Hostname:          hostname,
		ExtraIPs:          extraIPs,
		ExtraDNSNames:     extraDNS,
		AutoInterfaceSANs: true,
	})
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
