package cluster

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/pki"
	"github.com/kennyparsons/agent-bridge/internal/protocol"
)

const (
	defaultGossipInterval      = 1500 * time.Millisecond
	clusterHTTPReadHeaderLimit = 10 * time.Second
	clusterHTTPIdleTimeout     = 60 * time.Second
	clusterShutdownGrace       = 3 * time.Second
)

// Config configures a multi-node cluster control-plane Engine instance.
type Config struct {
	NodeID             string
	ClusterBindAddr    string
	AdvertiseAddr      string
	ExecAddr           string
	CertPath           string
	KeyPath            string
	CAPath             string
	CAKeyPath          string
	StatePath          string
	SeedPeers          []string
	CRLWatcher         *pki.CRLWatcher
	GossipInterval     time.Duration
	SuspectTimeout     time.Duration
	UnreachableTimeout time.Duration
	Logger             *log.Logger
}

// Engine implements the pure-Go TLS 1.3 TCP gossip mesh, topology-aware dynamic quorum/leadership
// evaluator, dual-mode cryptographic join authority, and monotonic CRL/ExecutionPolicy state machine.
type Engine struct {
	cfg       Config
	logger    *log.Logger
	nodeID    string
	hostname  string
	hasCAKey  bool
	statePath string
	seedAddrs []string

	caCert     *x509.Certificate
	caCertPEM  string
	caPool     *x509.CertPool
	caKey      *ecdsa.PrivateKey
	nodeCert   *x509.Certificate
	nodeKey    *ecdsa.PrivateKey
	crlWatcher *pki.CRLWatcher

	serverTLSConfig *tls.Config
	peerTransport   *http.Transport
	peerHTTPClient  *http.Client
	httpServer      *http.Server

	addrMu            sync.RWMutex
	boundAddr         string
	advertisedAddr    string
	explicitAdvertise bool
	execAddr          string

	readyOnce sync.Once
	readyCh   chan struct{}
	doneCh    chan struct{}

	rootCtx    context.Context
	cancelRoot context.CancelFunc

	started atomic.Bool
	closed  atomic.Bool

	bgMu sync.Mutex
	bgWG sync.WaitGroup

	joinMu sync.Mutex

	broadcastMu         sync.Mutex
	lastBroadcastCRLNum *big.Int

	mu              sync.RWMutex
	selfIncarnation uint64
	selfJoinedAt    int64
	peers           map[string]*PeerInfo
	lastContact     map[string]time.Time
	tokens          map[string]*TokenRecord
	signedPolicy    *SignedPolicyEnvelope
	stateSeq        uint64

	policySnap atomic.Pointer[protocol.ExecutionPolicy]

	persistMu        sync.Mutex
	lastPersistedSeq uint64

	closeOnce sync.Once
	closeErr  error
}

// NewEngine validates cfg, cross-checks PKI credentials against Root CA + CRLWatcher, restores any
// persisted cluster state from disk, attaches a hot-reload CRL broadcast listener, and prepares
// the TLS 1.3 control-plane HTTP server and peer mTLS transport.
func NewEngine(cfg Config) (*Engine, error) {
	rawBind := strings.TrimSpace(cfg.ClusterBindAddr)
	if rawBind == "" {
		return nil, errors.New("cluster bind address (ClusterBindAddr) is required")
	}
	normBind, err := normalizeBindOrAdvertiseAddr(rawBind, config.DefaultClusterPort, true)
	if err != nil {
		return nil, fmt.Errorf("invalid ClusterBindAddr %q: %w", cfg.ClusterBindAddr, err)
	}
	cfg.ClusterBindAddr = normBind

	explicitAdvertise := strings.TrimSpace(cfg.AdvertiseAddr) != ""
	var advertisedAddr string
	if explicitAdvertise {
		normAdv, advErr := normalizeBindOrAdvertiseAddr(cfg.AdvertiseAddr, config.DefaultClusterPort, true)
		if advErr != nil {
			return nil, fmt.Errorf("invalid AdvertiseAddr %q: %w", cfg.AdvertiseAddr, advErr)
		}
		advertisedAddr = normAdv
	} else {
		advertisedAddr = resolveAdvertisedFromBind(normBind)
	}

	var execAddr string
	if strings.TrimSpace(cfg.ExecAddr) != "" {
		normExec, execErr := normalizeBindOrAdvertiseAddr(cfg.ExecAddr, protocol.DefaultPort, true)
		if execErr != nil {
			return nil, fmt.Errorf("invalid ExecAddr %q: %w", cfg.ExecAddr, execErr)
		}
		execAddr = normExec
	}

	cfg.CertPath = strings.TrimSpace(cfg.CertPath)
	if cfg.CertPath == "" {
		return nil, errors.New("cluster CertPath is required")
	}
	cfg.KeyPath = strings.TrimSpace(cfg.KeyPath)
	if cfg.KeyPath == "" {
		return nil, errors.New("cluster KeyPath is required")
	}
	cfg.CAPath = strings.TrimSpace(cfg.CAPath)
	if cfg.CAPath == "" {
		return nil, errors.New("cluster CAPath is required")
	}
	if cfg.CRLWatcher == nil {
		return nil, errors.New("cluster CRLWatcher is required")
	}

	if cfg.GossipInterval <= 0 {
		cfg.GossipInterval = defaultGossipInterval
	}
	if cfg.SuspectTimeout <= 0 {
		cfg.SuspectTimeout = 3 * cfg.GossipInterval
	}
	if cfg.UnreachableTimeout <= 0 {
		cfg.UnreachableTimeout = 6 * cfg.GossipInterval
	}
	if cfg.UnreachableTimeout < cfg.SuspectTimeout {
		cfg.UnreachableTimeout = 2 * cfg.SuspectTimeout
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.New(os.Stderr, "[agent-bridge-cluster] ", log.LstdFlags)
	}

	nodeTLSCert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load cluster node X.509 keypair: %w", err)
	}
	if len(nodeTLSCert.Certificate) == 0 {
		return nil, errors.New("cluster node X.509 keypair contains no certificate")
	}
	leafCert, err := x509.ParseCertificate(nodeTLSCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse cluster node leaf certificate: %w", err)
	}
	nodeTLSCert.Leaf = leafCert

	nodeKey, err := pki.LoadPrivateKey(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load cluster node ECDSA private key: %w", err)
	}

	caCert, caPool, err := pki.LoadCACertPool(cfg.CAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load Root CA certificate pool: %w", err)
	}

	if _, err := pki.VerifyPeerCertDualEKU([][]byte{leafCert.Raw}, caPool, cfg.CRLWatcher); err != nil {
		return nil, fmt.Errorf("cluster node certificate failed verification: %w", err)
	}
	if !hasExtKeyUsage(leafCert, x509.ExtKeyUsageServerAuth) {
		return nil, errors.New("cluster node certificate must possess ServerAuth extended key usage")
	}

	// Ensure Root CA DER is appended in the TLS handshake chain so Mode A BootstrapJoin clients
	// without ca.crt on disk can cryptographically verify the seed chain against token.CAFingerprint.
	hasCAInChain := false
	for _, rawCert := range nodeTLSCert.Certificate {
		if bytes.Equal(rawCert, caCert.Raw) {
			hasCAInChain = true
			break
		}
	}
	if !hasCAInChain {
		nodeTLSCert.Certificate = append(nodeTLSCert.Certificate, caCert.Raw)
	}

	caCertPEMBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caCert.Raw,
	})

	var (
		hasCAKey bool
		caKey    *ecdsa.PrivateKey
	)
	if trimmedCAKey := strings.TrimSpace(cfg.CAKeyPath); trimmedCAKey != "" {
		_, loadedCAKey, caKeyErr := pki.LoadCAKeyPair(cfg.CAPath, trimmedCAKey)
		if caKeyErr != nil {
			return nil, fmt.Errorf("failed to load Root CA private key %q: %w", trimmedCAKey, caKeyErr)
		}
		hasCAKey = true
		caKey = loadedCAKey
	}

	hostname, _ := os.Hostname()
	hostname = strings.TrimSpace(hostname)

	nodeID := strings.TrimSpace(cfg.NodeID)
	if nodeID == "" {
		nodeID = strings.TrimSpace(leafCert.Subject.CommonName)
	}
	if nodeID == "" {
		nodeID = hostname
	}
	if nodeID == "" {
		nodeID = "node-1"
	}
	cfg.NodeID = nodeID

	statePath := strings.TrimSpace(cfg.StatePath)
	if statePath == "" {
		statePath = DefaultStatePath(cfg.CRLWatcher.CRLPath(), nodeID)
	}
	cfg.StatePath = statePath

	var seedAddrs []string
	seedSeen := make(map[string]struct{})
	for _, rawSeed := range cfg.SeedPeers {
		for _, tok := range strings.Split(rawSeed, ",") {
			trimmed := strings.TrimSpace(tok)
			if trimmed == "" {
				continue
			}
			normSeed, _, seedErr := config.NormalizeClusterAddr(trimmed)
			if seedErr != nil {
				return nil, fmt.Errorf("invalid seed peer address %q: %w", trimmed, seedErr)
			}
			if _, exists := seedSeen[normSeed]; !exists {
				seedSeen[normSeed] = struct{}{}
				seedAddrs = append(seedAddrs, normSeed)
			}
		}
	}

	rootCtx, cancelRoot := context.WithCancel(context.Background())

	eng := &Engine{
		cfg:                 cfg,
		logger:              logger,
		nodeID:              nodeID,
		hostname:            hostname,
		hasCAKey:            hasCAKey,
		statePath:           statePath,
		seedAddrs:           seedAddrs,
		caCert:              caCert,
		caCertPEM:           string(caCertPEMBytes),
		caPool:              caPool,
		caKey:               caKey,
		nodeCert:            leafCert,
		nodeKey:             nodeKey,
		crlWatcher:          cfg.CRLWatcher,
		boundAddr:           cfg.ClusterBindAddr,
		advertisedAddr:      advertisedAddr,
		explicitAdvertise:   explicitAdvertise,
		execAddr:            execAddr,
		readyCh:             make(chan struct{}),
		doneCh:              make(chan struct{}),
		rootCtx:             rootCtx,
		cancelRoot:          cancelRoot,
		lastBroadcastCRLNum: cfg.CRLWatcher.CRLNumber(),
		peers:               make(map[string]*PeerInfo),
		lastContact:         make(map[string]time.Time),
		tokens:              make(map[string]*TokenRecord),
	}

	emptyPol := protocol.ExecutionPolicy{}
	eng.policySnap.Store(&emptyPol)

	now := time.Now().UTC()
	persisted, err := loadPersistedState(statePath)
	if err != nil {
		cancelRoot()
		return nil, err
	}

	eng.selfIncarnation = 1
	eng.selfJoinedAt = now.Unix()

	if persisted != nil {
		if persisted.Incarnation >= 1 {
			eng.selfIncarnation = persisted.Incarnation + 1
		}
		if persisted.JoinedAtUnix > 0 {
			eng.selfJoinedAt = persisted.JoinedAtUnix
		}
		if persisted.SignedPolicy != nil {
			if verifyErr := persisted.SignedPolicy.Verify(caCert, caPool, cfg.CRLWatcher); verifyErr == nil {
				eng.signedPolicy = persisted.SignedPolicy.Clone()
				eng.storePolicySnapshotLocked(eng.signedPolicy.Policy)
			} else {
				eng.logf("ignoring invalid persisted SignedPolicy in %q: %v", statePath, verifyErr)
			}
		}
		for _, p := range persisted.Peers {
			id := strings.TrimSpace(p.NodeID)
			if id == "" || id == nodeID {
				continue
			}
			cp := p.Clone()
			cp.IsSelf = false
			cp.IsLeader = false
			if eng.isPeerSerialRevoked(cp.CertSerialHex) {
				cp.State = PeerUnreachable
			}
			eng.peers[id] = &cp
			if cp.State == PeerAlive {
				eng.lastContact[id] = now
			}
		}
		cutoffUnix := now.Add(-tokenTombstoneRetention).Unix()
		for _, t := range persisted.Tokens {
			if t.IsValidStructure() && t.ExpiresAtUnix >= cutoffUnix {
				cp := t.Clone()
				eng.tokens[cp.TokenID] = &cp
			}
		}
	}

	eng.mu.Lock()
	eng.refreshSelfLocked(now)
	initialSnap, initialSeq := eng.buildPersistedSnapshotLocked()
	eng.mu.Unlock()

	if err := eng.writePersistedSnapshot(initialSnap, initialSeq); err != nil {
		cancelRoot()
		return nil, err
	}

	eng.serverTLSConfig = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		ClientAuth:   tls.RequestClientCert,
		ClientCAs:    caPool,
		Certificates: []tls.Certificate{nodeTLSCert},
		VerifyConnection: func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				// Allowed at TLS layer ONLY for unauthenticated /cluster/v1/join; all other endpoints enforce requireMTLS.
				return nil
			}
			rawCerts := certsToRawDER(cs.PeerCertificates)
			_, verifyErr := pki.VerifyPeerCertDualEKU(rawCerts, caPool, eng.crlWatcher)
			return verifyErr
		},
	}

	eng.peerTransport = &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			Certificates:       []tls.Certificate{nodeTLSCert},
			InsecureSkipVerify: true, // Strictly paired with VerifyPeerCertDualEKU in VerifyConnection below.
			VerifyConnection: func(cs tls.ConnectionState) error {
				rawCerts := certsToRawDER(cs.PeerCertificates)
				peerLeaf, verifyErr := pki.VerifyPeerCertDualEKU(rawCerts, caPool, eng.crlWatcher)
				if verifyErr != nil {
					return verifyErr
				}
				if !hasExtKeyUsage(peerLeaf, x509.ExtKeyUsageServerAuth) {
					return errors.New("TLS Handshake Rejected: cluster peer server certificate lacks ServerAuth extended key usage")
				}
				return nil
			},
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        64,
		MaxIdleConnsPerHost: 8,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
	}

	eng.peerHTTPClient = &http.Client{
		Transport: &peerCRLRoundTripper{
			engine: eng,
			base:   eng.peerTransport,
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc(pathClusterJoin, eng.handleJoin)
	mux.HandleFunc(pathClusterSignJoin, eng.requirePeerMTLS(eng.handleSignJoin))
	mux.HandleFunc(pathClusterSyncPush, eng.requirePeerMTLS(eng.handleSyncPush))
	mux.HandleFunc(pathClusterSyncPull, eng.requirePeerMTLS(eng.handleSyncPull))
	mux.HandleFunc(pathClusterStatus, eng.requireAdminMTLS(eng.handleStatus))
	mux.HandleFunc(pathClusterPeers, eng.requireAdminMTLS(eng.handlePeers))
	mux.HandleFunc(pathClusterTokens, eng.requireAdminMTLS(eng.handleCreateToken))
	mux.HandleFunc(pathClusterSync, eng.requireAdminMTLS(eng.handleSync))

	eng.httpServer = &http.Server{
		Handler:           mux,
		ErrorLog:          logger,
		ReadHeaderTimeout: clusterHTTPReadHeaderLimit,
		IdleTimeout:       clusterHTTPIdleTimeout,
	}

	cfg.CRLWatcher.AddReloadListener(eng.onCRLReload)

	return eng, nil
}

// Start binds the cluster TLS 1.3 TCP listener synchronously (updating Addr() and closing Ready())
// and launches the background control-plane HTTP server and SWIM/anti-entropy gossip loops.
// Canceling ctx triggers graceful shutdown via Close().
func (e *Engine) Start(ctx context.Context) error {
	if e == nil {
		return errors.New("cluster engine is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if e.closed.Load() {
		return errors.New("cluster engine is already closed")
	}
	if !e.started.CompareAndSwap(false, true) {
		return errors.New("cluster engine is already started")
	}

	ln, err := net.Listen("tcp", e.cfg.ClusterBindAddr)
	if err != nil {
		e.started.Store(false)
		return fmt.Errorf("failed to bind cluster listener on %s: %w", e.cfg.ClusterBindAddr, err)
	}

	actualBound := ln.Addr().String()
	e.addrMu.Lock()
	e.boundAddr = actualBound
	if !e.explicitAdvertise || !hasDialablePort(e.advertisedAddr) {
		e.advertisedAddr = resolveAdvertisedFromBind(actualBound)
	}
	advAddr := e.advertisedAddr
	e.addrMu.Unlock()

	now := time.Now().UTC()
	var persistSnap *persistedClusterState
	var persistSeq uint64
	e.mu.Lock()
	if curSelf, ok := e.peers[e.nodeID]; ok && curSelf != nil && curSelf.ClusterAddr != advAddr {
		e.selfIncarnation++
	}
	e.refreshSelfLocked(now)
	persistSnap, persistSeq = e.buildPersistedSnapshotLocked()
	e.mu.Unlock()
	_ = e.writePersistedSnapshot(persistSnap, persistSeq)

	tlsLn := tls.NewListener(ln, e.serverTLSConfig.Clone())

	e.readyOnce.Do(func() {
		close(e.readyCh)
	})

	// Watch caller context cancellation without registering in bgWG (otherwise Close -> bgWG.Wait
	// would deadlock waiting for this goroutine to return from Close).
	go func() {
		select {
		case <-ctx.Done():
			_ = e.Close()
		case <-e.rootCtx.Done():
		}
	}()

	// Serve HTTPS/mTLS 1.3 cluster API.
	if e.trackBgStart() {
		go func() {
			defer e.bgWG.Done()
			defer close(e.doneCh)
			if serveErr := e.httpServer.Serve(tlsLn); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
				if !e.closed.Load() {
					e.logf("cluster HTTPS server stopped with error: %v", serveErr)
				}
			}
		}()
	} else {
		_ = tlsLn.Close()
		close(e.doneCh)
	}

	// Start SWIM liveness + anti-entropy gossip loop.
	if e.trackBgStart() {
		go e.gossipLoop()
	}

	return nil
}

// Ready returns a channel closed as soon as Start has bound the cluster TLS 1.3 TCP listener.
func (e *Engine) Ready() <-chan struct{} {
	if e == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return e.readyCh
}

// Addr returns the cluster listener's bound "ip:port" address.
func (e *Engine) Addr() string {
	if e == nil {
		return ""
	}
	e.addrMu.RLock()
	defer e.addrMu.RUnlock()
	return e.boundAddr
}

// Wait blocks until the cluster HTTP server exits (via Close or parent context cancellation).
func (e *Engine) Wait() error {
	if e == nil {
		return nil
	}
	<-e.doneCh
	return e.closeErr
}

// Close gracefully shuts down the cluster HTTP server, cancels all background gossip/sync RPCs,
// and waits for background goroutines to exit cleanly. Note: Close does NOT close the shared
// CRLWatcher passed in Config so local /ws/exec can manage its own lifecycle independently.
func (e *Engine) Close() error {
	if e == nil {
		return nil
	}
	e.closeOnce.Do(func() {
		e.bgMu.Lock()
		e.closed.Store(true)
		e.bgMu.Unlock()

		e.cancelRoot()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), clusterShutdownGrace)
		defer cancel()

		if e.httpServer != nil && e.started.Load() {
			if err := e.httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				e.closeErr = err
			}
		}

		if e.peerTransport != nil {
			e.peerTransport.CloseIdleConnections()
		}

		e.bgWG.Wait()
	})
	return e.closeErr
}

// ExecutionPolicy returns the active cryptographically verified ExecutionPolicy via a lock-free
// atomic pointer read suitable for synchronous per-request enforcement on /ws/exec.
func (e *Engine) ExecutionPolicy() protocol.ExecutionPolicy {
	if e == nil {
		return protocol.ExecutionPolicy{}
	}
	snap := e.policySnap.Load()
	if snap == nil {
		return protocol.ExecutionPolicy{}
	}
	out := *snap
	if len(snap.AllowedClients) > 0 {
		out.AllowedClients = append([]string(nil), snap.AllowedClients...)
	}
	return out
}

// Peers returns a deterministic, quorum-annotated snapshot of all known cluster members.
func (e *Engine) Peers() []PeerInfo {
	if e == nil {
		return nil
	}
	return e.Status().Peers
}

// Status computes the current topology-aware quorum state, coordinator election, CRL metadata,
// active ExecutionPolicy, and annotated peer roster.
func (e *Engine) Status() ClusterStatus {
	if e == nil {
		return ClusterStatus{}
	}

	crlNumStr := e.currentCRLNumberString()
	revokedCount := 0
	if e.crlWatcher != nil {
		revokedCount = e.crlWatcher.RevokedCount()
	}

	e.mu.RLock()
	rawPeers := e.peersSliceLocked()
	e.mu.RUnlock()

	for i := range rawPeers {
		if rawPeers[i].NodeID == e.nodeID {
			rawPeers[i].ClusterAddr = e.currentAdvertisedAddr()
			rawPeers[i].CRLNumber = crlNumStr
		} else if e.isPeerSerialRevoked(rawPeers[i].CertSerialHex) {
			rawPeers[i].State = PeerUnreachable
		}
	}

	eval := EvaluateQuorum(e.nodeID, rawPeers)
	pol := e.ExecutionPolicy()

	return ClusterStatus{
		NodeID:         e.nodeID,
		ClusterAddr:    e.currentAdvertisedAddr(),
		ExecAddr:       e.execAddr,
		Topology:       eval.Topology,
		QuorumState:    eval.QuorumState,
		HasQuorum:      eval.HasQuorum,
		TotalNodes:     eval.TotalNodes,
		AliveNodes:     eval.AliveNodes,
		QuorumRequired: eval.QuorumRequired,
		LeaderID:       eval.LeaderID,
		LeaderAddr:     eval.LeaderAddr,
		IsLeader:       eval.IsLeader,
		HasCAKey:       e.hasCAKey,
		CRLNumber:      crlNumStr,
		RevokedCerts:   revokedCount,
		Policy:         pol,
		Peers:          eval.Peers,
	}
}

// CreateJoinToken mints a single-use, Root-CA-pinned join token (`abjt1.<ca_sha256>.<id>.<secret>`),
// persists ONLY its salted SHA-256 hash record to disk, and replicates the hash record across peers.
// Rejects token creation with ErrNoQuorum when Topology == "multi-node-quorum" and HasQuorum == false.
func (e *Engine) CreateJoinToken(ttl time.Duration, boundNodeID string) (token string, expiresAt time.Time, err error) {
	if e == nil {
		return "", time.Time{}, errors.New("cluster engine is nil")
	}
	if e.closed.Load() {
		return "", time.Time{}, errors.New("cluster engine is closed")
	}

	status := e.Status()
	if status.Topology == TopologyMultiNodeQuorum && !status.HasQuorum {
		return "", time.Time{}, ErrNoQuorum
	}

	now := time.Now().UTC()
	rawToken, rec, exp, err := GenerateJoinToken(e.caCert, e.nodeID, boundNodeID, ttl, now)
	if err != nil {
		return "", time.Time{}, err
	}

	var persistSnap *persistedClusterState
	var persistSeq uint64

	e.mu.Lock()
	e.pruneExpiredTokensLocked(now)
	recCopy := rec.Clone()
	e.tokens[recCopy.TokenID] = &recCopy
	persistSnap, persistSeq = e.buildPersistedSnapshotLocked()
	e.mu.Unlock()

	if err := e.writePersistedSnapshot(persistSnap, persistSeq); err != nil {
		return "", time.Time{}, err
	}

	e.triggerAsyncBroadcast(false)
	return rawToken, exp, nil
}

// Sync executes an immediate push/pull anti-entropy synchronization across all known peers,
// optionally applying a newer signed CRL PEM and/or signing and broadcasting an ExecutionPolicy update.
func (e *Engine) Sync(ctx context.Context, req SyncRequest) (*SyncResult, error) {
	if e == nil {
		return nil, errors.New("cluster engine is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if e.closed.Load() {
		return nil, errors.New("cluster engine is closed")
	}

	if e.crlWatcher != nil {
		_ = e.crlWatcher.ReloadNow()
	}

	crlApplied := false
	if strings.TrimSpace(req.CRLPEM) != "" {
		applied, _, err := e.crlWatcher.ApplyCRLPEM([]byte(req.CRLPEM))
		if err != nil {
			return nil, fmt.Errorf("invalid CRLPEM in SyncRequest: %w", err)
		}
		crlApplied = applied
	}

	policyUpdated := false
	if req.PolicyUpdate != nil {
		status := e.Status()
		if status.Topology == TopologyMultiNodeQuorum && !status.HasQuorum {
			return nil, ErrNoQuorum
		}

		now := time.Now().UTC()
		e.mu.RLock()
		var curVer uint64
		if e.signedPolicy != nil {
			curVer = e.signedPolicy.Policy.Version
		}
		e.mu.RUnlock()

		nextPol := *req.PolicyUpdate
		if nextPol.Version <= curVer {
			nextPol.Version = curVer + 1
		}
		if nextPol.UpdatedAtUnix <= 0 {
			nextPol.UpdatedAtUnix = now.Unix()
		}

		signerCert := e.nodeCert
		signerKey := e.nodeKey
		if e.hasCAKey && e.caKey != nil {
			signerCert = e.caCert
			signerKey = e.caKey
		}

		env, signErr := SignPolicyEnvelope(nextPol, e.nodeID, signerCert, signerKey)
		if signErr != nil {
			return nil, signErr
		}
		if verifyErr := env.Verify(e.caCert, e.caPool, e.crlWatcher); verifyErr != nil {
			return nil, fmt.Errorf("self-signed policy failed verification: %w", verifyErr)
		}

		var persistSnap *persistedClusterState
		var persistSeq uint64

		e.mu.Lock()
		if env.IsNewerThan(e.signedPolicy) {
			e.signedPolicy = env
			e.storePolicySnapshotLocked(env.Policy)
			e.refreshSelfLocked(now)
			policyUpdated = true
			persistSnap, persistSeq = e.buildPersistedSnapshotLocked()
		}
		e.mu.Unlock()

		if policyUpdated {
			if err := e.writePersistedSnapshot(persistSnap, persistSeq); err != nil {
				return nil, err
			}
		}
	}

	syncedPeers, failedPeers := e.syncAllPeersDetailed(ctx, true)
	finalStatus := e.Status()

	return &SyncResult{
		NodeID:        e.nodeID,
		CRLApplied:    crlApplied,
		CRLNumber:     finalStatus.CRLNumber,
		RevokedCerts:  finalStatus.RevokedCerts,
		PolicyUpdated: policyUpdated,
		PolicyVersion: finalStatus.Policy.Version,
		Policy:        finalStatus.Policy,
		SyncedPeers:   syncedPeers,
		FailedPeers:   failedPeers,
		Status:        finalStatus,
	}, nil
}

func (e *Engine) onCRLReload(crlPEM []byte, crlNum *big.Int) {
	if e == nil || e.closed.Load() || crlNum == nil {
		return
	}

	e.broadcastMu.Lock()
	if e.lastBroadcastCRLNum != nil && crlNum.Cmp(e.lastBroadcastCRLNum) <= 0 {
		e.broadcastMu.Unlock()
		return
	}
	e.lastBroadcastCRLNum = new(big.Int).Set(crlNum)
	e.broadcastMu.Unlock()

	now := time.Now().UTC()
	var persistSnap *persistedClusterState
	var persistSeq uint64
	changed := false

	e.mu.Lock()
	for id, p := range e.peers {
		if id == e.nodeID || p == nil {
			continue
		}
		if e.isPeerSerialRevoked(p.CertSerialHex) && p.State != PeerUnreachable {
			p.State = PeerUnreachable
			changed = true
		}
	}
	e.refreshSelfLocked(now)
	if changed {
		persistSnap, persistSeq = e.buildPersistedSnapshotLocked()
	}
	e.mu.Unlock()

	if changed {
		_ = e.writePersistedSnapshot(persistSnap, persistSeq)
	}

	if e.peerTransport != nil {
		e.peerTransport.CloseIdleConnections()
	}

	if len(crlPEM) > 0 {
		e.triggerAsyncBroadcast(true)
	}
}

func (e *Engine) validateMTLSPeerRequest(w http.ResponseWriter, r *http.Request) (*x509.Certificate, bool) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		writeJSONError(w, http.StatusUnauthorized, "TLS Handshake Rejected: mTLS client or peer certificate required")
		return nil, false
	}

	now := time.Now().UTC()
	leaf := r.TLS.PeerCertificates[0]
	if leaf == nil || leaf.IsCA {
		w.Header().Set("Connection", "close")
		writeJSONError(w, http.StatusForbidden, "TLS Handshake Rejected: invalid peer leaf certificate")
		return nil, false
	}
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		w.Header().Set("Connection", "close")
		writeJSONError(w, http.StatusForbidden, "TLS Handshake Rejected: client/peer certificate is expired or not yet valid")
		return nil, false
	}

	if e.crlWatcher != nil {
		for _, cert := range r.TLS.PeerCertificates {
			if cert != nil && cert.SerialNumber != nil && e.crlWatcher.IsRevoked(cert.SerialNumber) {
				w.Header().Set("Connection", "close")
				writeJSONError(
					w,
					http.StatusForbidden,
					fmt.Sprintf("TLS Handshake Rejected: Certificate Serial [%s] is Revoked", pki.FormatSerialHex(cert.SerialNumber)),
				)
				return nil, false
			}
		}
	}

	return leaf, true
}

// requirePeerMTLS guards internal peer-to-peer mesh routes (/sign-join, /sync-push, /sync-pull),
// strictly requiring an unrevoked certificate carrying ExtKeyUsageServerAuth (rejecting --type client certs).
func (e *Engine) requirePeerMTLS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		leaf, ok := e.validateMTLSPeerRequest(w, r)
		if !ok {
			return
		}
		if !hasExtKeyUsage(leaf, x509.ExtKeyUsageServerAuth) {
			writeJSONError(w, http.StatusForbidden, "cluster peer certificate with ServerAuth EKU required")
			return
		}
		next(w, r)
	}
}

// requireAdminMTLS guards operator/admin routes (/status, /peers, /tokens, /sync), admitting
// cluster peer/server certificates (ServerAuth EKU) and enforcing ExecutionPolicy.IsClientAllowed
// on ClientAuth-only certificates whenever EnforceClientACL is enabled.
func (e *Engine) requireAdminMTLS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		leaf, ok := e.validateMTLSPeerRequest(w, r)
		if !ok {
			return
		}
		if !hasExtKeyUsage(leaf, x509.ExtKeyUsageServerAuth) {
			pol := e.ExecutionPolicy()
			serialHex := pki.FormatSerialHex(leaf.SerialNumber)
			if !pol.IsClientAllowed(leaf.Subject.CommonName, serialHex) {
				writeJSONError(w, http.StatusForbidden, "client certificate is not authorized by cluster execution policy")
				return
			}
		}
		next(w, r)
	}
}

func (e *Engine) validatePeerSenderIdentity(
	senderNodeID string,
	senderJoinedAtUnix int64,
	tlsLeaf *x509.Certificate,
	tlsLeafSerialHex string,
) error {
	trimmedSender := strings.TrimSpace(senderNodeID)
	if trimmedSender == "" {
		return errors.New("gossip sender node_id cannot be empty")
	}
	if tlsLeaf == nil || tlsLeafSerialHex == "" {
		return errors.New("missing peer TLS leaf certificate")
	}

	localSerialHex := pki.FormatSerialHex(e.nodeCert.SerialNumber)
	if trimmedSender == e.nodeID && !strings.EqualFold(tlsLeafSerialHex, localSerialHex) {
		return fmt.Errorf("peer certificate serial %s cannot claim local engine node_id %q", tlsLeafSerialHex, e.nodeID)
	}

	e.mu.RLock()
	existing, exists := e.peers[trimmedSender]
	var existingSerial string
	var existingJoinedAt int64
	if exists && existing != nil {
		existingSerial = strings.TrimSpace(existing.CertSerialHex)
		existingJoinedAt = existing.JoinedAtUnix
	}
	e.mu.RUnlock()

	if existingSerial != "" && !strings.EqualFold(existingSerial, tlsLeafSerialHex) {
		leafCN := strings.TrimSpace(tlsLeaf.Subject.CommonName)
		if !(senderJoinedAtUnix > existingJoinedAt && leafCN == trimmedSender) {
			return fmt.Errorf(
				"peer certificate (CN=%q, serial=%s) cannot impersonate existing node %q (serial=%s)",
				leafCN, tlsLeafSerialHex, trimmedSender, existingSerial,
			)
		}
	}
	return nil
}

func (e *Engine) handleSyncPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var incoming GossipPayload
	if err := decodeJSONBody(w, r, &incoming); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid GossipPayload JSON: %v", err))
		return
	}

	leaf := r.TLS.PeerCertificates[0]
	tlsLeafSerialHex := pki.FormatSerialHex(leaf.SerialNumber)
	if err := e.validatePeerSenderIdentity(incoming.Sender.NodeID, incoming.Sender.JoinedAtUnix, leaf, tlsLeafSerialHex); err != nil {
		writeJSONError(w, http.StatusForbidden, err.Error())
		return
	}
	incoming.Sender.CertSerialHex = tlsLeafSerialHex

	e.mergeGossipPayload(r.Context(), incoming, incoming.Sender.NodeID, true)

	localCRLNum := e.currentCRLNumberString()
	includeCRL := localCRLNum != "" && incoming.CRLNumber != localCRLNum
	reply := e.buildGossipPayload(includeCRL)
	writeJSONResponse(w, http.StatusOK, reply)
}

func (e *Engine) handleSyncPull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	leaf := r.TLS.PeerCertificates[0]
	tlsLeafSerialHex := pki.FormatSerialHex(leaf.SerialNumber)
	localSerialHex := pki.FormatSerialHex(e.nodeCert.SerialNumber)
	if strings.TrimSpace(leaf.Subject.CommonName) == e.nodeID && !strings.EqualFold(tlsLeafSerialHex, localSerialHex) {
		writeJSONError(w, http.StatusForbidden, fmt.Sprintf("peer certificate serial %s cannot claim local engine node_id %q", tlsLeafSerialHex, e.nodeID))
		return
	}
	reply := e.buildGossipPayload(true)
	writeJSONResponse(w, http.StatusOK, reply)
}

func (e *Engine) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSONResponse(w, http.StatusOK, e.Status())
}

func (e *Engine) handlePeers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSONResponse(w, http.StatusOK, e.Peers())
}

func (e *Engine) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req TokenCreateRequest
	if r.ContentLength != 0 {
		if err := decodeJSONBody(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid TokenCreateRequest JSON: %v", err))
			return
		}
	}

	var ttl time.Duration
	if req.TTLSeconds < 0 {
		writeJSONError(w, http.StatusBadRequest, "ttl_seconds must be non-negative")
		return
	}
	if req.TTLSeconds > 0 {
		ttl = time.Duration(req.TTLSeconds) * time.Second
	}

	rawTok, exp, err := e.CreateJoinToken(ttl, req.BoundNodeID)
	if err != nil {
		if errors.Is(err, ErrNoQuorum) {
			writeJSONError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	parsed, _ := ParseJoinToken(rawTok)
	var tokID, caFP string
	if parsed != nil {
		tokID = parsed.TokenID
		caFP = parsed.CAFingerprint
	}

	writeJSONResponse(w, http.StatusOK, TokenCreateResponse{
		Token:         rawTok,
		TokenID:       tokID,
		CAFingerprint: caFP,
		BoundNodeID:   strings.TrimSpace(req.BoundNodeID),
		CreatedByNode: e.nodeID,
		ExpiresAt:     exp,
		ExpiresAtUnix: exp.Unix(),
	})
}

func (e *Engine) handleSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req SyncRequest
	if r.ContentLength != 0 {
		if err := decodeJSONBody(w, r, &req); err != nil && !errors.Is(err, io.EOF) {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("invalid SyncRequest JSON: %v", err))
			return
		}
	}

	res, err := e.Sync(r.Context(), req)
	if err != nil {
		if errors.Is(err, ErrNoQuorum) {
			writeJSONError(w, http.StatusServiceUnavailable, err.Error())
			return
		}
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, res)
}

func (e *Engine) refreshSelfLocked(now time.Time) {
	var polVer uint64
	if e.signedPolicy != nil {
		polVer = e.signedPolicy.Policy.Version
	}
	if e.selfJoinedAt <= 0 {
		e.selfJoinedAt = now.Unix()
	}
	if e.selfIncarnation == 0 {
		e.selfIncarnation = 1
	}

	e.peers[e.nodeID] = &PeerInfo{
		NodeID:        e.nodeID,
		ClusterAddr:   e.currentAdvertisedAddr(),
		ExecAddr:      e.execAddr,
		Hostname:      e.hostname,
		CertSerialHex: pki.FormatSerialHex(e.nodeCert.SerialNumber),
		HasCAKey:      e.hasCAKey,
		Incarnation:   e.selfIncarnation,
		State:         PeerAlive,
		CRLNumber:     e.currentCRLNumberString(),
		PolicyVersion: polVer,
		JoinedAtUnix:  e.selfJoinedAt,
		LastSeenUnix:  now.Unix(),
	}
	e.lastContact[e.nodeID] = now
}

func (e *Engine) peersSliceLocked() []PeerInfo {
	out := make([]PeerInfo, 0, len(e.peers))
	for _, p := range e.peers {
		if p != nil {
			out = append(out, p.Clone())
		}
	}
	return out
}

func (e *Engine) storePolicySnapshotLocked(pol protocol.ExecutionPolicy) {
	cp := pol
	if len(pol.AllowedClients) > 0 {
		cp.AllowedClients = append([]string(nil), pol.AllowedClients...)
	}
	e.policySnap.Store(&cp)
}

func (e *Engine) pruneExpiredTokensLocked(now time.Time) {
	cutoffUnix := now.Add(-tokenTombstoneRetention).Unix()
	for id, rec := range e.tokens {
		if rec == nil || rec.ExpiresAtUnix < cutoffUnix {
			delete(e.tokens, id)
		}
	}
}

func (e *Engine) buildPersistedSnapshotLocked() (*persistedClusterState, uint64) {
	e.stateSeq++
	seq := e.stateSeq

	peers := make([]PeerInfo, 0, len(e.peers))
	for _, p := range e.peers {
		if p == nil {
			continue
		}
		cp := p.Clone()
		cp.IsSelf = false
		cp.IsLeader = false
		peers = append(peers, cp)
	}

	tokens := make([]TokenRecord, 0, len(e.tokens))
	for _, t := range e.tokens {
		if t != nil && t.IsValidStructure() {
			tokens = append(tokens, t.Clone())
		}
	}

	return &persistedClusterState{
		SchemaVersion: currentStateSchemaVersion,
		Bootstrapped:  true,
		NodeID:        e.nodeID,
		Incarnation:   e.selfIncarnation,
		JoinedAtUnix:  e.selfJoinedAt,
		SignedPolicy:  e.signedPolicy.Clone(),
		Peers:         peers,
		Tokens:        tokens,
	}, seq
}

func (e *Engine) writePersistedSnapshot(snap *persistedClusterState, seq uint64) error {
	if snap == nil || e.statePath == "" {
		return nil
	}
	e.persistMu.Lock()
	defer e.persistMu.Unlock()

	if seq <= e.lastPersistedSeq {
		return nil
	}
	if err := savePersistedState(e.statePath, snap); err != nil {
		return err
	}
	e.lastPersistedSeq = seq
	return nil
}

func (e *Engine) currentAdvertisedAddr() string {
	e.addrMu.RLock()
	defer e.addrMu.RUnlock()
	return e.advertisedAddr
}

func (e *Engine) currentCRLNumberString() string {
	if e == nil || e.crlWatcher == nil {
		return ""
	}
	num := e.crlWatcher.CRLNumber()
	if num == nil {
		return ""
	}
	return num.String()
}

func (e *Engine) isPeerSerialRevoked(serialHex string) bool {
	if e == nil || e.crlWatcher == nil || strings.TrimSpace(serialHex) == "" {
		return false
	}
	serial, err := pki.ParseSerialHex(serialHex)
	if err != nil {
		return false
	}
	return e.crlWatcher.IsRevoked(serial)
}

func (e *Engine) trackBgStart() bool {
	e.bgMu.Lock()
	defer e.bgMu.Unlock()
	if e.closed.Load() {
		return false
	}
	e.bgWG.Add(1)
	return true
}

func (e *Engine) logf(format string, args ...any) {
	if e != nil && e.logger != nil {
		e.logger.Printf(format, args...)
	}
}

func resolveAdvertisedFromBind(bindAddr string) string {
	host, portStr, err := net.SplitHostPort(bindAddr)
	if err != nil {
		return bindAddr
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsUnspecified() {
		if ip.To4() != nil {
			return net.JoinHostPort("127.0.0.1", portStr)
		}
		return net.JoinHostPort("::1", portStr)
	}
	if portNum, convErr := strconv.Atoi(portStr); convErr == nil {
		return net.JoinHostPort(host, strconv.Itoa(portNum))
	}
	return bindAddr
}

func certsToRawDER(certs []*x509.Certificate) [][]byte {
	raw := make([][]byte, 0, len(certs))
	for _, c := range certs {
		if c != nil && len(c.Raw) > 0 {
			raw = append(raw, c.Raw)
		}
	}
	return raw
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, dst any) error {
	limited := http.MaxBytesReader(w, r.Body, maxJoinBodyBytes)
	dec := json.NewDecoder(limited)
	return dec.Decode(dst)
}

func writeJSONResponse(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeJSONError(w http.ResponseWriter, statusCode int, msg string) {
	writeJSONResponse(w, statusCode, apiErrorResponse{Error: msg})
}

func decodeClusterHTTPError(statusCode int, body []byte, fallbackPrefix string) error {
	var apiErr apiErrorResponse
	if len(body) > 0 && json.Unmarshal(body, &apiErr) == nil && strings.TrimSpace(apiErr.Error) != "" {
		return fmt.Errorf("%s (HTTP %d): %s", fallbackPrefix, statusCode, apiErr.Error)
	}
	trimmed := strings.TrimSpace(string(body))
	if trimmed != "" {
		return fmt.Errorf("%s (HTTP %d): %s", fallbackPrefix, statusCode, trimmed)
	}
	return fmt.Errorf("%s (HTTP %d)", fallbackPrefix, statusCode)
}

// peerCRLRoundTripper wraps the cluster outbound *http.Transport so already-multiplexed HTTP/2
// connections to a newly-revoked peer are cut off at 0ms both before request transmission and
// before any response from a pooled connection is accepted.
type peerCRLRoundTripper struct {
	engine *Engine
	base   *http.Transport
}

func (rt *peerCRLRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt == nil || rt.base == nil {
		return nil, errors.New("peer transport is nil")
	}
	if rt.engine != nil && req != nil && req.URL != nil {
		if revokedSerial := rt.engine.revokedSerialForHost(req.URL.Host); revokedSerial != "" {
			rt.base.CloseIdleConnections()
			return nil, fmt.Errorf("TLS Handshake Rejected: Certificate Serial [%s] is Revoked", revokedSerial)
		}
	}

	resp, err := rt.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	if rt.engine != nil && rt.engine.crlWatcher != nil && resp.TLS != nil {
		for _, cert := range resp.TLS.PeerCertificates {
			if cert != nil && cert.SerialNumber != nil && rt.engine.crlWatcher.IsRevoked(cert.SerialNumber) {
				_ = resp.Body.Close()
				rt.base.CloseIdleConnections()
				return nil, fmt.Errorf("TLS Handshake Rejected: Certificate Serial [%s] is Revoked", pki.FormatSerialHex(cert.SerialNumber))
			}
		}
	}
	return resp, nil
}

func (e *Engine) revokedSerialForHost(hostPort string) string {
	if e == nil || e.crlWatcher == nil || strings.TrimSpace(hostPort) == "" {
		return ""
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, p := range e.peers {
		if p == nil || p.NodeID == e.nodeID {
			continue
		}
		if p.ClusterAddr == hostPort && e.isPeerSerialRevoked(p.CertSerialHex) {
			return p.CertSerialHex
		}
	}
	return ""
}
