package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
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

	"github.com/gorilla/websocket"

	"github.com/kennyparsons/agent-bridge/internal/pki"
	"github.com/kennyparsons/agent-bridge/internal/protocol"
	"github.com/kennyparsons/agent-bridge/internal/runner"
)

const (
	wsReadBufferSize     = 4096
	wsWriteBufferSize    = 65536
	maxRequestFrameBytes = 1 << 20 // 1 MiB ceiling on incoming CommandRequest JSON frame

	httpReadHeaderTimeout = 15 * time.Second
	httpIdleTimeout       = 60 * time.Second
	requestReadTimeout    = 15 * time.Second
	responseWriteTimeout  = 30 * time.Second
	closeFrameTimeout     = 5 * time.Second
	closeDrainTimeout     = 100 * time.Millisecond
	gracefulShutdownWait  = 5 * time.Second
)

// PolicyProvider dynamically supplies the active cluster ExecutionPolicy per incoming command request.
type PolicyProvider interface {
	ExecutionPolicy() protocol.ExecutionPolicy
}

// Config defines the network binding, PKI assets, CRL path, optional shared cluster hooks,
// and execution shell for the daemon.
type Config struct {
	BindIP         string
	Port           int
	CertPath       string
	KeyPath        string
	CAPath         string
	CRLPath        string
	CRLWatcher     *pki.CRLWatcher
	PolicyProvider PolicyProvider
	Shell          string
	ShellExplicit  bool
	Logger         *log.Logger
}

// Server implements the mTLS 1.3 + hot-reloading CRL + transactional WebSocket command daemon.
type Server struct {
	cfg            Config
	logger         *log.Logger
	caCert         *x509.Certificate
	caPool         *x509.CertPool
	crlWatcher     *pki.CRLWatcher
	ownsCRLWatcher bool
	tlsConfig      *tls.Config
	httpServer     *http.Server
	upgrader       websocket.Upgrader

	addrMu    sync.RWMutex
	boundAddr string
	readyOnce sync.Once
	readyCh   chan struct{}

	execRootCtx    context.Context
	cancelExecRoot context.CancelFunc

	connMu      sync.Mutex
	closed      atomic.Bool
	activeConns sync.WaitGroup

	closeOnce sync.Once
	closeErr  error
}

// New validates Config, loads the server X.509 keypair and Root CA pool, and synchronously
// initializes and verifies the hot-reloading CRL watcher (failing fast before any socket opens
// if crl.pem is missing, malformed, expired, or forged).
func New(cfg Config) (*Server, error) {
	bindIP := strings.TrimSpace(cfg.BindIP)
	if bindIP == "" {
		return nil, errors.New("server bind IP (--bind) is required")
	}
	parsedIP := net.ParseIP(bindIP)
	if parsedIP == nil {
		return nil, fmt.Errorf("invalid server bind IP address %q", bindIP)
	}
	cfg.BindIP = bindIP

	if cfg.Port == 0 {
		cfg.Port = protocol.DefaultPort
	}
	if cfg.Port < 1 || cfg.Port > 65535 {
		return nil, fmt.Errorf("invalid server port %d: must be between 1 and 65535", cfg.Port)
	}

	cfg.CertPath = strings.TrimSpace(cfg.CertPath)
	if cfg.CertPath == "" {
		return nil, errors.New("server certificate path (--cert) is required")
	}
	cfg.KeyPath = strings.TrimSpace(cfg.KeyPath)
	if cfg.KeyPath == "" {
		return nil, errors.New("server private key path (--key) is required")
	}
	cfg.CAPath = strings.TrimSpace(cfg.CAPath)
	if cfg.CAPath == "" {
		return nil, errors.New("Root CA certificate path (--ca) is required")
	}
	cfg.CRLPath = strings.TrimSpace(cfg.CRLPath)
	if cfg.CRLPath == "" && cfg.CRLWatcher != nil {
		cfg.CRLPath = strings.TrimSpace(cfg.CRLWatcher.CRLPath())
	}
	if cfg.CRLPath == "" && cfg.CRLWatcher == nil {
		return nil, errors.New("CRL path (--crl) is required")
	}
	cfg.Shell = strings.TrimSpace(cfg.Shell)

	logger := cfg.Logger
	if logger == nil {
		logger = log.New(os.Stderr, "[agent-bridge] ", log.LstdFlags)
	}

	serverCert, err := tls.LoadX509KeyPair(cfg.CertPath, cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server X.509 keypair: %w", err)
	}
	if serverCert.Leaf == nil && len(serverCert.Certificate) > 0 {
		leaf, parseErr := x509.ParseCertificate(serverCert.Certificate[0])
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse server leaf certificate: %w", parseErr)
		}
		serverCert.Leaf = leaf
	}

	caCert, caPool, err := pki.LoadCACertPool(cfg.CAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load Root CA pool: %w", err)
	}

	execRootCtx, cancelExecRoot := context.WithCancel(context.Background())

	srv := &Server{
		cfg:            cfg,
		logger:         logger,
		caCert:         caCert,
		caPool:         caPool,
		boundAddr:      net.JoinHostPort(cfg.BindIP, strconv.Itoa(cfg.Port)),
		readyCh:        make(chan struct{}),
		execRootCtx:    execRootCtx,
		cancelExecRoot: cancelExecRoot,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  wsReadBufferSize,
			WriteBufferSize: wsWriteBufferSize,
			CheckOrigin: func(*http.Request) bool {
				return true
			},
		},
	}

	if cfg.CRLWatcher != nil {
		rawCRLPEM := cfg.CRLWatcher.CRLPEM()
		if len(rawCRLPEM) == 0 {
			cancelExecRoot()
			return nil, errors.New("shared CRLWatcher has no active CRL snapshot")
		}
		if _, verifyErr := pki.ParseAndVerifyCRL(rawCRLPEM, caCert); verifyErr != nil {
			cancelExecRoot()
			return nil, fmt.Errorf("shared CRLWatcher verification against Root CA failed: %w", verifyErr)
		}
		srv.crlWatcher = cfg.CRLWatcher
		srv.ownsCRLWatcher = false
	} else {
		crlWatcher, err := pki.NewCRLWatcher(
			cfg.CRLPath,
			caCert,
			func(revokedCount int, crlNum *big.Int) {
				srv.logf("CRL hot-reloaded: crl_number=%v revoked_serials=%d", crlNum, revokedCount)
			},
			func(watchErr error) {
				srv.logf("CRL reload error: %v", watchErr)
			},
		)
		if err != nil {
			cancelExecRoot()
			return nil, fmt.Errorf("CRL initialization failed: %w", err)
		}
		srv.crlWatcher = crlWatcher
		srv.ownsCRLWatcher = true
	}

	srv.tlsConfig = &tls.Config{
		MinVersion:            tls.VersionTLS13,
		ClientAuth:            tls.RequireAndVerifyClientCert,
		ClientCAs:             caPool,
		Certificates:          []tls.Certificate{serverCert},
		VerifyPeerCertificate: srv.crlWatcher.VerifyPeerCertChain(caCert),
	}

	mux := http.NewServeMux()
	mux.HandleFunc(protocol.ExecWSPath, srv.handleExecWS)

	srv.httpServer = &http.Server{
		Handler:           mux,
		ErrorLog:          logger,
		ReadHeaderTimeout: httpReadHeaderTimeout,
		IdleTimeout:       httpIdleTimeout,
	}

	return srv, nil
}

// Addr returns the listener's bound "ip:port" address (or the configured bind address prior to Serve).
func (s *Server) Addr() string {
	if s == nil {
		return ""
	}
	s.addrMu.RLock()
	defer s.addrMu.RUnlock()
	return s.boundAddr
}

// Ready returns a channel that is closed once the server has bound its TCP listener and started serving.
func (s *Server) Ready() <-chan struct{} {
	return s.readyCh
}

// CRLWatcher returns the server's active hot-reloading CRLWatcher.
func (s *Server) CRLWatcher() *pki.CRLWatcher {
	if s == nil {
		return nil
	}
	return s.crlWatcher
}

// ListenAndServe strictly binds TCP on Config.BindIP:Config.Port and serves mTLS 1.3 WebSocket requests
// until ctx is canceled or Close is called. Fails fast if the bind IP interface is down or unassignable.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if s == nil {
		return errors.New("server is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	listenAddr := net.JoinHostPort(s.cfg.BindIP, strconv.Itoa(s.cfg.Port))
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		_ = s.Close()
		return fmt.Errorf("failed to bind TCP listener on %s: %w", listenAddr, err)
	}

	return s.Serve(ctx, ln)
}

// Serve wraps ln with the server's strict mTLS 1.3 + CRL configuration and serves requests
// until ctx is canceled or Close is called.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	if s == nil {
		return errors.New("server is nil")
	}
	if ln == nil {
		_ = s.Close()
		return errors.New("listener cannot be nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if s.closed.Load() {
		_ = ln.Close()
		return http.ErrServerClosed
	}

	s.addrMu.Lock()
	s.boundAddr = ln.Addr().String()
	s.addrMu.Unlock()

	tlsLn := tls.NewListener(ln, s.tlsConfig.Clone())
	s.readyOnce.Do(func() {
		close(s.readyCh)
	})

	serveDoneCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = s.Close()
		case <-serveDoneCh:
		}
	}()

	serveErr := s.httpServer.Serve(tlsLn)
	close(serveDoneCh)

	closeErr := s.Close()

	if errors.Is(serveErr, http.ErrServerClosed) && (ctx.Err() != nil || s.closed.Load()) {
		return closeErr
	}
	if serveErr != nil {
		return serveErr
	}
	return closeErr
}

// Close initiates graceful HTTP/WebSocket shutdown, terminates any in-flight subprocesses,
// and closes the fsnotify CRL watcher. Safe to call multiple times concurrently.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.connMu.Lock()
		s.closed.Store(true)
		s.connMu.Unlock()

		s.cancelExecRoot()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), gracefulShutdownWait)
		defer cancel()

		var firstErr error
		if s.httpServer != nil {
			if err := s.httpServer.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
				firstErr = err
			}
		}

		wsDone := make(chan struct{})
		go func() {
			s.activeConns.Wait()
			close(wsDone)
		}()
		select {
		case <-wsDone:
		case <-shutdownCtx.Done():
		}

		if s.ownsCRLWatcher && s.crlWatcher != nil {
			if err := s.crlWatcher.Close(); err != nil && firstErr == nil {
				firstErr = err
			}
		}

		s.closeErr = firstErr
	})
	return s.closeErr
}

func (s *Server) trackConnStart() bool {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.closed.Load() {
		return false
	}
	s.activeConns.Add(1)
	return true
}

func (s *Server) handleExecWS(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != protocol.ExecWSPath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.trackConnStart() {
		http.Error(w, "server is shutting down", http.StatusServiceUnavailable)
		return
	}
	defer s.activeConns.Done()

	var activePolicy *protocol.ExecutionPolicy
	if s.cfg.PolicyProvider != nil {
		pol := s.cfg.PolicyProvider.ExecutionPolicy()
		activePolicy = &pol

		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0] == nil {
			s.logf("Client ACL Rejected from %s: missing verified mTLS client certificate", r.RemoteAddr)
			http.Error(w, "forbidden: missing client certificate", http.StatusForbidden)
			return
		}
		leaf := r.TLS.PeerCertificates[0]
		clientCN := leaf.Subject.CommonName
		serialHex := pki.FormatSerialHex(leaf.SerialNumber)
		if !pol.IsClientAllowed(clientCN, serialHex) {
			s.logf("Client ACL Rejected from %s: CN=%q Serial=[%s] denied by cluster policy (version=%d)", r.RemoteAddr, clientCN, serialHex, pol.Version)
			http.Error(w, fmt.Sprintf("forbidden: client certificate CN=%q Serial=[%s] is not authorized", clientCN, serialHex), http.StatusForbidden)
			return
		}
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logf("WebSocket upgrade failed from %s: %v", r.RemoteAddr, err)
		return
	}
	defer func() {
		_ = conn.Close()
	}()

	conn.SetReadLimit(maxRequestFrameBytes)
	_ = conn.SetReadDeadline(time.Now().Add(requestReadTimeout))

	msgType, rawPayload, err := conn.ReadMessage()
	if err != nil {
		if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
			s.logf("failed reading request frame from %s: %v", r.RemoteAddr, err)
		}
		return
	}
	// Clear read deadline for the execution phase; command lifetime is governed by execCtx/timeout.
	_ = conn.SetReadDeadline(time.Time{})

	if msgType != websocket.TextMessage {
		s.writeResponseAndClose(conn, protocol.CommandResponse{
			ExitCode: runner.ExitCodeInvalidRequest,
			Stderr:   "invalid websocket frame type: expected text message",
		}, nil)
		return
	}

	var req protocol.CommandRequest
	if err := json.Unmarshal(rawPayload, &req); err != nil {
		s.writeResponseAndClose(conn, protocol.CommandResponse{
			ExitCode: runner.ExitCodeInvalidRequest,
			Stderr:   fmt.Sprintf("malformed command request JSON: %v", err),
		}, nil)
		return
	}
	if strings.TrimSpace(req.Command) == "" {
		s.writeResponseAndClose(conn, protocol.CommandResponse{
			ExitCode: runner.ExitCodeInvalidRequest,
			Stderr:   "command cannot be empty",
		}, nil)
		return
	}

	execCtx, cancelExec := context.WithCancel(s.execRootCtx)
	defer cancelExec()

	var execFinished atomic.Bool
	var clientDisconnected atomic.Bool
	readerDone := make(chan struct{})

	go func() {
		defer close(readerDone)
		for {
			if _, _, readErr := conn.ReadMessage(); readErr != nil {
				if !execFinished.Load() {
					clientDisconnected.Store(true)
					cancelExec()
				}
				return
			}
		}
	}()

	var resp protocol.CommandResponse
	if activePolicy != nil {
		resp = runner.RunWithPolicy(execCtx, req, s.cfg.Shell, s.cfg.ShellExplicit, activePolicy)
	} else {
		resp = runner.Run(execCtx, req, s.cfg.Shell)
	}
	execFinished.Store(true)

	if clientDisconnected.Load() {
		<-readerDone
		return
	}

	s.writeResponseAndClose(conn, resp, readerDone)
}

func (s *Server) writeResponseAndClose(
	conn *websocket.Conn,
	resp protocol.CommandResponse,
	readerDone <-chan struct{},
) {
	payload, err := json.Marshal(resp)
	if err != nil {
		s.logf("failed to marshal CommandResponse: %v", err)
		if readerDone != nil {
			_ = conn.Close()
			<-readerDone
		}
		return
	}

	_ = conn.SetWriteDeadline(time.Now().Add(responseWriteTimeout))
	if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
		if readerDone != nil {
			_ = conn.Close()
			<-readerDone
		}
		return
	}

	closeMsg := websocket.FormatCloseMessage(websocket.CloseNormalClosure, "")
	_ = conn.WriteControl(websocket.CloseMessage, closeMsg, time.Now().Add(closeFrameTimeout))

	if readerDone != nil {
		_ = conn.SetReadDeadline(time.Now().Add(closeDrainTimeout))
		<-readerDone
	} else {
		_ = conn.SetReadDeadline(time.Now().Add(closeDrainTimeout))
		_, _, _ = conn.ReadMessage()
	}
}

func (s *Server) logf(format string, args ...any) {
	if s != nil && s.logger != nil {
		s.logger.Printf(format, args...)
	}
}
