package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/kennyparsons/agent-bridge/internal/netbind"
	"github.com/kennyparsons/agent-bridge/internal/pki"
	"github.com/kennyparsons/agent-bridge/internal/protocol"
	"github.com/kennyparsons/agent-bridge/internal/runner"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type testPKIFixture struct {
	caDir      string
	caRes      *pki.InitCAResult
	caPool     *x509.CertPool
	serverCert *pki.IssueCertResult
	clientCert *pki.IssueCertResult
}

func newTestPKIFixture(t *testing.T) *testPKIFixture {
	t.Helper()
	root := t.TempDir()
	caDir := filepath.Join(root, "ca")

	caRes, err := pki.InitCA(pki.InitCAOptions{
		OutDir:     caDir,
		CommonName: "Test-Agent-Bridge-Root-CA",
		Org:        "Test Automation",
		Years:      2,
	})
	if err != nil {
		t.Fatalf("InitCA failed: %v", err)
	}

	_, caPool, err := pki.LoadCACertPool(caRes.CACertPath)
	if err != nil {
		t.Fatalf("LoadCACertPool failed: %v", err)
	}

	srvCert, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:    caDir,
		OutDir:   filepath.Join(root, "server"),
		Type:     pki.TypeServer,
		Name:     "loopback-server",
		IPs:      []string{"127.0.0.1"},
		DNSNames: []string{"localhost"},
		Years:    1,
	})
	if err != nil {
		t.Fatalf("IssueCert(server) failed: %v", err)
	}

	cliCert, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  caDir,
		OutDir: filepath.Join(root, "client-default"),
		Type:   pki.TypeClient,
		Name:   "agent-operator",
		Years:  1,
	})
	if err != nil {
		t.Fatalf("IssueCert(client) failed: %v", err)
	}

	return &testPKIFixture{
		caDir:      caDir,
		caRes:      caRes,
		caPool:     caPool,
		serverCert: srvCert,
		clientCert: cliCert,
	}
}

func startTestServer(t *testing.T, fix *testPKIFixture) (*Server, *syncBuffer, context.CancelFunc, <-chan error) {
	t.Helper()
	logBuf := &syncBuffer{}
	logger := log.New(logBuf, "", 0)

	srv, err := New(Config{
		BindIP:   "127.0.0.1",
		Port:     protocol.DefaultPort,
		CertPath: fix.serverCert.CertPath,
		KeyPath:  fix.serverCert.KeyPath,
		CAPath:   fix.caRes.CACertPath,
		CRLPath:  fix.caRes.CRLPath,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = srv.Close()
		t.Fatalf("net.Listen(127.0.0.1:0) failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx, ln)
	}()

	select {
	case <-srv.Ready():
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("timed out waiting for server.Ready()")
	}

	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		select {
		case serveErr := <-errCh:
			if serveErr != nil {
				t.Errorf("unexpected server shutdown error: %v", serveErr)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("timed out waiting for server goroutine exit")
		}
	})

	return srv, logBuf, cancel, errCh
}

func newMTLSClientTLSConfig(t *testing.T, caPool *x509.CertPool, certPath, keyPath string) *tls.Config {
	t.Helper()
	kp, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		t.Fatalf("LoadX509KeyPair failed: %v", err)
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      caPool,
		Certificates: []tls.Certificate{kp},
	}
}

func dialWS(ctx context.Context, addr string, tlsCfg *tls.Config) (*websocket.Conn, *http.Response, error) {
	dialer := websocket.Dialer{
		TLSClientConfig:  tlsCfg,
		HandshakeTimeout: 5 * time.Second,
	}
	wsURL := fmt.Sprintf("wss://%s%s", addr, protocol.ExecWSPath)
	return dialer.DialContext(ctx, wsURL, nil)
}

func TestServerStartupFailFast(t *testing.T) {
	fix := newTestPKIFixture(t)

	t.Run("empty BindIP rejected", func(t *testing.T) {
		_, err := New(Config{
			BindIP:   "",
			CertPath: fix.serverCert.CertPath,
			KeyPath:  fix.serverCert.KeyPath,
			CAPath:   fix.caRes.CACertPath,
			CRLPath:  fix.caRes.CRLPath,
		})
		if err == nil {
			t.Fatal("expected error for empty BindIP")
		}
	})

	t.Run("malformed BindIP rejected", func(t *testing.T) {
		_, err := New(Config{
			BindIP:   "not-an-ip-address",
			CertPath: fix.serverCert.CertPath,
			KeyPath:  fix.serverCert.KeyPath,
			CAPath:   fix.caRes.CACertPath,
			CRLPath:  fix.caRes.CRLPath,
		})
		if err == nil {
			t.Fatal("expected error for malformed BindIP")
		}
	})

	t.Run("missing crl.pem rejected before socket bind", func(t *testing.T) {
		_, err := New(Config{
			BindIP:   "127.0.0.1",
			CertPath: fix.serverCert.CertPath,
			KeyPath:  fix.serverCert.KeyPath,
			CAPath:   fix.caRes.CACertPath,
			CRLPath:  filepath.Join(t.TempDir(), "nonexistent-crl.pem"),
		})
		if err == nil {
			t.Fatal("expected error for missing crl.pem")
		}
	})

	t.Run("crl.pem signed by wrong CA rejected", func(t *testing.T) {
		rogueCA, err := pki.InitCA(pki.InitCAOptions{
			OutDir:     filepath.Join(t.TempDir(), "rogue-ca"),
			CommonName: "Rogue-CA",
			Org:        "Rogue",
			Years:      1,
		})
		if err != nil {
			t.Fatalf("InitCA(rogue) failed: %v", err)
		}

		_, err = New(Config{
			BindIP:   "127.0.0.1",
			CertPath: fix.serverCert.CertPath,
			KeyPath:  fix.serverCert.KeyPath,
			CAPath:   fix.caRes.CACertPath,
			CRLPath:  rogueCA.CRLPath,
		})
		if err == nil {
			t.Fatal("expected error when crl.pem is signed by wrong CA")
		}
		if !strings.Contains(err.Error(), "signature") {
			t.Fatalf("expected signature verification error, got: %v", err)
		}
	})

	t.Run("unassignable BindIP fails fast on ListenAndServe", func(t *testing.T) {
		// 198.51.100.99 is RFC 5737 TEST-NET-2 documentation space and cannot be bound locally.
		srv, err := New(Config{
			BindIP:   "198.51.100.99",
			Port:     18443,
			CertPath: fix.serverCert.CertPath,
			KeyPath:  fix.serverCert.KeyPath,
			CAPath:   fix.caRes.CACertPath,
			CRLPath:  fix.caRes.CRLPath,
			Logger:   log.New(io.Discard, "", 0),
		})
		if err != nil {
			t.Fatalf("New failed unexpectedly: %v", err)
		}
		defer func() { _ = srv.Close() }()

		bindErr := srv.ListenAndServe(context.Background())
		if bindErr == nil {
			t.Fatal("expected ListenAndServe to fail fast on unassignable IP 198.51.100.99")
		}
	})

	t.Run("ListenAndServe binds explicit loopback port and shuts down cleanly", func(t *testing.T) {
		probeLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("probe listen failed: %v", err)
		}
		freePort := probeLn.Addr().(*net.TCPAddr).Port
		_ = probeLn.Close()

		srv, err := New(Config{
			BindIP:   "127.0.0.1",
			Port:     freePort,
			CertPath: fix.serverCert.CertPath,
			KeyPath:  fix.serverCert.KeyPath,
			CAPath:   fix.caRes.CACertPath,
			CRLPath:  fix.caRes.CRLPath,
			Logger:   log.New(io.Discard, "", 0),
		})
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		doneCh := make(chan error, 1)
		go func() {
			doneCh <- srv.ListenAndServe(ctx)
		}()

		select {
		case <-srv.Ready():
		case err := <-doneCh:
			t.Fatalf("ListenAndServe exited early: %v", err)
		case <-time.After(3 * time.Second):
			cancel()
			t.Fatal("timed out waiting for ListenAndServe Ready()")
		}

		wantAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort))
		if got := srv.Addr(); got != wantAddr {
			t.Fatalf("Addr() = %q, want %q", got, wantAddr)
		}

		cancel()
		select {
		case err := <-doneCh:
			if err != nil {
				t.Fatalf("ListenAndServe returned error on clean ctx cancel: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("ListenAndServe did not shut down within 3s")
		}
	})
}

func TestServerTransactionalWSExecAndWireFormatting(t *testing.T) {
	fix := newTestPKIFixture(t)
	srv, _, _, _ := startTestServer(t, fix)
	clientTLS := newMTLSClientTLSConfig(t, fix.caPool, fix.clientCert.CertPath, fix.clientCert.KeyPath)

	t.Run("exit 0 compact JSON omits stderr and closes 1000", func(t *testing.T) {
		wsConn, _, err := dialWS(context.Background(), srv.Addr(), clientTLS)
		if err != nil {
			t.Fatalf("dialWS failed: %v", err)
		}
		defer func() { _ = wsConn.Close() }()

		if err := wsConn.WriteJSON(protocol.CommandRequest{
			Command:        echoTrimTestCommand(),
			TimeoutSeconds: 10,
		}); err != nil {
			t.Fatalf("WriteJSON failed: %v", err)
		}

		msgType, rawFrame, err := wsConn.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage(response) failed: %v", err)
		}
		if msgType != websocket.TextMessage {
			t.Fatalf("message type = %d, want TextMessage (%d)", msgType, websocket.TextMessage)
		}
		if bytes.HasSuffix(rawFrame, []byte("\n")) {
			t.Fatalf("WebSocket JSON frame must not contain trailing newline: %q", string(rawFrame))
		}

		var rawMap map[string]any
		if err := json.Unmarshal(rawFrame, &rawMap); err != nil {
			t.Fatalf("json.Unmarshal(map) failed: %v", err)
		}
		if _, hasStderr := rawMap["stderr"]; hasStderr {
			t.Fatalf("expected 'stderr' key omitted on empty stderr, got frame: %s", string(rawFrame))
		}

		var resp protocol.CommandResponse
		if err := json.Unmarshal(rawFrame, &resp); err != nil {
			t.Fatalf("json.Unmarshal(CommandResponse) failed: %v", err)
		}
		if resp.ExitCode != 0 || resp.Stdout != "hello compact json" || resp.Stderr != "" {
			t.Fatalf("unexpected CommandResponse: %+v", resp)
		}

		// Next read MUST observe WebSocket CloseNormalClosure (1000).
		_, _, closeErr := wsConn.ReadMessage()
		if !websocket.IsCloseError(closeErr, websocket.CloseNormalClosure) {
			t.Fatalf("expected WebSocket CloseNormalClosure (1000), got: %v", closeErr)
		}
	})

	t.Run("exit 7 compact JSON omits stdout and closes 1000", func(t *testing.T) {
		wsConn, _, err := dialWS(context.Background(), srv.Addr(), clientTLS)
		if err != nil {
			t.Fatalf("dialWS failed: %v", err)
		}
		defer func() { _ = wsConn.Close() }()

		if err := wsConn.WriteJSON(protocol.CommandRequest{
			Command:        stderrExit7Command(),
			TimeoutSeconds: 10,
		}); err != nil {
			t.Fatalf("WriteJSON failed: %v", err)
		}

		_, rawFrame, err := wsConn.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage(response) failed: %v", err)
		}
		if bytes.HasSuffix(rawFrame, []byte("\n")) {
			t.Fatalf("WebSocket JSON frame must not contain trailing newline: %q", string(rawFrame))
		}

		var rawMap map[string]any
		if err := json.Unmarshal(rawFrame, &rawMap); err != nil {
			t.Fatalf("json.Unmarshal(map) failed: %v", err)
		}
		if _, hasStdout := rawMap["stdout"]; hasStdout {
			t.Fatalf("expected 'stdout' key omitted on empty stdout, got frame: %s", string(rawFrame))
		}

		var resp protocol.CommandResponse
		if err := json.Unmarshal(rawFrame, &resp); err != nil {
			t.Fatalf("json.Unmarshal(CommandResponse) failed: %v", err)
		}
		if resp.ExitCode != 7 || resp.Stdout != "" || resp.Stderr != "domain lookup failed" {
			t.Fatalf("unexpected CommandResponse: %+v", resp)
		}

		_, _, closeErr := wsConn.ReadMessage()
		if !websocket.IsCloseError(closeErr, websocket.CloseNormalClosure) {
			t.Fatalf("expected WebSocket CloseNormalClosure (1000), got: %v", closeErr)
		}
	})

	t.Run("non-/ws/exec path returns 404", func(t *testing.T) {
		httpClient := &http.Client{
			Transport: &http.Transport{TLSClientConfig: clientTLS.Clone()},
			Timeout:   5 * time.Second,
		}
		resp, err := httpClient.Get(fmt.Sprintf("https://%s/not-found", srv.Addr()))
		if err != nil {
			t.Fatalf("HTTP GET failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("StatusCode = %d, want 404", resp.StatusCode)
		}
	})

	t.Run("malformed JSON request returns ExitCode 2 and closes 1000", func(t *testing.T) {
		wsConn, _, err := dialWS(context.Background(), srv.Addr(), clientTLS)
		if err != nil {
			t.Fatalf("dialWS failed: %v", err)
		}
		defer func() { _ = wsConn.Close() }()

		if err := wsConn.WriteMessage(websocket.TextMessage, []byte("{broken-json")); err != nil {
			t.Fatalf("WriteMessage failed: %v", err)
		}
		_, rawFrame, err := wsConn.ReadMessage()
		if err != nil {
			t.Fatalf("ReadMessage failed: %v", err)
		}
		var resp protocol.CommandResponse
		if err := json.Unmarshal(rawFrame, &resp); err != nil {
			t.Fatalf("Unmarshal failed: %v", err)
		}
		if resp.ExitCode != 2 || resp.Stderr == "" {
			t.Fatalf("expected ExitCode 2 with diagnostic, got %+v", resp)
		}
		_, _, closeErr := wsConn.ReadMessage()
		if !websocket.IsCloseError(closeErr, websocket.CloseNormalClosure) {
			t.Fatalf("expected CloseNormalClosure (1000), got: %v", closeErr)
		}
	})
}

func TestServerMTLSAndTLS13Rejections(t *testing.T) {
	fix := newTestPKIFixture(t)
	srv, _, _, _ := startTestServer(t, fix)

	t.Run("unauthenticated client without client certificate rejected", func(t *testing.T) {
		noCertTLS := &tls.Config{
			MinVersion: tls.VersionTLS13,
			RootCAs:    fix.caPool,
		}
		wsConn, _, err := dialWS(context.Background(), srv.Addr(), noCertTLS)
		if err == nil {
			_ = wsConn.Close()
			t.Fatal("expected TLS handshake failure when client presents no certificate")
		}
	})

	t.Run("client certificate signed by untrusted CA rejected", func(t *testing.T) {
		rogueDir := t.TempDir()
		_, err := pki.InitCA(pki.InitCAOptions{
			OutDir:     filepath.Join(rogueDir, "ca"),
			CommonName: "Untrusted-CA",
			Org:        "Untrusted",
			Years:      1,
		})
		if err != nil {
			t.Fatalf("InitCA(rogue) failed: %v", err)
		}
		rogueClient, err := pki.IssueCert(pki.IssueCertOptions{
			CADir:  filepath.Join(rogueDir, "ca"),
			OutDir: filepath.Join(rogueDir, "client"),
			Type:   pki.TypeClient,
			Name:   "rogue-agent",
			Years:  1,
		})
		if err != nil {
			t.Fatalf("IssueCert(rogue client) failed: %v", err)
		}

		wrongCATLS := newMTLSClientTLSConfig(t, fix.caPool, rogueClient.CertPath, rogueClient.KeyPath)
		wsConn, _, err := dialWS(context.Background(), srv.Addr(), wrongCATLS)
		if err == nil {
			_ = wsConn.Close()
			t.Fatal("expected TLS handshake failure when client cert is signed by wrong CA")
		}
	})

	t.Run("TLS 1.2 maximum client rejected by TLS 1.3 enforcement", func(t *testing.T) {
		kp, err := tls.LoadX509KeyPair(fix.clientCert.CertPath, fix.clientCert.KeyPath)
		if err != nil {
			t.Fatalf("LoadX509KeyPair failed: %v", err)
		}
		tls12Only := &tls.Config{
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
			RootCAs:      fix.caPool,
			Certificates: []tls.Certificate{kp},
		}
		wsConn, _, err := dialWS(context.Background(), srv.Addr(), tls12Only)
		if err == nil {
			_ = wsConn.Close()
			t.Fatal("expected TLS handshake failure when client only supports TLS 1.2")
		}
	})
}

func TestServerLiveCRLHotReloadRevocation(t *testing.T) {
	fix := newTestPKIFixture(t)
	srv, logBuf, _, _ := startTestServer(t, fix)

	revokedTarget, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  fix.caDir,
		OutDir: filepath.Join(t.TempDir(), "client-to-revoke"),
		Type:   pki.TypeClient,
		Name:   "compromised-agent",
		Years:  1,
	})
	if err != nil {
		t.Fatalf("IssueCert(compromised-agent) failed: %v", err)
	}

	revokedTLS := newMTLSClientTLSConfig(t, fix.caPool, revokedTarget.CertPath, revokedTarget.KeyPath)
	healthyTLS := newMTLSClientTLSConfig(t, fix.caPool, fix.clientCert.CertPath, fix.clientCert.KeyPath)

	// 1. Pre-revocation sanity check: compromised-agent succeeds.
	wsConn, _, err := dialWS(context.Background(), srv.Addr(), revokedTLS)
	if err != nil {
		t.Fatalf("initial pre-revocation dialWS failed: %v", err)
	}
	if err := wsConn.WriteJSON(protocol.CommandRequest{Command: echoTrimTestCommand()}); err != nil {
		_ = wsConn.Close()
		t.Fatalf("WriteJSON failed: %v", err)
	}
	if _, _, err := wsConn.ReadMessage(); err != nil {
		_ = wsConn.Close()
		t.Fatalf("ReadMessage failed: %v", err)
	}
	_ = wsConn.Close()

	// 2. Revoke compromised-agent on disk while server continues running.
	if _, err := pki.RevokeCert(pki.RevokeCertOptions{
		CADir:  fix.caDir,
		Serial: revokedTarget.SerialHex,
		CRLOut: fix.caRes.CRLPath,
	}); err != nil {
		t.Fatalf("RevokeCert failed: %v", err)
	}

	// 3. Wait for atomic hot-reload via fsnotify (without restarting server).
	reloadDeadline := time.Now().Add(3 * time.Second)
	for !srv.CRLWatcher().IsRevoked(revokedTarget.Serial) {
		if time.Now().After(reloadDeadline) {
			t.Fatalf("CRLWatcher did not hot-reload revoked serial %s within 3s", revokedTarget.SerialHex)
		}
		time.Sleep(15 * time.Millisecond)
	}

	// 4. Subsequent connection with revoked certificate MUST be rejected at TLS handshake.
	badConn, _, dialErr := dialWS(context.Background(), srv.Addr(), revokedTLS)
	if dialErr == nil {
		_ = badConn.Close()
		t.Fatalf("expected revoked certificate %s to fail mTLS handshake", revokedTarget.SerialHex)
	}

	wantLogSubstr := fmt.Sprintf("TLS Handshake Rejected: Certificate Serial [%s] is Revoked", revokedTarget.SerialHex)
	logDeadline := time.Now().Add(time.Second)
	for !strings.Contains(logBuf.String(), wantLogSubstr) {
		if time.Now().After(logDeadline) {
			t.Fatalf("server TLS log missing %q; got logs:\n%s", wantLogSubstr, logBuf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}

	// 5. Non-revoked client certificate continues executing without interruption.
	okConn, _, err := dialWS(context.Background(), srv.Addr(), healthyTLS)
	if err != nil {
		t.Fatalf("non-revoked client failed after CRL hot-reload: %v", err)
	}
	defer func() { _ = okConn.Close() }()

	if err := okConn.WriteJSON(protocol.CommandRequest{Command: echoTrimTestCommand()}); err != nil {
		t.Fatalf("healthy client WriteJSON failed: %v", err)
	}
	_, rawResp, err := okConn.ReadMessage()
	if err != nil {
		t.Fatalf("healthy client ReadMessage failed: %v", err)
	}
	var resp protocol.CommandResponse
	if err := json.Unmarshal(rawResp, &resp); err != nil || resp.ExitCode != 0 {
		t.Fatalf("healthy client unexpected response: err=%v resp=%+v", err, resp)
	}
}

func TestServerMidCommandClientDisconnectKillsGrandchild(t *testing.T) {
	fix := newTestPKIFixture(t)
	srv, _, _, _ := startTestServer(t, fix)
	clientTLS := newMTLSClientTLSConfig(t, fix.caPool, fix.clientCert.CertPath, fix.clientCert.KeyPath)

	pidFile := filepath.Join(t.TempDir(), "ws-disconnect-grandchild.pid")

	wsConn, _, err := dialWS(context.Background(), srv.Addr(), clientTLS)
	if err != nil {
		t.Fatalf("dialWS failed: %v", err)
	}

	if err := wsConn.WriteJSON(protocol.CommandRequest{
		Command:        grandchildSleepCommand(pidFile),
		TimeoutSeconds: 30,
	}); err != nil {
		_ = wsConn.Close()
		t.Fatalf("WriteJSON failed: %v", err)
	}

	grandchildPID := waitForPIDFile(t, pidFile, 3*time.Second)

	// Abruptly drop the underlying client TCP/TLS connection mid-execution.
	_ = wsConn.UnderlyingConn().Close()
	_ = wsConn.Close()

	killElapsed := waitProcessDead(t, grandchildPID, time.Second)
	if killElapsed >= time.Second {
		t.Fatalf("grandchild kill took %v, expected < 1s", killElapsed)
	}
}

type dynamicPolicyProvider struct {
	cur atomic.Pointer[protocol.ExecutionPolicy]
}

func newDynamicPolicyProvider(initial protocol.ExecutionPolicy) *dynamicPolicyProvider {
	p := &dynamicPolicyProvider{}
	cp := initial
	p.cur.Store(&cp)
	return p
}

func (p *dynamicPolicyProvider) Set(next protocol.ExecutionPolicy) {
	cp := next
	p.cur.Store(&cp)
}

func (p *dynamicPolicyProvider) ExecutionPolicy() protocol.ExecutionPolicy {
	loaded := p.cur.Load()
	if loaded == nil {
		return protocol.ExecutionPolicy{}
	}
	return *loaded
}

func startCustomTestServer(t *testing.T, cfg Config) (*Server, *syncBuffer) {
	t.Helper()
	logBuf := &syncBuffer{}
	if cfg.Logger == nil {
		cfg.Logger = log.New(logBuf, "", 0)
	}
	if cfg.BindIP == "" {
		cfg.BindIP = "127.0.0.1"
	}

	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = srv.Close()
		t.Fatalf("net.Listen(127.0.0.1:0) failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ctx, ln)
	}()

	select {
	case <-srv.Ready():
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("timed out waiting for server.Ready()")
	}

	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		select {
		case serveErr := <-errCh:
			if serveErr != nil {
				t.Errorf("unexpected server shutdown error: %v", serveErr)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("timed out waiting for server goroutine exit")
		}
	})

	return srv, logBuf
}

func TestServerSharedCRLWatcherOwnership(t *testing.T) {
	fix := newTestPKIFixture(t)

	// 1. Reject shared CRLWatcher signed by a different CA.
	rogueDir := t.TempDir()
	rogueCARes, err := pki.InitCA(pki.InitCAOptions{
		OutDir:     filepath.Join(rogueDir, "ca"),
		CommonName: "Rogue-Cluster-CA",
		Org:        "Rogue",
		Years:      1,
	})
	if err != nil {
		t.Fatalf("InitCA(rogue) failed: %v", err)
	}
	rogueWatcher, err := pki.NewCRLWatcher(rogueCARes.CRLPath, rogueCARes.Certificate, nil, nil)
	if err != nil {
		t.Fatalf("NewCRLWatcher(rogue) failed: %v", err)
	}
	defer func() { _ = rogueWatcher.Close() }()

	if _, err := New(Config{
		BindIP:     "127.0.0.1",
		CertPath:   fix.serverCert.CertPath,
		KeyPath:    fix.serverCert.KeyPath,
		CAPath:     fix.caRes.CACertPath,
		CRLWatcher: rogueWatcher,
	}); err == nil {
		t.Fatal("expected New to reject shared CRLWatcher signed by wrong CA")
	}

	// 2. Borrowed CRLWatcher must NOT be closed when Server.Close() is called.
	sharedWatcher, err := pki.NewCRLWatcher(fix.caRes.CRLPath, fix.caRes.Certificate, nil, nil)
	if err != nil {
		t.Fatalf("NewCRLWatcher(shared) failed: %v", err)
	}
	defer func() { _ = sharedWatcher.Close() }()

	srv1, err := New(Config{
		BindIP:     "127.0.0.1",
		CertPath:   fix.serverCert.CertPath,
		KeyPath:    fix.serverCert.KeyPath,
		CAPath:     fix.caRes.CACertPath,
		CRLWatcher: sharedWatcher,
		Logger:     log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("New(srv1 with sharedWatcher) failed: %v", err)
	}

	ln1, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = srv1.Close()
		t.Fatalf("net.Listen failed: %v", err)
	}
	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan error, 1)
	go func() { done1 <- srv1.Serve(ctx1, ln1) }()
	<-srv1.Ready()

	clientTLS := newMTLSClientTLSConfig(t, fix.caPool, fix.clientCert.CertPath, fix.clientCert.KeyPath)
	ws1, _, err := dialWS(context.Background(), srv1.Addr(), clientTLS)
	if err != nil {
		t.Fatalf("dialWS(srv1) failed: %v", err)
	}
	_ = ws1.Close()

	// Shut down srv1 completely.
	cancel1()
	if err := srv1.Close(); err != nil {
		t.Fatalf("srv1.Close() failed: %v", err)
	}
	if err := <-done1; err != nil {
		t.Fatalf("srv1.Serve exit error: %v", err)
	}

	// Issue & revoke a certificate AFTER srv1.Close() and verify sharedWatcher's background
	// watchLoop is still alive and hot-reloading automatically!
	revokedAfterClose, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  fix.caDir,
		OutDir: filepath.Join(t.TempDir(), "revoked-after-srv1-close"),
		Type:   pki.TypeClient,
		Name:   "temp-agent",
		Years:  1,
	})
	if err != nil {
		t.Fatalf("IssueCert failed: %v", err)
	}
	if _, err := pki.RevokeCert(pki.RevokeCertOptions{
		CADir:  fix.caDir,
		Serial: revokedAfterClose.SerialHex,
		CRLOut: fix.caRes.CRLPath,
	}); err != nil {
		t.Fatalf("RevokeCert failed: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for !sharedWatcher.IsRevoked(revokedAfterClose.Serial) {
		if time.Now().After(deadline) {
			t.Fatalf("borrowed sharedWatcher stopped hot-reloading after srv1.Close()")
		}
		time.Sleep(15 * time.Millisecond)
	}

	// Spin up srv2 sharing the same sharedWatcher; verify revoked cert fails and healthy cert succeeds.
	srv2, _ := startCustomTestServer(t, Config{
		BindIP:     "127.0.0.1",
		CertPath:   fix.serverCert.CertPath,
		KeyPath:    fix.serverCert.KeyPath,
		CAPath:     fix.caRes.CACertPath,
		CRLWatcher: sharedWatcher,
	})
	revokedTLS := newMTLSClientTLSConfig(t, fix.caPool, revokedAfterClose.CertPath, revokedAfterClose.KeyPath)
	if badConn, _, dialErr := dialWS(context.Background(), srv2.Addr(), revokedTLS); dialErr == nil {
		_ = badConn.Close()
		t.Fatal("expected revoked cert to be rejected on srv2 using sharedWatcher")
	}
	okConn, _, err := dialWS(context.Background(), srv2.Addr(), clientTLS)
	if err != nil {
		t.Fatalf("healthy client failed on srv2: %v", err)
	}
	_ = okConn.Close()

	// 3. Contrast: an owned CRLWatcher (Config.CRLWatcher == nil) IS closed by Server.Close().
	ownedFix := newTestPKIFixture(t)
	srvOwned, err := New(Config{
		BindIP:   "127.0.0.1",
		CertPath: ownedFix.serverCert.CertPath,
		KeyPath:  ownedFix.serverCert.KeyPath,
		CAPath:   ownedFix.caRes.CACertPath,
		CRLPath:  ownedFix.caRes.CRLPath,
		Logger:   log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("New(srvOwned) failed: %v", err)
	}
	ownedWatcher := srvOwned.CRLWatcher()
	if err := srvOwned.Close(); err != nil {
		t.Fatalf("srvOwned.Close() failed: %v", err)
	}

	if _, err := pki.RevokeCert(pki.RevokeCertOptions{
		CADir:  ownedFix.caDir,
		Serial: ownedFix.clientCert.SerialHex,
		CRLOut: ownedFix.caRes.CRLPath,
	}); err != nil {
		t.Fatalf("RevokeCert(ownedFix) failed: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if ownedWatcher.IsRevoked(ownedFix.clientCert.Serial) {
		t.Fatal("expected owned CRLWatcher background watchLoop to be stopped after srvOwned.Close()")
	}
}

func TestServerDynamicPolicyProviderACLAndExecutionBounds(t *testing.T) {
	fix := newTestPKIFixture(t)

	aliceCert, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  fix.caDir,
		OutDir: filepath.Join(t.TempDir(), "alice"),
		Type:   pki.TypeClient,
		Name:   "alice-operator",
		Years:  1,
	})
	if err != nil {
		t.Fatalf("IssueCert(alice) failed: %v", err)
	}
	bobCert, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  fix.caDir,
		OutDir: filepath.Join(t.TempDir(), "bob"),
		Type:   pki.TypeClient,
		Name:   "bob-operator",
		Years:  1,
	})
	if err != nil {
		t.Fatalf("IssueCert(bob) failed: %v", err)
	}

	aliceTLS := newMTLSClientTLSConfig(t, fix.caPool, aliceCert.CertPath, aliceCert.KeyPath)
	bobTLS := newMTLSClientTLSConfig(t, fix.caPool, bobCert.CertPath, bobCert.KeyPath)

	// Start with ACL allowing only CN="alice-operator".
	policyHolder := newDynamicPolicyProvider(protocol.ExecutionPolicy{
		Version:          1,
		EnforceClientACL: true,
		AllowedClients:   []string{"alice-operator"},
	})

	srv, logBuf := startCustomTestServer(t, Config{
		BindIP:         "127.0.0.1",
		CertPath:       fix.serverCert.CertPath,
		KeyPath:        fix.serverCert.KeyPath,
		CAPath:         fix.caRes.CACertPath,
		CRLPath:        fix.caRes.CRLPath,
		PolicyProvider: policyHolder,
	})

	// 1. Unauthorized mTLS client (bob) is rejected before WebSocket upgrade with HTTP 403 Forbidden.
	bobConn, httpResp, bobErr := dialWS(context.Background(), srv.Addr(), bobTLS)
	if bobErr == nil {
		_ = bobConn.Close()
		t.Fatal("expected bob-operator to be rejected with HTTP 403 Forbidden")
	}
	if httpResp == nil || httpResp.StatusCode != http.StatusForbidden {
		status := 0
		if httpResp != nil {
			status = httpResp.StatusCode
		}
		t.Fatalf("bob HTTP status = %d, want 403 Forbidden (err=%v)", status, bobErr)
	}
	if httpResp.Body != nil {
		_ = httpResp.Body.Close()
	}
	if !strings.Contains(logBuf.String(), "Client ACL Rejected") {
		t.Fatalf("expected ACL denial log entry, got logs:\n%s", logBuf.String())
	}

	// 2. Authorized CN (alice) upgrades cleanly and executes.
	aliceConn, _, err := dialWS(context.Background(), srv.Addr(), aliceTLS)
	if err != nil {
		t.Fatalf("alice dialWS failed: %v", err)
	}
	if err := aliceConn.WriteJSON(protocol.CommandRequest{Command: echoTrimTestCommand()}); err != nil {
		_ = aliceConn.Close()
		t.Fatalf("alice WriteJSON failed: %v", err)
	}
	_, rawFrame, err := aliceConn.ReadMessage()
	_ = aliceConn.Close()
	if err != nil {
		t.Fatalf("alice ReadMessage failed: %v", err)
	}
	var aliceResp protocol.CommandResponse
	if err := json.Unmarshal(rawFrame, &aliceResp); err != nil || aliceResp.ExitCode != 0 {
		t.Fatalf("unexpected alice response: err=%v resp=%+v", err, aliceResp)
	}

	// 3. Dynamically update PolicyProvider (without restarting Server) to authorize bob by SerialHex
	// and enforce 1s DefaultTimeoutSeconds + 1s MaxTimeoutSeconds.
	policyHolder.Set(protocol.ExecutionPolicy{
		Version:               2,
		EnforceClientACL:      true,
		AllowedClients:        []string{strings.ToLower(bobCert.SerialHex)},
		DefaultTimeoutSeconds: 1,
		MaxTimeoutSeconds:     1,
	})

	// Alice is now immediately denied with 403 Forbidden.
	aliceDeniedConn, aliceHTTP, aliceDeniedErr := dialWS(context.Background(), srv.Addr(), aliceTLS)
	if aliceDeniedErr == nil {
		_ = aliceDeniedConn.Close()
		t.Fatal("expected alice to be denied after live policy update")
	}
	if aliceHTTP == nil || aliceHTTP.StatusCode != http.StatusForbidden {
		t.Fatalf("expected HTTP 403 for alice after policy update, got resp=%v err=%v", aliceHTTP, aliceDeniedErr)
	}
	if aliceHTTP.Body != nil {
		_ = aliceHTTP.Body.Close()
	}

	// Bob is now allowed by serial hex, and omitted timeout (0) uses policy DefaultTimeoutSeconds=1s.
	bobDefaultConn, _, err := dialWS(context.Background(), srv.Addr(), bobTLS)
	if err != nil {
		t.Fatalf("bob dialWS after policy update failed: %v", err)
	}
	start := time.Now()
	if err := bobDefaultConn.WriteJSON(protocol.CommandRequest{
		Command:        sleepFiveSecondsCommand(),
		TimeoutSeconds: 0,
	}); err != nil {
		_ = bobDefaultConn.Close()
		t.Fatalf("bob WriteJSON failed: %v", err)
	}
	_, bobTimeoutFrame, err := bobDefaultConn.ReadMessage()
	_ = bobDefaultConn.Close()
	if err != nil {
		t.Fatalf("bob ReadMessage failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("policy DefaultTimeoutSeconds=1 took %v, expected ~1s", elapsed)
	}
	var bobTimeoutResp protocol.CommandResponse
	if err := json.Unmarshal(bobTimeoutFrame, &bobTimeoutResp); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if bobTimeoutResp.ExitCode != runner.ExitCodeTimeout || !strings.Contains(bobTimeoutResp.Stderr, "command timed out after 1s") {
		t.Fatalf("expected 1s policy default timeout, got %+v", bobTimeoutResp)
	}

	// Bob requesting TimeoutSeconds=30 is clamped to policy MaxTimeoutSeconds=1s.
	bobClampConn, _, err := dialWS(context.Background(), srv.Addr(), bobTLS)
	if err != nil {
		t.Fatalf("bob dialWS(clamp) failed: %v", err)
	}
	start = time.Now()
	if err := bobClampConn.WriteJSON(protocol.CommandRequest{
		Command:        sleepFiveSecondsCommand(),
		TimeoutSeconds: 30,
	}); err != nil {
		_ = bobClampConn.Close()
		t.Fatalf("bob WriteJSON(clamp) failed: %v", err)
	}
	_, bobClampFrame, err := bobClampConn.ReadMessage()
	_ = bobClampConn.Close()
	if err != nil {
		t.Fatalf("bob ReadMessage(clamp) failed: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("policy MaxTimeoutSeconds=1 clamp took %v, expected ~1s", elapsed)
	}
	var bobClampResp protocol.CommandResponse
	if err := json.Unmarshal(bobClampFrame, &bobClampResp); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if bobClampResp.ExitCode != runner.ExitCodeTimeout || !strings.Contains(bobClampResp.Stderr, "command timed out after 1s") {
		t.Fatalf("expected 1s clamped timeout, got %+v", bobClampResp)
	}

	// 4. Verify ShellExplicit=true overrides policy.DefaultShell, whereas ShellExplicit=false uses policy.DefaultShell.
	policyHolder.Set(protocol.ExecutionPolicy{
		Version:          3,
		EnforceClientACL: false,
		DefaultShell:     "/nonexistent/replicated-policy-shell",
	})

	nonExplicitConn, _, err := dialWS(context.Background(), srv.Addr(), bobTLS)
	if err != nil {
		t.Fatalf("dialWS(nonExplicit) failed: %v", err)
	}
	if err := nonExplicitConn.WriteJSON(protocol.CommandRequest{Command: echoTrimTestCommand()}); err != nil {
		_ = nonExplicitConn.Close()
		t.Fatalf("WriteJSON failed: %v", err)
	}
	_, nonExplicitRaw, err := nonExplicitConn.ReadMessage()
	_ = nonExplicitConn.Close()
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}
	var nonExplicitResp protocol.CommandResponse
	if err := json.Unmarshal(nonExplicitRaw, &nonExplicitResp); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if nonExplicitResp.ExitCode != runner.ExitCodeExecError || !strings.Contains(nonExplicitResp.Stderr, "/nonexistent/replicated-policy-shell") {
		t.Fatalf("expected policy.DefaultShell when ShellExplicit=false, got %+v", nonExplicitResp)
	}

	srvExplicit, _ := startCustomTestServer(t, Config{
		BindIP:         "127.0.0.1",
		CertPath:       fix.serverCert.CertPath,
		KeyPath:        fix.serverCert.KeyPath,
		CAPath:         fix.caRes.CACertPath,
		CRLPath:        fix.caRes.CRLPath,
		PolicyProvider: policyHolder,
		Shell:          runner.DefaultShell(),
		ShellExplicit:  true,
	})
	explicitConn, _, err := dialWS(context.Background(), srvExplicit.Addr(), bobTLS)
	if err != nil {
		t.Fatalf("dialWS(srvExplicit) failed: %v", err)
	}
	if err := explicitConn.WriteJSON(protocol.CommandRequest{Command: echoTrimTestCommand()}); err != nil {
		_ = explicitConn.Close()
		t.Fatalf("WriteJSON failed: %v", err)
	}
	_, explicitRaw, err := explicitConn.ReadMessage()
	_ = explicitConn.Close()
	if err != nil {
		t.Fatalf("ReadMessage failed: %v", err)
	}
	var explicitResp protocol.CommandResponse
	if err := json.Unmarshal(explicitRaw, &explicitResp); err != nil || explicitResp.ExitCode != 0 {
		t.Fatalf("expected explicit local shell to succeed over policy.DefaultShell, err=%v resp=%+v", err, explicitResp)
	}
}

func waitForPIDFile(t *testing.T, pidFile string, maxWait time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(pidFile)
		if err == nil {
			trimmed := strings.TrimSpace(string(raw))
			if trimmed != "" {
				pid, parseErr := strconv.Atoi(trimmed)
				if parseErr == nil && pid > 0 {
					return pid
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for grandchild PID file %q", pidFile)
	return 0
}

type failingAcceptListener struct {
	addr    net.Addr
	failCh  chan error
	closeCh chan struct{}
	once    sync.Once
}

func newFailingAcceptListener(addr string) *failingAcceptListener {
	tcpAddr, _ := net.ResolveTCPAddr("tcp", addr)
	return &failingAcceptListener{
		addr:    tcpAddr,
		failCh:  make(chan error, 1),
		closeCh: make(chan struct{}),
	}
}

func (l *failingAcceptListener) Accept() (net.Conn, error) {
	select {
	case err := <-l.failCh:
		return nil, err
	case <-l.closeCh:
		return nil, net.ErrClosed
	}
}

func (l *failingAcceptListener) Close() error {
	l.once.Do(func() {
		close(l.closeCh)
	})
	return nil
}

func (l *failingAcceptListener) Addr() net.Addr {
	return l.addr
}

func TestServerMultiListenerServeAndBoundAddrs(t *testing.T) {
	fix := newTestPKIFixture(t)
	clientTLS := newMTLSClientTLSConfig(t, fix.caPool, fix.clientCert.CertPath, fix.clientCert.KeyPath)

	srv, err := New(Config{
		BindSpecs: []string{"127.0.0.1"},
		Port:      protocol.DefaultPort,
		CertPath:  fix.serverCert.CertPath,
		KeyPath:   fix.serverCert.KeyPath,
		CAPath:    fix.caRes.CACertPath,
		CRLPath:   fix.caRes.CRLPath,
		Logger:    log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}

	ln1, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = srv.Close()
		t.Fatalf("net.Listen #1 failed: %v", err)
	}
	ln2, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		_ = ln1.Close()
		_ = srv.Close()
		t.Fatalf("net.Listen #2 failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan error, 1)
	go func() {
		doneCh <- srv.ServeListeners(ctx, []net.Listener{ln1, ln2})
	}()

	select {
	case <-srv.Ready():
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("timed out waiting for multi-listener Ready()")
	}

	bound := srv.BoundAddrs()
	if len(bound) != 2 {
		cancel()
		t.Fatalf("BoundAddrs() len = %d (%v), want 2", len(bound), bound)
	}
	if srv.Addr() != bound[0] {
		cancel()
		t.Fatalf("Addr() = %q, want BoundAddrs()[0] = %q", srv.Addr(), bound[0])
	}

	// Execute a command over EACH bound listener to prove both listeners serve mTLS 1.3 traffic.
	for i, targetAddr := range bound {
		wsConn, _, dialErr := dialWS(context.Background(), targetAddr, clientTLS)
		if dialErr != nil {
			cancel()
			t.Fatalf("listener #%d (%s) dialWS failed: %v", i, targetAddr, dialErr)
		}
		if writeErr := wsConn.WriteJSON(protocol.CommandRequest{
			Command:        echoTrimTestCommand(),
			TimeoutSeconds: 10,
		}); writeErr != nil {
			_ = wsConn.Close()
			cancel()
			t.Fatalf("listener #%d WriteJSON failed: %v", i, writeErr)
		}
		_, rawFrame, readErr := wsConn.ReadMessage()
		_ = wsConn.Close()
		if readErr != nil {
			cancel()
			t.Fatalf("listener #%d ReadMessage failed: %v", i, readErr)
		}
		var resp protocol.CommandResponse
		if unmarshalErr := json.Unmarshal(rawFrame, &resp); unmarshalErr != nil || resp.ExitCode != 0 {
			cancel()
			t.Fatalf("listener #%d unexpected response: err=%v resp=%+v", i, unmarshalErr, resp)
		}
	}

	cancel()
	select {
	case serveErr := <-doneCh:
		if serveErr != nil {
			t.Fatalf("ServeListeners returned error on clean shutdown: %v", serveErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for ServeListeners shutdown")
	}
}

func TestServerBindSpecsDualStackAndUnexpectedListenerExit(t *testing.T) {
	fix := newTestPKIFixture(t)
	clientTLS := newMTLSClientTLSConfig(t, fix.caPool, fix.clientCert.CertPath, fix.clientCert.KeyPath)

	t.Run("BindSpecs 'all' dual-stack ListenAndServe", func(t *testing.T) {
		probe4, err := net.Listen("tcp4", "0.0.0.0:0")
		if err != nil {
			t.Fatalf("probe tcp4 listen failed: %v", err)
		}
		freePort := probe4.Addr().(*net.TCPAddr).Port
		_ = probe4.Close()

		// Ensure tcp6 is also free on that port if IPv6 is enabled.
		if probe6, err6 := net.Listen("tcp6", net.JoinHostPort("::", strconv.Itoa(freePort))); err6 == nil {
			_ = probe6.Close()
		}

		srv, err := New(Config{
			BindSpecs: []string{"all"},
			Port:      freePort,
			CertPath:  fix.serverCert.CertPath,
			KeyPath:   fix.serverCert.KeyPath,
			CAPath:    fix.caRes.CACertPath,
			CRLPath:   fix.caRes.CRLPath,
			Logger:    log.New(io.Discard, "", 0),
		})
		if err != nil {
			t.Fatalf("New(BindSpecs=['all']) failed: %v", err)
		}

		ctx, cancel := context.WithCancel(context.Background())
		doneCh := make(chan error, 1)
		go func() {
			doneCh <- srv.ListenAndServe(ctx)
		}()

		select {
		case <-srv.Ready():
		case err := <-doneCh:
			t.Fatalf("ListenAndServe(['all']) exited early: %v", err)
		case <-time.After(3 * time.Second):
			cancel()
			t.Fatal("timed out waiting for dual-stack Ready()")
		}

		if len(srv.BoundAddrs()) < 1 {
			cancel()
			t.Fatalf("expected at least 1 bound listener for 'all', got %v", srv.BoundAddrs())
		}

		loopbackTarget := net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort))
		wsConn, _, err := dialWS(context.Background(), loopbackTarget, clientTLS)
		if err != nil {
			cancel()
			t.Fatalf("dialWS(%s) against 'all' listener failed: %v", loopbackTarget, err)
		}
		_ = wsConn.Close()

		cancel()
		if err := <-doneCh; err != nil {
			t.Fatalf("ListenAndServe(['all']) shutdown error: %v", err)
		}
	})

	t.Run("WaitBind polls CIDR interface provider and shuts down cleanly on failure", func(t *testing.T) {
		var calls atomic.Int32
		emptyProvider := netbind.InterfaceProviderFunc(func() ([]netbind.InterfaceInfo, error) {
			calls.Add(1)
			return nil, nil
		})

		srv, err := New(Config{
			BindSpecs:         []string{"100.64.0.0/10"},
			WaitBind:          650 * time.Millisecond,
			InterfaceProvider: emptyProvider,
			Port:              18444,
			CertPath:          fix.serverCert.CertPath,
			KeyPath:           fix.serverCert.KeyPath,
			CAPath:            fix.caRes.CACertPath,
			CRLPath:           fix.caRes.CRLPath,
			Logger:            log.New(io.Discard, "", 0),
		})
		if err != nil {
			t.Fatalf("New(CIDR + WaitBind) failed: %v", err)
		}

		err = srv.ListenAndServe(context.Background())
		if err == nil || !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("expected WaitBind timeout error, got: %v", err)
		}
		if calls.Load() < 2 {
			t.Fatalf("expected at least 2 interface polls during 650ms WaitBind, got %d", calls.Load())
		}
	})

	t.Run("unexpected error on one listener closes sibling listeners cleanly", func(t *testing.T) {
		srv, err := New(Config{
			BindSpecs: []string{"127.0.0.1"},
			Port:      protocol.DefaultPort,
			CertPath:  fix.serverCert.CertPath,
			KeyPath:   fix.serverCert.KeyPath,
			CAPath:    fix.caRes.CACertPath,
			CRLPath:   fix.caRes.CRLPath,
			Logger:    log.New(io.Discard, "", 0),
		})
		if err != nil {
			t.Fatalf("New failed: %v", err)
		}

		healthyLn, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			_ = srv.Close()
			t.Fatalf("net.Listen failed: %v", err)
		}
		failingLn := newFailingAcceptListener("192.0.2.10:38443")

		doneCh := make(chan error, 1)
		go func() {
			doneCh <- srv.ServeListeners(context.Background(), []net.Listener{healthyLn, failingLn})
		}()

		<-srv.Ready()

		boomErr := errors.New("simulated listener hardware fault")
		failingLn.failCh <- boomErr

		select {
		case serveErr := <-doneCh:
			if !errors.Is(serveErr, boomErr) {
				t.Fatalf("ServeListeners error = %v, want %v", serveErr, boomErr)
			}
		case <-time.After(3 * time.Second):
			_ = srv.Close()
			t.Fatal("ServeListeners hung in partial-listener zombie state after one listener failed")
		}

		// Verify healthyLn was also closed automatically.
		if conn, dialErr := net.DialTimeout("tcp4", healthyLn.Addr().String(), 200*time.Millisecond); dialErr == nil {
			_ = conn.Close()
			t.Fatal("expected sibling healthyLn to be closed after failingLn faulted")
		}
	})
}
