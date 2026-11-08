package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/pki"
	"github.com/kennyparsons/agent-bridge/internal/protocol"
)

type trackingWriter struct {
	buf        bytes.Buffer
	writeCalls int
}

func (tw *trackingWriter) Write(p []byte) (int, error) {
	tw.writeCalls++
	return tw.buf.Write(p)
}

func (tw *trackingWriter) String() string {
	return tw.buf.String()
}

type testServerHarness struct {
	caDir      string
	caCertPath string
	crlPath    string
	watcher    *pki.CRLWatcher
	clientCert *pki.IssueCertResult
	port       string
	closeFn    func()
}

func startLoopbackMTLSServer(t *testing.T, handler func(req protocol.CommandRequest) protocol.CommandResponse) *testServerHarness {
	t.Helper()

	rootDir := t.TempDir()
	caDir := filepath.Join(rootDir, "pki")
	serverCertDir := filepath.Join(rootDir, "server")
	clientCertDir := filepath.Join(rootDir, "client")

	caRes, err := pki.InitCA(pki.InitCAOptions{
		OutDir:     caDir,
		CommonName: "Test-Agent-Bridge-Root-CA",
		Org:        "Agent-Bridge Test Suite",
		Years:      1,
	})
	if err != nil {
		t.Fatalf("InitCA failed: %v", err)
	}

	serverCertRes, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:    caDir,
		OutDir:   serverCertDir,
		Type:     pki.TypeServer,
		Name:     "loopback-server",
		IPs:      []string{"127.0.0.1"},
		DNSNames: []string{"localhost"},
		Years:    1,
	})
	if err != nil {
		t.Fatalf("IssueCert(server) failed: %v", err)
	}

	clientCertRes, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  caDir,
		OutDir: clientCertDir,
		Type:   pki.TypeClient,
		Name:   "test-agent-client",
		Years:  1,
	})
	if err != nil {
		t.Fatalf("IssueCert(client) failed: %v", err)
	}

	caCert, caPool, err := pki.LoadCACertPool(caRes.CACertPath)
	if err != nil {
		t.Fatalf("LoadCACertPool failed: %v", err)
	}

	watcher, err := pki.NewCRLWatcher(caRes.CRLPath, caCert, nil, nil)
	if err != nil {
		t.Fatalf("NewCRLWatcher failed: %v", err)
	}

	srvKeyPair, err := tls.LoadX509KeyPair(serverCertRes.CertPath, serverCertRes.KeyPath)
	if err != nil {
		_ = watcher.Close()
		t.Fatalf("LoadX509KeyPair(server) failed: %v", err)
	}

	tlsCfg := &tls.Config{
		MinVersion:            tls.VersionTLS13,
		MaxVersion:            tls.VersionTLS13,
		Certificates:          []tls.Certificate{srvKeyPair},
		ClientAuth:            tls.RequireAndVerifyClientCert,
		ClientCAs:             caPool,
		VerifyPeerCertificate: watcher.VerifyPeerCertificate,
	}

	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = watcher.Close()
		t.Fatalf("net.Listen failed: %v", err)
	}
	_, port, err := net.SplitHostPort(rawListener.Addr().String())
	if err != nil {
		_ = rawListener.Close()
		_ = watcher.Close()
		t.Fatalf("SplitHostPort failed: %v", err)
	}

	tlsListener := tls.NewListener(rawListener, tlsCfg)

	upgrader := websocket.Upgrader{
		CheckOrigin: func(*http.Request) bool { return true },
	}

	mux := http.NewServeMux()
	mux.HandleFunc(protocol.ExecWSPath, func(w http.ResponseWriter, r *http.Request) {
		conn, upErr := upgrader.Upgrade(w, r, nil)
		if upErr != nil {
			return
		}
		defer conn.Close()

		conn.SetReadLimit(1024 * 1024)
		_, rawReq, readErr := conn.ReadMessage()
		if readErr != nil {
			return
		}

		var cmdReq protocol.CommandRequest
		if jsonErr := json.Unmarshal(rawReq, &cmdReq); jsonErr != nil {
			return
		}

		resp := handler(cmdReq)
		resp.Stdout = protocol.SanitizeOutput(resp.Stdout)
		resp.Stderr = protocol.SanitizeOutput(resp.Stderr)

		respBytes, marshalErr := json.Marshal(resp)
		if marshalErr != nil {
			return
		}

		if writeErr := conn.WriteMessage(websocket.TextMessage, respBytes); writeErr != nil {
			return
		}

		_ = conn.WriteControl(
			websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
			time.Now().Add(2*time.Second),
		)
	})

	httpSrv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ErrorLog:          log.New(io.Discard, "", 0),
	}

	go func() {
		_ = httpSrv.Serve(tlsListener)
	}()

	closeFn := func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutdownCtx)
		_ = tlsListener.Close()
		_ = watcher.Close()
	}
	t.Cleanup(closeFn)

	return &testServerHarness{
		caDir:      caDir,
		caCertPath: caRes.CACertPath,
		crlPath:    caRes.CRLPath,
		watcher:    watcher,
		clientCert: clientCertRes,
		port:       port,
		closeFn:    closeFn,
	}
}

func (h *testServerHarness) clientConfigForHost(t *testing.T, host string) *config.ResolvedConfig {
	t.Helper()
	endpoint := net.JoinHostPort(host, h.port)
	hp, wsURL, err := config.NormalizeEndpoint(endpoint)
	if err != nil {
		t.Fatalf("NormalizeEndpoint(%q) failed: %v", endpoint, err)
	}
	return &config.ResolvedConfig{
		Endpoint:       hp,
		WSURL:          wsURL,
		CertPath:       h.clientCert.CertPath,
		KeyPath:        h.clientCert.KeyPath,
		CAPath:         h.caCertPath,
		Timeout:        30 * time.Second,
		TimeoutSeconds: 30,
	}
}

func TestClientRunExitZeroAndNonZero(t *testing.T) {
	t.Parallel()

	var (
		mu          sync.Mutex
		capturedReq protocol.CommandRequest
	)
	h := startLoopbackMTLSServer(t, func(req protocol.CommandRequest) protocol.CommandResponse {
		mu.Lock()
		capturedReq = req
		mu.Unlock()
		if req.Command == "fail-23" {
			return protocol.CommandResponse{
				ExitCode: 23,
				Stderr:   "  Object not found in directory  \r\n",
			}
		}
		return protocol.CommandResponse{
			ExitCode: 0,
			Stdout:   "  {\"SamAccountName\":\"jdoe\",\"Enabled\":true}  \n",
		}
	})

	cfg := h.clientConfigForHost(t, "127.0.0.1")

	// 1. Exit code 0: stdout receives trimmed text + single trailing newline; stderr untouched.
	var stdoutZero, stderrZero trackingWriter
	exitCode, err := Run(context.Background(), cfg, "Get-ADUser -Identity jdoe", &stdoutZero, &stderrZero)
	if err != nil {
		t.Fatalf("Run(exit 0) unexpected error: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	wantStdout := "{\"SamAccountName\":\"jdoe\",\"Enabled\":true}\n"
	if stdoutZero.String() != wantStdout {
		t.Errorf("stdout = %q, want %q", stdoutZero.String(), wantStdout)
	}
	if stderrZero.writeCalls != 0 || stderrZero.buf.Len() != 0 {
		t.Errorf("expected stderr untouched, got %d writes (%q)", stderrZero.writeCalls, stderrZero.String())
	}
	mu.Lock()
	gotTimeout := capturedReq.TimeoutSeconds
	mu.Unlock()
	if gotTimeout != 30 {
		t.Errorf("captured TimeoutSeconds = %d, want 30", gotTimeout)
	}

	// 2. Non-zero exit code (23): stderr written with clean trailing newline; stdout untouched.
	var stdoutFail, stderrFail trackingWriter
	exitCode, err = Run(context.Background(), cfg, "fail-23", &stdoutFail, &stderrFail)
	if err != nil {
		t.Fatalf("Run(exit 23) unexpected error: %v", err)
	}
	if exitCode != 23 {
		t.Fatalf("exitCode = %d, want 23", exitCode)
	}
	wantStderr := "Object not found in directory\n"
	if stderrFail.String() != wantStderr {
		t.Errorf("stderr = %q, want %q", stderrFail.String(), wantStderr)
	}
	if stdoutFail.writeCalls != 0 || stdoutFail.buf.Len() != 0 {
		t.Errorf("expected stdout untouched, got %d writes (%q)", stdoutFail.writeCalls, stdoutFail.String())
	}
}

func TestClientIPSANAndDNSSANConnections(t *testing.T) {
	t.Parallel()

	h := startLoopbackMTLSServer(t, func(req protocol.CommandRequest) protocol.CommandResponse {
		return protocol.CommandResponse{
			ExitCode: 0,
			Stdout:   "pong:" + req.Command,
		}
	})

	// Connect via IP SAN (127.0.0.1:<port>)
	ipCfg := h.clientConfigForHost(t, "127.0.0.1")
	respIP, err := Execute(context.Background(), ipCfg, "via-ip")
	if err != nil {
		t.Fatalf("Execute via IP SAN (127.0.0.1) failed: %v", err)
	}
	if respIP.ExitCode != 0 || respIP.Stdout != "pong:via-ip" {
		t.Fatalf("unexpected IP SAN response: %+v", respIP)
	}

	// Connect via DNS SAN (localhost:<port>)
	dnsCfg := h.clientConfigForHost(t, "localhost")
	respDNS, err := Execute(context.Background(), dnsCfg, "via-dns")
	if err != nil {
		t.Fatalf("Execute via DNS SAN (localhost) failed: %v", err)
	}
	if respDNS.ExitCode != 0 || respDNS.Stdout != "pong:via-dns" {
		t.Fatalf("unexpected DNS SAN response: %+v", respDNS)
	}
}

func TestClientHandshakeRejectsWrongCAAndRevokedCertificate(t *testing.T) {
	t.Parallel()

	h := startLoopbackMTLSServer(t, func(req protocol.CommandRequest) protocol.CommandResponse {
		return protocol.CommandResponse{
			ExitCode: 0,
			Stdout:   "allowed",
		}
	})

	validCfg := h.clientConfigForHost(t, "127.0.0.1")

	// Sanity-check valid handshake succeeds prior to revocation.
	if _, err := Execute(context.Background(), validCfg, "pre-check"); err != nil {
		t.Fatalf("initial valid mTLS Execute failed: %v", err)
	}

	// Case A: Client trusts an unrelated Root CA -> client rejects server certificate during TLS 1.3 handshake.
	rogueCADir := filepath.Join(t.TempDir(), "rogue-ca")
	rogueCA, err := pki.InitCA(pki.InitCAOptions{
		OutDir:     rogueCADir,
		CommonName: "Rogue-CA",
		Years:      1,
	})
	if err != nil {
		t.Fatalf("InitCA(rogue) failed: %v", err)
	}

	wrongCACfg := *validCfg
	wrongCACfg.CAPath = rogueCA.CACertPath
	if _, err := Execute(context.Background(), &wrongCACfg, "should-fail-ca"); err == nil {
		t.Fatal("expected TLS handshake failure with wrong CA, got nil")
	} else if !strings.Contains(strings.ToLower(err.Error()), "ca") && !strings.Contains(strings.ToLower(err.Error()), "authority") {
		t.Fatalf("expected actionable CA mismatch message, got: %v", err)
	}

	// Case B: Client presents a certificate signed by rogue CA -> server rejects client certificate.
	rogueClientDir := filepath.Join(t.TempDir(), "rogue-client")
	rogueClient, err := pki.IssueCert(pki.IssueCertOptions{
		CADir:  rogueCADir,
		OutDir: rogueClientDir,
		Type:   pki.TypeClient,
		Name:   "rogue-agent",
		Years:  1,
	})
	if err != nil {
		t.Fatalf("IssueCert(rogue-client) failed: %v", err)
	}
	untrustedClientCfg := *validCfg
	untrustedClientCfg.CertPath = rogueClient.CertPath
	untrustedClientCfg.KeyPath = rogueClient.KeyPath
	if _, err := Execute(context.Background(), &untrustedClientCfg, "should-fail-untrusted-client"); err == nil {
		t.Fatal("expected server rejection of untrusted client cert, got nil")
	}

	// Case C: Revoke the legitimate client certificate serial in the server's CRL and verify immediate rejection.
	if _, err := pki.RevokeCert(pki.RevokeCertOptions{
		CADir:  h.caDir,
		Serial: h.clientCert.SerialHex,
		CRLOut: h.crlPath,
	}); err != nil {
		t.Fatalf("RevokeCert failed: %v", err)
	}

	// Wait until watcher atomically hot-reloads the updated CRL snapshot.
	deadline := time.Now().Add(3 * time.Second)
	for !h.watcher.IsRevoked(h.clientCert.Serial) {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for CRLWatcher to reload revoked serial")
		}
		time.Sleep(15 * time.Millisecond)
	}

	if _, err := Execute(context.Background(), validCfg, "should-fail-revoked"); err == nil {
		t.Fatal("expected mTLS rejection for revoked client certificate, got nil")
	} else {
		msg := strings.ToLower(err.Error())
		if !strings.Contains(msg, "revoked") && !strings.Contains(msg, "bad certificate") && !strings.Contains(msg, "rejected") {
			t.Fatalf("expected actionable revocation/rejection error, got: %v", err)
		}
	}
}

func TestClientLarge9Point5MiBStdoutPayload(t *testing.T) {
	t.Parallel()

	// Construct a deterministic ~9.5 MiB payload with non-whitespace boundaries.
	const targetBytes = (9 * 1024 * 1024) + (512 * 1024) // 9.5 MiB (9,961,472 bytes)
	chunk := "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz+/"
	repeats := targetBytes / len(chunk)
	largePayload := strings.Repeat(chunk, repeats)
	if len(largePayload) != targetBytes {
		t.Fatalf("constructed payload size = %d, want %d", len(largePayload), targetBytes)
	}

	h := startLoopbackMTLSServer(t, func(req protocol.CommandRequest) protocol.CommandResponse {
		return protocol.CommandResponse{
			ExitCode: 0,
			Stdout:   largePayload,
		}
	})

	cfg := h.clientConfigForHost(t, "127.0.0.1")

	var stdoutBuf, stderrBuf trackingWriter
	exitCode, err := Run(context.Background(), cfg, "dump-9.5mib", &stdoutBuf, &stderrBuf)
	if err != nil {
		t.Fatalf("Run(9.5 MiB payload) failed: %v", err)
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0", exitCode)
	}
	if stdoutBuf.buf.Len() != len(largePayload)+1 {
		t.Fatalf("stdout byte length = %d, want %d (9.5 MiB + trailing newline)", stdoutBuf.buf.Len(), len(largePayload)+1)
	}
	gotOut := stdoutBuf.String()
	if !strings.HasSuffix(gotOut, "\n") {
		t.Fatal("expected trailing newline on stdout")
	}
	if gotOut[:len(largePayload)] != largePayload {
		t.Fatal("received 9.5 MiB stdout payload did not match transmitted bytes")
	}
	if stderrBuf.writeCalls != 0 {
		t.Errorf("expected 0 stderr writes, got %d", stderrBuf.writeCalls)
	}
}

func TestClientContextCancellationAndUnreachableEndpoint(t *testing.T) {
	t.Parallel()

	startedCh := make(chan struct{})
	releaseCh := make(chan struct{})
	defer close(releaseCh)

	h := startLoopbackMTLSServer(t, func(req protocol.CommandRequest) protocol.CommandResponse {
		close(startedCh)
		<-releaseCh
		return protocol.CommandResponse{ExitCode: 0}
	})

	cfg := h.clientConfigForHost(t, "127.0.0.1")

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-startedCh
		cancel()
	}()

	if _, err := Execute(ctx, cfg, "long-running"); err == nil {
		t.Fatal("expected cancellation error, got nil")
	} else if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected errors.Is(err, context.Canceled), got: %v", err)
	}

	// Verify actionable error when TCP endpoint is unreachable (connection refused).
	deadListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	deadAddr := deadListener.Addr().String()
	_ = deadListener.Close()

	_, deadWS, err := config.NormalizeEndpoint(deadAddr)
	if err != nil {
		t.Fatalf("NormalizeEndpoint: %v", err)
	}
	deadCfg := *cfg
	deadCfg.Endpoint = deadAddr
	deadCfg.WSURL = deadWS

	if _, err := Execute(context.Background(), &deadCfg, "ping"); err == nil {
		t.Fatal("expected error dialing closed port, got nil")
	} else if !strings.Contains(strings.ToLower(err.Error()), "unable to reach") {
		t.Fatalf("expected actionable unreachable daemon error, got: %v", err)
	}
}

func TestFormatTransportErrorWindowsWinSockRefused(t *testing.T) {
	winErr := errors.New("dial tcp 127.0.0.1:8443: connectex: No connection could be made because the target machine actively refused it.")
	got := formatTransportError("connecting to", "127.0.0.1:8443", winErr, nil)
	if got == nil {
		t.Fatal("expected non-nil formatted error")
	}
	if !strings.Contains(strings.ToLower(got.Error()), "unable to reach agent-bridge daemon") {
		t.Fatalf("expected actionable unreachable daemon error for WinSock connectex refusal, got: %v", got)
	}
	if !errors.Is(got, winErr) {
		t.Fatalf("expected wrapped underlying error, got: %v", got)
	}
}
