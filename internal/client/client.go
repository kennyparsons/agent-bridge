package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/pki"
	"github.com/kennyparsons/agent-bridge/internal/protocol"
)

const (
	// MaxResponseBytes caps incoming WebSocket response frames at 32 MiB so a full
	// 10 MiB stdout + 10 MiB stderr JSON-encoded envelope never hits client frame truncation.
	MaxResponseBytes = 32 * 1024 * 1024

	// DefaultHandshakeTimeout bounds the TCP + TLS 1.3 + HTTP Upgrade handshake duration.
	DefaultHandshakeTimeout = 15 * time.Second

	// DefaultDeadlineGrace adds a safety buffer beyond CommandRequest.EffectiveTimeout()
	// so the remote server can terminate a timed-out subprocess and deliver its structured
	// JSON CommandResponse before the client tears down the underlying TCP socket.
	DefaultDeadlineGrace = 10 * time.Second
)

// Execute performs a single synchronous mTLS 1.3 WebSocket transaction against `wss://<endpoint>/ws/exec`,
// transmitting one CommandRequest JSON text frame and returning the decoded CommandResponse.
func Execute(ctx context.Context, cfg *config.ResolvedConfig, command string) (*protocol.CommandResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg == nil {
		return nil, errors.New("client configuration cannot be nil")
	}
	if strings.TrimSpace(command) == "" {
		return nil, errors.New("command cannot be empty")
	}

	wsURL := strings.TrimSpace(cfg.WSURL)
	endpointLabel := strings.TrimSpace(cfg.Endpoint)
	if wsURL == "" {
		if endpointLabel == "" {
			return nil, errors.New("missing target endpoint in client configuration")
		}
		normHostPort, normWSURL, err := config.NormalizeEndpoint(endpointLabel)
		if err != nil {
			return nil, err
		}
		endpointLabel = normHostPort
		wsURL = normWSURL
	}
	if endpointLabel == "" {
		endpointLabel = wsURL
	}

	certPath := strings.TrimSpace(cfg.CertPath)
	keyPath := strings.TrimSpace(cfg.KeyPath)
	caPath := strings.TrimSpace(cfg.CAPath)
	if certPath == "" {
		return nil, errors.New("missing client certificate path in client configuration")
	}
	if keyPath == "" {
		return nil, errors.New("missing client private key path in client configuration")
	}
	if caPath == "" {
		return nil, errors.New("missing Root CA certificate path in client configuration")
	}

	clientCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load client mTLS keypair (cert=%q, key=%q): %w", certPath, keyPath, err)
	}

	_, caPool, err := pki.LoadCACertPool(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load Root CA certificate %q: %w", caPath, err)
	}

	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{clientCert},
		RootCAs:      caPool,
	}

	req := protocol.CommandRequest{
		Command:        command,
		TimeoutSeconds: cfg.EffectiveTimeoutSeconds(),
	}

	safetyTimeout := req.EffectiveTimeout() + DefaultDeadlineGrace
	execCtx, cancel := context.WithTimeout(ctx, safetyTimeout)
	defer cancel()

	handshakeTimeout := DefaultHandshakeTimeout
	if safetyTimeout < handshakeTimeout {
		handshakeTimeout = safetyTimeout
	}

	dialer := websocket.Dialer{
		TLSClientConfig:  tlsConfig,
		HandshakeTimeout: handshakeTimeout,
	}

	conn, httpResp, err := dialer.DialContext(execCtx, wsURL, nil)
	if err != nil {
		return nil, formatTransportError("connecting to", endpointLabel, err, httpResp)
	}
	if httpResp != nil && httpResp.Body != nil {
		_ = httpResp.Body.Close()
	}
	defer conn.Close()

	conn.SetReadLimit(MaxResponseBytes)

	if deadline, ok := execCtx.Deadline(); ok {
		if err := conn.SetWriteDeadline(deadline); err != nil {
			return nil, fmt.Errorf("failed to set WebSocket write deadline on %s: %w", endpointLabel, err)
		}
		if err := conn.SetReadDeadline(deadline); err != nil {
			return nil, fmt.Errorf("failed to set WebSocket read deadline on %s: %w", endpointLabel, err)
		}
	}

	// Unblock conn.ReadMessage immediately if caller cancels ctx or safety deadline fires.
	doneCh := make(chan struct{})
	defer close(doneCh)
	go func() {
		select {
		case <-execCtx.Done():
			_ = conn.Close()
		case <-doneCh:
		}
	}()

	reqPayload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to encode CommandRequest JSON: %w", err)
	}

	if err := conn.WriteMessage(websocket.TextMessage, reqPayload); err != nil {
		if ctxErr := execCtx.Err(); ctxErr != nil {
			return nil, formatContextError(ctx, ctxErr, endpointLabel, req.EffectiveTimeout())
		}
		return nil, formatTransportError("sending command request to", endpointLabel, err, nil)
	}

	msgType, respPayload, err := conn.ReadMessage()
	if err != nil {
		if ctxErr := execCtx.Err(); ctxErr != nil {
			return nil, formatContextError(ctx, ctxErr, endpointLabel, req.EffectiveTimeout())
		}
		var closeErr *websocket.CloseError
		if errors.As(err, &closeErr) {
			if closeErr.Code == websocket.CloseNormalClosure {
				return nil, fmt.Errorf("server %s closed WebSocket connection (code 1000) before sending a CommandResponse: %w", endpointLabel, err)
			}
			return nil, fmt.Errorf("server %s terminated WebSocket session (code %d %q): %w", endpointLabel, closeErr.Code, closeErr.Text, err)
		}
		return nil, formatTransportError("reading command response from", endpointLabel, err, nil)
	}

	if msgType != websocket.TextMessage {
		return nil, fmt.Errorf("unexpected WebSocket frame type %d from %s (expected text frame)", msgType, endpointLabel)
	}

	var cmdResp protocol.CommandResponse
	if err := json.Unmarshal(respPayload, &cmdResp); err != nil {
		return nil, fmt.Errorf("failed to decode CommandResponse JSON from %s: %w", endpointLabel, err)
	}

	// Best-effort reciprocal CloseNormalClosure (1000); ignore write errors if server already closed TCP.
	_ = conn.WriteControl(
		websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""),
		time.Now().Add(time.Second),
	)

	return &cmdResp, nil
}

// Run executes command on the remote agent-bridge server, writes any non-empty stdout/stderr
// payloads to the supplied writers (ensuring a single trailing newline since server-side
// protocol.SanitizeOutput trims trailing whitespace), and returns the remote process exit code.
func Run(ctx context.Context, cfg *config.ResolvedConfig, command string, stdout, stderr io.Writer) (int, error) {
	resp, err := Execute(ctx, cfg, command)
	if err != nil {
		return 1, err
	}

	if resp.Stdout != "" && stdout != nil {
		if err := writeStreamWithNewline(stdout, resp.Stdout); err != nil {
			return 1, fmt.Errorf("failed to write remote stdout: %w", err)
		}
	}

	if resp.Stderr != "" && stderr != nil {
		if err := writeStreamWithNewline(stderr, resp.Stderr); err != nil {
			return 1, fmt.Errorf("failed to write remote stderr: %w", err)
		}
	}

	return resp.ExitCode, nil
}

func writeStreamWithNewline(w io.Writer, data string) error {
	if _, err := io.WriteString(w, data); err != nil {
		return err
	}
	if !strings.HasSuffix(data, "\n") {
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
	}
	return nil
}

func formatContextError(parentCtx context.Context, execCtxErr error, endpoint string, cmdTimeout time.Duration) error {
	if parentCtx != nil && errors.Is(parentCtx.Err(), context.Canceled) {
		return fmt.Errorf("command execution against %s canceled by caller: %w", endpoint, parentCtx.Err())
	}
	if errors.Is(execCtxErr, context.DeadlineExceeded) {
		return fmt.Errorf("client safety deadline exceeded waiting for response from %s (command timeout %s): %w", endpoint, cmdTimeout, execCtxErr)
	}
	return fmt.Errorf("command execution against %s interrupted: %w", endpoint, execCtxErr)
}

func formatTransportError(action, endpoint string, err error, httpResp *http.Response) error {
	lower := strings.ToLower(err.Error())

	if httpResp != nil {
		defer func() {
			if httpResp.Body != nil {
				_ = httpResp.Body.Close()
			}
		}()
		var bodySnippet string
		if httpResp.Body != nil {
			if raw, readErr := io.ReadAll(io.LimitReader(httpResp.Body, 512)); readErr == nil {
				bodySnippet = strings.TrimSpace(string(raw))
			}
		}
		if bodySnippet != "" {
			return fmt.Errorf("WebSocket upgrade rejected by %s (HTTP %d %s: %s): %w", endpoint, httpResp.StatusCode, http.StatusText(httpResp.StatusCode), bodySnippet, err)
		}
		return fmt.Errorf("WebSocket upgrade rejected by %s (HTTP %d %s): %w", endpoint, httpResp.StatusCode, http.StatusText(httpResp.StatusCode), err)
	}

	switch {
	case strings.Contains(lower, "bad certificate") || strings.Contains(lower, "certificate revoked") || strings.Contains(lower, "revoked"):
		return fmt.Errorf("mTLS handshake rejected while %s %s (client certificate may be revoked in server CRL or issued by an untrusted CA): %w", action, endpoint, err)

	case strings.Contains(lower, "unknown authority") || strings.Contains(lower, "unknown certificate authority"):
		return fmt.Errorf("mTLS trust verification failed while %s %s (CA mismatch: ensure --ca matches the Root CA that signed both server and client certificates): %w", action, endpoint, err)

	case strings.Contains(lower, "certificate required"):
		return fmt.Errorf("mTLS handshake rejected while %s %s (server requires a valid client certificate): %w", action, endpoint, err)

	case strings.Contains(lower, "x509:") || strings.Contains(lower, "tls:"):
		return fmt.Errorf("TLS 1.3 handshake failed while %s %s (verify server SANs cover %s and certificates have not expired): %w", action, endpoint, endpoint, err)

	case strings.Contains(lower, "connection refused") ||
		strings.Contains(lower, "no route to host") ||
		strings.Contains(lower, "network is unreachable") ||
		strings.Contains(lower, "i/o timeout"):
		return fmt.Errorf("unable to reach agent-bridge daemon while %s %s (verify `agent-bridge server` is running and Tailscale connectivity is active): %w", action, endpoint, err)

	default:
		return fmt.Errorf("error %s %s: %w", action, endpoint, err)
	}
}
