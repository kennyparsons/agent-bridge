package cluster

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/pki"
)

// Client is an authenticated mTLS 1.3 HTTP control-plane client for `agent-bridge cluster` operations.
type Client struct {
	baseHTTPSURL string
	timeout      time.Duration
	transport    *http.Transport
	httpClient   *http.Client
}

// NewClient constructs a TLS 1.3 mutual-authenticated cluster administration client from cfg.
func NewClient(cfg *config.ResolvedClusterConfig) (*Client, error) {
	if cfg == nil {
		return nil, errors.New("cluster configuration cannot be nil")
	}

	rawTarget := strings.TrimSpace(cfg.BaseHTTPSURL)
	if rawTarget == "" {
		rawTarget = strings.TrimSpace(cfg.ClusterAddr)
	}
	if rawTarget == "" {
		rawTarget = config.DefaultClusterEndpoint
	}
	_, baseHTTPSURL, err := config.NormalizeClusterAddr(rawTarget)
	if err != nil {
		return nil, fmt.Errorf("invalid cluster target address: %w", err)
	}

	certPath := strings.TrimSpace(cfg.CertPath)
	if certPath == "" {
		return nil, errors.New("cluster client certificate path is required")
	}
	keyPath := strings.TrimSpace(cfg.KeyPath)
	if keyPath == "" {
		return nil, errors.New("cluster client private key path is required")
	}
	caPath := strings.TrimSpace(cfg.CAPath)
	if caPath == "" {
		return nil, errors.New("cluster Root CA certificate path is required")
	}

	clientCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load cluster client X.509 keypair: %w", err)
	}
	_, caPool, err := pki.LoadCACertPool(caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load Root CA certificate pool: %w", err)
	}

	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true, // Strictly paired with VerifyPeerCertDualEKU + ServerAuth check in VerifyConnection.
		VerifyConnection: func(cs tls.ConnectionState) error {
			rawCerts := certsToRawDER(cs.PeerCertificates)
			leaf, verifyErr := pki.VerifyPeerCertDualEKU(rawCerts, caPool, nil)
			if verifyErr != nil {
				return verifyErr
			}
			if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
				return errors.New("TLS Handshake Rejected: cluster server certificate lacks ServerAuth extended key usage")
			}
			return nil
		},
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsCfg,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        8,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &Client{
		baseHTTPSURL: baseHTTPSURL,
		timeout:      cfg.EffectiveTimeout(),
		transport:    transport,
		httpClient: &http.Client{
			Transport: transport,
		},
	}, nil
}

// Close closes any pooled idle TLS connections held by Client.
func (c *Client) Close() error {
	if c != nil && c.transport != nil {
		c.transport.CloseIdleConnections()
	}
	return nil
}

// CreateToken requests a new single-use Root-CA-pinned join token from the target cluster node.
func (c *Client) CreateToken(ctx context.Context, ttl time.Duration, boundNodeID string) (*TokenCreateResponse, error) {
	if c == nil {
		return nil, errors.New("cluster client is nil")
	}
	if ttl < 0 {
		return nil, fmt.Errorf("join token TTL must be non-negative, got %s", ttl)
	}

	var ttlSec int64
	if ttl > 0 {
		ttlSec = int64((ttl + time.Second - 1) / time.Second)
		if ttlSec < 1 {
			ttlSec = 1
		}
	}

	reqBody := TokenCreateRequest{
		TTLSeconds:  ttlSec,
		BoundNodeID: strings.TrimSpace(boundNodeID),
	}
	var out TokenCreateResponse
	if err := c.doJSON(ctx, http.MethodPost, pathClusterTokens, reqBody, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Status queries the target cluster node's topology, quorum state, leader, CRL, policy, and peer roster.
func (c *Client) Status(ctx context.Context) (*ClusterStatus, error) {
	if c == nil {
		return nil, errors.New("cluster client is nil")
	}
	var out ClusterStatus
	if err := c.doJSON(ctx, http.MethodGet, pathClusterStatus, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Peers returns the target cluster node's view of all cluster members.
func (c *Client) Peers(ctx context.Context) ([]PeerInfo, error) {
	if c == nil {
		return nil, errors.New("cluster client is nil")
	}
	var out []PeerInfo
	if err := c.doJSON(ctx, http.MethodGet, pathClusterPeers, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Sync triggers an immediate CRL/policy/peer push-pull sync round (and optional CRL upload or ExecutionPolicy update).
func (c *Client) Sync(ctx context.Context, req SyncRequest) (*SyncResult, error) {
	if c == nil {
		return nil, errors.New("cluster client is nil")
	}
	var out SyncResult
	if err := c.doJSON(ctx, http.MethodPost, pathClusterSync, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) doJSON(ctx context.Context, method, path string, reqPayload any, respDst any) error {
	if ctx == nil {
		ctx = context.Background()
	}

	reqCtx := ctx
	var cancel context.CancelFunc
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && c.timeout > 0 {
		reqCtx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	var bodyReader io.Reader
	if reqPayload != nil {
		encoded, err := json.Marshal(reqPayload)
		if err != nil {
			return fmt.Errorf("failed to marshal cluster request: %w", err)
		}
		bodyReader = bytes.NewReader(encoded)
	}

	httpReq, err := http.NewRequestWithContext(reqCtx, method, c.baseHTTPSURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("failed to create cluster HTTP request: %w", err)
	}
	if reqPayload != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	httpResp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("cluster request %s %s failed: %w", method, c.baseHTTPSURL+path, err)
	}
	defer httpResp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(httpResp.Body, maxJoinBodyBytes))
	if err != nil {
		return fmt.Errorf("failed reading cluster response from %s: %w", c.baseHTTPSURL+path, err)
	}

	if httpResp.StatusCode < 200 || httpResp.StatusCode >= 300 {
		return decodeClusterHTTPError(httpResp.StatusCode, respBytes, fmt.Sprintf("cluster %s %s failed", method, path))
	}

	if respDst != nil {
		if err := json.Unmarshal(respBytes, respDst); err != nil {
			return fmt.Errorf("malformed JSON response from %s%s: %w", c.baseHTTPSURL, path, err)
		}
	}
	return nil
}
