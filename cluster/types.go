package cluster

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/pki"
	"github.com/kennyparsons/agent-bridge/internal/protocol"
)

const (
	// Domain-separation prefixes for cluster cryptographic signatures.
	policySignatureDomainPrefix = "agent-bridge-policy-v1:"
	joinPoPDomainPrefix         = "agent-bridge-join-pop-v1:"
	joinTokenHashDomainPrefix   = "agent-bridge-join-token-v1:"

	// Cluster HTTP/1.1 + HTTP/2 over TLS 1.3 control-plane API paths.
	pathClusterJoin     = "/cluster/v1/join"
	pathClusterSignJoin = "/cluster/v1/sign-join"
	pathClusterSyncPush = "/cluster/v1/sync-push"
	pathClusterSyncPull = "/cluster/v1/sync-pull"
	pathClusterStatus   = "/cluster/v1/status"
	pathClusterPeers    = "/cluster/v1/peers"
	pathClusterTokens   = "/cluster/v1/tokens"
	pathClusterSync     = "/cluster/v1/sync"
)

// PeerState describes the SWIM-style reachability health of a cluster member.
type PeerState string

const (
	PeerAlive       PeerState = "alive"
	PeerSuspect     PeerState = "suspect"
	PeerUnreachable PeerState = "unreachable"
)

// TopologyMode classifies cluster quorum rules based on total registered membership size N.
type TopologyMode string

const (
	TopologySingleNode      TopologyMode = "single-node"
	TopologyTwoNode         TopologyMode = "two-node"
	TopologyMultiNodeQuorum TopologyMode = "multi-node-quorum"
)

// QuorumState reports the operational quorum health of this node within the cluster topology.
type QuorumState string

const (
	QuorumHealthy                 QuorumState = "healthy"
	QuorumDegradedTwoNodeFailover QuorumState = "degraded-two-node-failover"
	QuorumDegradedQuorum          QuorumState = "degraded-quorum"
	QuorumMinorityPartition       QuorumState = "minority-partition"
)

// ErrNoQuorum is returned when a cluster-wide mutating control-plane operation (such as creating
// a join token or mutating ExecutionPolicy) is attempted on a node in a minority partition.
var ErrNoQuorum = errors.New("cluster operation rejected: node is in minority-partition without majority quorum")

// PeerInfo describes a cluster member's identity, network endpoints, cryptographic serial, and health.
type PeerInfo struct {
	NodeID        string    `json:"node_id"`
	ClusterAddr   string    `json:"cluster_addr"`
	ExecAddr      string    `json:"exec_addr,omitempty"`
	Hostname      string    `json:"hostname,omitempty"`
	CertSerialHex string    `json:"cert_serial_hex,omitempty"`
	HasCAKey      bool      `json:"has_ca_key"`
	Incarnation   uint64    `json:"incarnation"`
	State         PeerState `json:"state"`
	CRLNumber     string    `json:"crl_number,omitempty"`
	PolicyVersion uint64    `json:"policy_version"`
	JoinedAtUnix  int64     `json:"joined_at_unix"`
	LastSeenUnix  int64     `json:"last_seen_unix"`
	IsSelf        bool      `json:"is_self,omitempty"`
	IsLeader      bool      `json:"is_leader,omitempty"`
}

// Clone returns a copy of PeerInfo.
func (p PeerInfo) Clone() PeerInfo {
	return p
}

// SignedPolicyEnvelope wraps a canonicalized protocol.ExecutionPolicy with an ECDSA P-256 signature
// chained to the cluster Root CA so stale or compromised peers cannot forge or roll back policies.
type SignedPolicyEnvelope struct {
	Policy          protocol.ExecutionPolicy `json:"policy"`
	SignerNodeID    string                   `json:"signer_node_id"`
	SignerCertPEM   string                   `json:"signer_cert_pem"`
	SignatureBase64 string                   `json:"signature_base64"`
}

// Clone returns a deep copy of SignedPolicyEnvelope, duplicating Policy.AllowedClients.
func (e *SignedPolicyEnvelope) Clone() *SignedPolicyEnvelope {
	if e == nil {
		return nil
	}
	cp := *e
	if len(e.Policy.AllowedClients) > 0 {
		cp.Policy.AllowedClients = append([]string(nil), e.Policy.AllowedClients...)
	}
	return &cp
}

// SignPolicyEnvelope canonicalizes policy, computes a domain-separated SHA-256 digest
// ("agent-bridge-policy-v1:" || canonicalBytes), and signs it with signerKey (ECDSA P-256).
func SignPolicyEnvelope(
	policy protocol.ExecutionPolicy,
	signerNodeID string,
	signerCert *x509.Certificate,
	signerKey *ecdsa.PrivateKey,
) (*SignedPolicyEnvelope, error) {
	trimmedSigner := strings.TrimSpace(signerNodeID)
	if trimmedSigner == "" {
		return nil, errors.New("policy signer node ID cannot be empty")
	}
	if signerCert == nil || len(signerCert.Raw) == 0 {
		return nil, errors.New("policy signer certificate cannot be nil")
	}
	if signerKey == nil {
		return nil, errors.New("policy signer private key cannot be nil")
	}
	if signerKey.Curve != elliptic.P256() {
		return nil, errors.New("policy signer private key must use ECDSA P-256")
	}
	certPub, ok := signerCert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !signerKey.PublicKey.Equal(certPub) {
		return nil, errors.New("policy signer private key does not match signer certificate public key")
	}

	canonicalBytes, err := policy.CanonicalBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize ExecutionPolicy: %w", err)
	}

	var normalizedPolicy protocol.ExecutionPolicy
	if err := json.Unmarshal(canonicalBytes, &normalizedPolicy); err != nil {
		return nil, fmt.Errorf("failed to normalize canonical ExecutionPolicy: %w", err)
	}

	digest := computePolicyDigest(canonicalBytes)
	sigASN1, err := ecdsa.SignASN1(rand.Reader, signerKey, digest[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign ExecutionPolicy: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: signerCert.Raw,
	})

	return &SignedPolicyEnvelope{
		Policy:          normalizedPolicy,
		SignerNodeID:    trimmedSigner,
		SignerCertPEM:   string(certPEM),
		SignatureBase64: base64.StdEncoding.EncodeToString(sigASN1),
	}, nil
}

// hasExtKeyUsage reports whether cert explicitly carries target in cert.ExtKeyUsage.
// Non-CA leaf certificates must explicitly carry ExtKeyUsageServerAuth for cluster peer/authority actions.
func hasExtKeyUsage(cert *x509.Certificate, target x509.ExtKeyUsage) bool {
	if cert == nil {
		return false
	}
	return slices.Contains(cert.ExtKeyUsage, target)
}

// Verify validates that SignerCertPEM is either the active Root CA certificate itself or an
// unrevoked cluster node/peer leaf certificate possessing ExtKeyUsageServerAuth signed by caPool
// (checked against crlWatcher), and verifies SignatureBase64 over the domain-separated canonical bytes of Policy.
func (e *SignedPolicyEnvelope) Verify(
	caCert *x509.Certificate,
	caPool *x509.CertPool,
	crlWatcher *pki.CRLWatcher,
) error {
	if e == nil {
		return errors.New("signed policy envelope is nil")
	}
	if caCert == nil {
		return errors.New("Root CA certificate cannot be nil")
	}
	if caPool == nil {
		return errors.New("Root CA pool cannot be nil")
	}
	if strings.TrimSpace(e.SignerNodeID) == "" {
		return errors.New("signed policy envelope is missing signer_node_id")
	}
	if strings.TrimSpace(e.SignerCertPEM) == "" {
		return errors.New("signed policy envelope is missing signer_cert_pem")
	}
	if strings.TrimSpace(e.SignatureBase64) == "" {
		return errors.New("signed policy envelope is missing signature_base64")
	}

	block, rest := pem.Decode([]byte(e.SignerCertPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("signer_cert_pem does not contain a valid CERTIFICATE PEM block")
	}
	if len(strings.TrimSpace(string(rest))) > 0 {
		return errors.New("signer_cert_pem contains unexpected trailing data")
	}

	signerCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse policy signer certificate: %w", err)
	}

	if bytes.Equal(signerCert.Raw, caCert.Raw) {
		if !signerCert.IsCA {
			return errors.New("matched Root CA certificate has IsCA=false")
		}
		now := time.Now().UTC()
		if now.Before(signerCert.NotBefore) || now.After(signerCert.NotAfter) {
			return fmt.Errorf("policy Root CA signer certificate is outside validity window (%s to %s)",
				signerCert.NotBefore.UTC().Format(time.RFC3339),
				signerCert.NotAfter.UTC().Format(time.RFC3339))
		}
	} else {
		if signerCert.IsCA {
			return errors.New("policy signer certificate cannot be an untrusted CA certificate")
		}
		if !hasExtKeyUsage(signerCert, x509.ExtKeyUsageServerAuth) {
			return errors.New("policy signer certificate lacks required ServerAuth extended key usage")
		}
		chains, verifyErr := signerCert.Verify(x509.VerifyOptions{
			Roots:     caPool,
			KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		})
		if verifyErr != nil {
			return fmt.Errorf("policy signer certificate verification failed: %w", verifyErr)
		}
		if crlWatcher != nil {
			if err := crlWatcher.CheckPeerChains(chains); err != nil {
				return fmt.Errorf("policy signer certificate verification failed: %w", err)
			}
		}
	}

	pub, ok := signerCert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return errors.New("policy signer certificate does not contain an ECDSA P-256 public key")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(strings.TrimSpace(e.SignatureBase64))
	if err != nil {
		return fmt.Errorf("invalid base64 policy signature: %w", err)
	}

	canonicalBytes, err := e.Policy.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("failed to compute canonical policy bytes: %w", err)
	}

	digest := computePolicyDigest(canonicalBytes)
	if !ecdsa.VerifyASN1(pub, digest[:], sigBytes) {
		return errors.New("policy ECDSA signature verification failed")
	}

	return nil
}

// ComparePolicyEnvelope establishes a strict deterministic monotonic ordering over signed policies:
//  1. Higher Policy.Version wins
//  2. Higher Policy.UpdatedAtUnix breaks version ties
//  3. Lexicographically higher SignerNodeID breaks timestamp ties
//  4. Canonical payload + signature comparison breaks any remaining tie so distinct envelopes never oscillate
//
// Returns >0 if a is newer than b, <0 if b is newer than a, and 0 if identical.
func ComparePolicyEnvelope(a, b *SignedPolicyEnvelope) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a != nil && b == nil:
		return 1
	case a == nil && b != nil:
		return -1
	}

	if a.Policy.Version != b.Policy.Version {
		if a.Policy.Version > b.Policy.Version {
			return 1
		}
		return -1
	}

	if a.Policy.UpdatedAtUnix != b.Policy.UpdatedAtUnix {
		if a.Policy.UpdatedAtUnix > b.Policy.UpdatedAtUnix {
			return 1
		}
		return -1
	}

	if a.SignerNodeID != b.SignerNodeID {
		if a.SignerNodeID > b.SignerNodeID {
			return 1
		}
		return -1
	}

	canonA, _ := a.Policy.CanonicalBytes()
	canonB, _ := b.Policy.CanonicalBytes()
	if cmp := bytes.Compare(canonA, canonB); cmp != 0 {
		return cmp
	}
	return strings.Compare(a.SignatureBase64, b.SignatureBase64)
}

// IsNewerThan reports whether e supersedes other under the cluster's monotonic policy ordering.
func (e *SignedPolicyEnvelope) IsNewerThan(other *SignedPolicyEnvelope) bool {
	return ComparePolicyEnvelope(e, other) > 0
}

func computePolicyDigest(canonicalBytes []byte) [32]byte {
	msg := make([]byte, 0, len(policySignatureDomainPrefix)+len(canonicalBytes))
	msg = append(msg, policySignatureDomainPrefix...)
	msg = append(msg, canonicalBytes...)
	return sha256.Sum256(msg)
}

// ClusterStatus summarizes local node identity, topology-aware quorum, leadership, CRL, policy, and peers.
type ClusterStatus struct {
	NodeID         string                   `json:"node_id"`
	ClusterAddr    string                   `json:"cluster_addr"`
	ExecAddr       string                   `json:"exec_addr,omitempty"`
	Topology       TopologyMode             `json:"topology"`
	QuorumState    QuorumState              `json:"quorum_state"`
	HasQuorum      bool                     `json:"has_quorum"`
	TotalNodes     int                      `json:"total_nodes"`
	AliveNodes     int                      `json:"alive_nodes"`
	QuorumRequired int                      `json:"quorum_required"`
	LeaderID       string                   `json:"leader_id,omitempty"`
	LeaderAddr     string                   `json:"leader_addr,omitempty"`
	IsLeader       bool                     `json:"is_leader"`
	HasCAKey       bool                     `json:"has_ca_key"`
	CRLNumber      string                   `json:"crl_number,omitempty"`
	RevokedCerts   int                      `json:"revoked_certs"`
	Policy         protocol.ExecutionPolicy `json:"policy"`
	Peers          []PeerInfo               `json:"peers"`
}

// TokenCreateRequest specifies parameters for minting a single-use cryptographic join token.
type TokenCreateRequest struct {
	TTLSeconds  int64  `json:"ttl_seconds,omitempty"`
	BoundNodeID string `json:"bound_node_id,omitempty"`
}

// TokenCreateResponse contains a newly minted single-use join token and its expiration metadata.
type TokenCreateResponse struct {
	Token         string    `json:"token"`
	TokenID       string    `json:"token_id"`
	CAFingerprint string    `json:"ca_fingerprint"`
	BoundNodeID   string    `json:"bound_node_id,omitempty"`
	CreatedByNode string    `json:"created_by_node,omitempty"`
	ExpiresAt     time.Time `json:"expires_at"`
	ExpiresAtUnix int64     `json:"expires_at_unix"`
}

// SyncRequest triggers an immediate anti-entropy push/pull across all cluster peers, optionally
// uploading a newer signed CRL PEM or mutating the cluster-wide ExecutionPolicy first.
type SyncRequest struct {
	CRLPEM       string                    `json:"crl_pem,omitempty"`
	PolicyUpdate *protocol.ExecutionPolicy `json:"policy_update,omitempty"`
}

// SyncResult reports the outcome of an on-demand cluster anti-entropy synchronization round.
type SyncResult struct {
	NodeID        string                   `json:"node_id"`
	CRLApplied    bool                     `json:"crl_applied"`
	CRLNumber     string                   `json:"crl_number,omitempty"`
	RevokedCerts  int                      `json:"revoked_certs"`
	PolicyUpdated bool                     `json:"policy_updated"`
	PolicyVersion uint64                   `json:"policy_version"`
	Policy        protocol.ExecutionPolicy `json:"policy"`
	SyncedPeers   []string                 `json:"synced_peers,omitempty"`
	FailedPeers   map[string]string        `json:"failed_peers,omitempty"`
	Status        ClusterStatus            `json:"status"`
}

// JoinRequest is submitted by a joining node to POST /cluster/v1/join in either Mode A (CSR) or Mode B (pre-issued cert).
type JoinRequest struct {
	Token              string `json:"token"`
	NodeID             string `json:"node_id"`
	ClusterAddr        string `json:"cluster_addr"`
	ExecAddr           string `json:"exec_addr,omitempty"`
	Hostname           string `json:"hostname,omitempty"`
	CSRPEM             string `json:"csr_pem,omitempty"`
	ExistingCertPEM    string `json:"existing_cert_pem,omitempty"`
	PoPSignatureBase64 string `json:"pop_signature_base64,omitempty"`
}

// JoinResponse is returned by POST /cluster/v1/join upon successful cryptographic admission.
type JoinResponse struct {
	NodeID        string                `json:"node_id"`
	CertSerialHex string                `json:"cert_serial_hex,omitempty"`
	IssuedCertPEM string                `json:"issued_cert_pem,omitempty"`
	CACertPEM     string                `json:"ca_cert_pem"`
	CRLPEM        string                `json:"crl_pem"`
	SignedPolicy  *SignedPolicyEnvelope `json:"signed_policy,omitempty"`
	Peers         []PeerInfo            `json:"peers"`
}

// signJoinForwardRequest is sent over peer mTLS from a non-CA node to an alive HasCAKey authority peer.
type signJoinForwardRequest struct {
	JoinRequest      JoinRequest  `json:"join_request"`
	ObservedRemoteIP string       `json:"observed_remote_ip,omitempty"`
	TokenRecord      *TokenRecord `json:"token_record,omitempty"`
}

// GossipPayload is exchanged over peer mTLS on /cluster/v1/sync-push and /cluster/v1/sync-pull.
type GossipPayload struct {
	Sender       PeerInfo              `json:"sender"`
	Peers        []PeerInfo            `json:"peers,omitempty"`
	CRLNumber    string                `json:"crl_number,omitempty"`
	CRLPEM       string                `json:"crl_pem,omitempty"`
	SignedPolicy *SignedPolicyEnvelope `json:"signed_policy,omitempty"`
	Tokens       []TokenRecord         `json:"tokens,omitempty"`
}

type apiErrorResponse struct {
	Error string `json:"error"`
}
