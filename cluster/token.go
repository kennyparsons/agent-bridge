package cluster

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/pki"
)

const (
	// JoinTokenVersionPrefix identifies v1 Root-CA-pinned join tokens on the wire.
	JoinTokenVersionPrefix = "abjt1"

	// DefaultJoinTokenTTL is used when CreateJoinToken is invoked with ttl == 0.
	DefaultJoinTokenTTL = 15 * time.Minute

	tokenIDByteLen     = 8  // 16 lowercase hex chars
	tokenSecretByteLen = 32 // 64 lowercase hex chars (256-bit secret)
	tokenSaltByteLen   = 16 // 32 lowercase hex chars (128-bit random salt)

	// Retain expired/consumed TokenRecord tombstones for 24h so consumption state converges across partitions.
	tokenTombstoneRetention = 24 * time.Hour
)

// ParsedJoinToken holds the validated components of an abjt1.<ca_sha256_hex_64>.<token_id_hex_16>.<secret_hex_64> token.
type ParsedJoinToken struct {
	Raw           string
	CAFingerprint string
	TokenID       string
	SecretHex     string
}

// TokenRecord stores ONLY the salted SHA-256 hash of a join token secret for disk persistence
// and peer-to-peer gossip replication. Plaintext token secrets are never persisted or replicated.
type TokenRecord struct {
	TokenID         string `json:"token_id"`
	SaltHex         string `json:"salt_hex"`
	SecretHashHex   string `json:"secret_hash_hex"`
	CreatedByNodeID string `json:"created_by_node_id"`
	BoundNodeID     string `json:"bound_node_id,omitempty"`
	CreatedAtUnix   int64  `json:"created_at_unix"`
	ExpiresAtUnix   int64  `json:"expires_at_unix"`
	Used            bool   `json:"used"`
	UsedByNodeID    string `json:"used_by_node_id,omitempty"`
	UsedAtUnix      int64  `json:"used_at_unix,omitempty"`
}

// Clone returns a copy of TokenRecord.
func (r TokenRecord) Clone() TokenRecord {
	return r
}

// GenerateJoinToken creates a single-use, time-bounded join token pinned to caCert's SHA-256 DER
// fingerprint alongside a salted SHA-256 TokenRecord safe for persistence and replication.
func GenerateJoinToken(
	caCert *x509.Certificate,
	createdByNodeID string,
	boundNodeID string,
	ttl time.Duration,
	now time.Time,
) (rawToken string, record TokenRecord, expiresAt time.Time, err error) {
	if caCert == nil || len(caCert.Raw) == 0 {
		return "", TokenRecord{}, time.Time{}, errors.New("Root CA certificate is required to mint join token")
	}
	creator := strings.TrimSpace(createdByNodeID)
	if creator == "" {
		return "", TokenRecord{}, time.Time{}, errors.New("creator node ID is required to mint join token")
	}
	if ttl < 0 {
		return "", TokenRecord{}, time.Time{}, fmt.Errorf("join token TTL must be positive, got %s", ttl)
	}
	if ttl == 0 {
		ttl = DefaultJoinTokenTTL
	}

	caFingerprint := pki.CertFingerprintSHA256(caCert)
	if len(caFingerprint) != 64 {
		return "", TokenRecord{}, time.Time{}, errors.New("failed to compute 64-char Root CA SHA-256 fingerprint")
	}

	var idBytes [tokenIDByteLen]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return "", TokenRecord{}, time.Time{}, fmt.Errorf("failed to generate random token ID: %w", err)
	}
	tokenID := hex.EncodeToString(idBytes[:])

	var secretBytes [tokenSecretByteLen]byte
	if _, err := rand.Read(secretBytes[:]); err != nil {
		return "", TokenRecord{}, time.Time{}, fmt.Errorf("failed to generate random token secret: %w", err)
	}
	secretHex := hex.EncodeToString(secretBytes[:])

	var saltBytes [tokenSaltByteLen]byte
	if _, err := rand.Read(saltBytes[:]); err != nil {
		return "", TokenRecord{}, time.Time{}, fmt.Errorf("failed to generate random token salt: %w", err)
	}
	saltHex := hex.EncodeToString(saltBytes[:])

	secretHash := computeSaltedTokenHash(tokenID, saltBytes[:], secretBytes[:])
	secretHashHex := hex.EncodeToString(secretHash[:])

	nowUTC := now.UTC()
	expiresAt = nowUTC.Add(ttl)

	rawToken = fmt.Sprintf("%s.%s.%s.%s", JoinTokenVersionPrefix, caFingerprint, tokenID, secretHex)
	record = TokenRecord{
		TokenID:         tokenID,
		SaltHex:         saltHex,
		SecretHashHex:   secretHashHex,
		CreatedByNodeID: creator,
		BoundNodeID:     strings.TrimSpace(boundNodeID),
		CreatedAtUnix:   nowUTC.Unix(),
		ExpiresAtUnix:   expiresAt.Unix(),
		Used:            false,
	}

	return rawToken, record, expiresAt, nil
}

// ParseJoinToken parses and structurally validates an abjt1.<ca_sha256_hex_64>.<token_id_hex_16>.<secret_hex_64> wire token.
func ParseJoinToken(raw string) (*ParsedJoinToken, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, errors.New("join token cannot be empty")
	}

	parts := strings.Split(trimmed, ".")
	if len(parts) != 4 {
		return nil, errors.New("malformed join token: expected format abjt1.<ca_sha256>.<token_id>.<secret>")
	}
	if parts[0] != JoinTokenVersionPrefix {
		return nil, fmt.Errorf("unsupported join token version %q (expected %q)", parts[0], JoinTokenVersionPrefix)
	}

	caFP := strings.ToLower(parts[1])
	if len(caFP) != 64 || !isValidHex(caFP) {
		return nil, errors.New("malformed join token: invalid 64-char Root CA SHA-256 hex fingerprint")
	}

	tokID := strings.ToLower(parts[2])
	if len(tokID) != tokenIDByteLen*2 || !isValidHex(tokID) {
		return nil, errors.New("malformed join token: invalid 16-char token ID")
	}

	secHex := strings.ToLower(parts[3])
	if len(secHex) != tokenSecretByteLen*2 || !isValidHex(secHex) {
		return nil, errors.New("malformed join token: invalid 64-char token secret")
	}

	return &ParsedJoinToken{
		Raw:           fmt.Sprintf("%s.%s.%s.%s", JoinTokenVersionPrefix, caFP, tokID, secHex),
		CAFingerprint: caFP,
		TokenID:       tokID,
		SecretHex:     secHex,
	}, nil
}

// VerifySecret validates secretHex against r.SaltHex and r.SecretHashHex in constant time.
func (r *TokenRecord) VerifySecret(secretHex string) bool {
	if r == nil {
		return false
	}
	if len(r.TokenID) != tokenIDByteLen*2 {
		return false
	}
	saltBytes, err := hex.DecodeString(r.SaltHex)
	if err != nil || len(saltBytes) != tokenSaltByteLen {
		return false
	}
	expectedHash, err := hex.DecodeString(r.SecretHashHex)
	if err != nil || len(expectedHash) != sha256.Size {
		return false
	}
	secretBytes, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(secretHex)))
	if err != nil || len(secretBytes) != tokenSecretByteLen {
		return false
	}

	actualHash := computeSaltedTokenHash(strings.ToLower(r.TokenID), saltBytes, secretBytes)
	return subtle.ConstantTimeCompare(actualHash[:], expectedHash) == 1
}

// IsValidStructure checks that a replicated or persisted TokenRecord contains well-formed hash metadata
// and no missing fields before admitting it into Engine state.
func (r *TokenRecord) IsValidStructure() bool {
	if r == nil {
		return false
	}
	if len(r.TokenID) != tokenIDByteLen*2 || !isValidHex(r.TokenID) {
		return false
	}
	if len(r.SaltHex) != tokenSaltByteLen*2 || !isValidHex(r.SaltHex) {
		return false
	}
	if len(r.SecretHashHex) != sha256.Size*2 || !isValidHex(r.SecretHashHex) {
		return false
	}
	if strings.TrimSpace(r.CreatedByNodeID) == "" || r.ExpiresAtUnix <= 0 {
		return false
	}
	return true
}

// mergeTokenRecord monotonically reconciles two TokenRecord instances for the same TokenID.
// Consumption (`Used == true`) is irreversible so single-use semantics converge across peers.
func mergeTokenRecord(existing, incoming TokenRecord) (merged TokenRecord, changed bool) {
	if existing.TokenID != incoming.TokenID ||
		!strings.EqualFold(existing.SaltHex, incoming.SaltHex) ||
		!strings.EqualFold(existing.SecretHashHex, incoming.SecretHashHex) {
		return existing, false
	}

	merged = existing
	if !existing.Used && incoming.Used {
		merged.Used = true
		merged.UsedByNodeID = incoming.UsedByNodeID
		merged.UsedAtUnix = incoming.UsedAtUnix
		changed = true
	}
	return merged, changed
}

func computeSaltedTokenHash(tokenID string, saltBytes, secretBytes []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte(joinTokenHashDomainPrefix))
	h.Write(saltBytes)
	h.Write([]byte(":"))
	h.Write([]byte(strings.ToLower(tokenID)))
	h.Write([]byte(":"))
	h.Write(secretBytes)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func isValidHex(s string) bool {
	if s == "" || len(s)%2 != 0 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
