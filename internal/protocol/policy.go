package protocol

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"sort"
	"strings"
	"time"
)

// ExecutionPolicy defines cluster-replicated execution guardrails and optional client certificate ACLs.
type ExecutionPolicy struct {
	Version               uint64   `json:"version"`
	UpdatedAtUnix         int64    `json:"updated_at_unix,omitempty"`
	DefaultTimeoutSeconds int      `json:"default_timeout_seconds,omitempty"`
	MaxTimeoutSeconds     int      `json:"max_timeout_seconds,omitempty"`
	DefaultShell          string   `json:"default_shell,omitempty"`
	EnforceClientACL      bool     `json:"enforce_client_acl,omitempty"`
	AllowedClients        []string `json:"allowed_clients,omitempty"` // Matches leaf cert CommonName OR uppercase colon-hex Serial
}

// CanonicalBytes produces a deterministic UTF-8 JSON byte representation of ExecutionPolicy
// (with trimmed DefaultShell and trimmed, deduplicated, lexicographically sorted AllowedClients)
// suitable for ECDSA P-256 signing and verification across cluster nodes.
func (p ExecutionPolicy) CanonicalBytes() ([]byte, error) {
	norm := ExecutionPolicy{
		Version:               p.Version,
		UpdatedAtUnix:         p.UpdatedAtUnix,
		DefaultTimeoutSeconds: p.DefaultTimeoutSeconds,
		MaxTimeoutSeconds:     p.MaxTimeoutSeconds,
		DefaultShell:          strings.TrimSpace(p.DefaultShell),
		EnforceClientACL:      p.EnforceClientACL,
	}

	if len(p.AllowedClients) > 0 {
		seen := make(map[string]struct{}, len(p.AllowedClients))
		cleaned := make([]string, 0, len(p.AllowedClients))
		for _, raw := range p.AllowedClients {
			trimmed := strings.TrimSpace(raw)
			if trimmed == "" {
				continue
			}
			if _, exists := seen[trimmed]; exists {
				continue
			}
			seen[trimmed] = struct{}{}
			cleaned = append(cleaned, trimmed)
		}
		if len(cleaned) > 0 {
			sort.Strings(cleaned)
			norm.AllowedClients = cleaned
		}
	}

	return json.Marshal(norm)
}

// IsClientAllowed reports whether a verified client certificate identified by commonName and serialHex
// is permitted under this ExecutionPolicy. When EnforceClientACL is false, all CA-verified unrevoked
// client certificates are allowed.
func (p ExecutionPolicy) IsClientAllowed(commonName string, serialHex string) bool {
	if !p.EnforceClientACL {
		return true
	}
	if len(p.AllowedClients) == 0 {
		return false
	}

	trimmedCN := strings.TrimSpace(commonName)
	normSerial, hasSerial := normalizePolicySerialHex(serialHex)

	for _, rawEntry := range p.AllowedClients {
		entry := strings.TrimSpace(rawEntry)
		if entry == "" {
			continue
		}
		if trimmedCN != "" && entry == trimmedCN {
			return true
		}
		if hasSerial {
			if strings.EqualFold(entry, normSerial) {
				return true
			}
			if entrySerial, ok := normalizePolicySerialHex(entry); ok && entrySerial == normSerial {
				return true
			}
		}
	}
	return false
}

// EffectiveTimeoutSecondsWithPolicy resolves CommandRequest.TimeoutSeconds against an optional
// cluster ExecutionPolicy while enforcing protocol-level safety bounds ([1, MaxTimeoutSeconds]).
func (r CommandRequest) EffectiveTimeoutSecondsWithPolicy(p *ExecutionPolicy) int {
	if p == nil {
		return r.EffectiveTimeoutSeconds()
	}

	effectiveMax := MaxTimeoutSeconds
	if p.MaxTimeoutSeconds > 0 && p.MaxTimeoutSeconds < effectiveMax {
		effectiveMax = p.MaxTimeoutSeconds
	}

	effectiveDefault := DefaultTimeoutSeconds
	if p.DefaultTimeoutSeconds > 0 {
		effectiveDefault = p.DefaultTimeoutSeconds
	}
	if effectiveDefault > effectiveMax {
		effectiveDefault = effectiveMax
	}

	sec := r.TimeoutSeconds
	if sec <= 0 {
		sec = effectiveDefault
	}
	if sec > effectiveMax {
		sec = effectiveMax
	}
	return sec
}

// EffectiveTimeoutWithPolicy returns EffectiveTimeoutSecondsWithPolicy(p) as a time.Duration.
func (r CommandRequest) EffectiveTimeoutWithPolicy(p *ExecutionPolicy) time.Duration {
	return time.Duration(r.EffectiveTimeoutSecondsWithPolicy(p)) * time.Second
}

func normalizePolicySerialHex(s string) (string, bool) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" || strings.HasPrefix(trimmed, "-") {
		return "", false
	}
	if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") {
		trimmed = trimmed[2:]
	}
	if trimmed == "" {
		return "", false
	}

	var hexBuf strings.Builder
	if strings.Contains(trimmed, ":") {
		parts := strings.Split(trimmed, ":")
		hexBuf.Grow(len(parts) * 2)
		for _, seg := range parts {
			if len(seg) == 0 || len(seg) > 2 {
				return "", false
			}
			if len(seg) == 1 {
				hexBuf.WriteByte('0')
			}
			hexBuf.WriteString(seg)
		}
	} else {
		if len(trimmed)%2 != 0 {
			hexBuf.WriteByte('0')
		}
		hexBuf.WriteString(trimmed)
	}

	decoded, err := hex.DecodeString(hexBuf.String())
	if err != nil {
		return "", false
	}
	n := new(big.Int).SetBytes(decoded)
	if n.Sign() <= 0 {
		return "", false
	}

	mag := n.Bytes()
	formatted := make([]string, len(mag))
	for i, b := range mag {
		const digits = "0123456789ABCDEF"
		formatted[i] = string([]byte{digits[b>>4], digits[b&0x0F]})
	}
	return strings.Join(formatted, ":"), true
}
