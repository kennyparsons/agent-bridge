package cluster

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kennyparsons/agent-bridge/internal/pki"
)

const currentStateSchemaVersion = 1

type persistedClusterState struct {
	SchemaVersion int                   `json:"schema_version"`
	Bootstrapped  bool                  `json:"bootstrapped,omitempty"`
	NodeID        string                `json:"node_id"`
	CertSerialHex string                `json:"cert_serial_hex,omitempty"`
	Incarnation   uint64                `json:"incarnation"`
	JoinedAtUnix  int64                 `json:"joined_at_unix"`
	SeedPeers     []string              `json:"seed_peers,omitempty"`
	SignedPolicy  *SignedPolicyEnvelope `json:"signed_policy,omitempty"`
	Peers         []PeerInfo            `json:"peers,omitempty"`
	Tokens        []TokenRecord         `json:"tokens,omitempty"`
}

func persistedSelfSerialHex(st *persistedClusterState, nodeID string) string {
	if st == nil {
		return ""
	}
	if trimmed := strings.TrimSpace(st.CertSerialHex); trimmed != "" {
		return trimmed
	}
	for _, p := range st.Peers {
		if p.NodeID == nodeID && strings.TrimSpace(p.CertSerialHex) != "" {
			return strings.TrimSpace(p.CertSerialHex)
		}
	}
	return ""
}

// DefaultStatePath derives a cross-platform default cluster state file path inside filepath.Dir(crlPath)
// scoped by nodeID (e.g. "<dir(CRL)>/cluster-state-<nodeID>.json").
func DefaultStatePath(crlPath, nodeID string) string {
	baseDir := "."
	if trimmedCRL := strings.TrimSpace(crlPath); trimmedCRL != "" {
		baseDir = filepath.Dir(trimmedCRL)
	}
	safeNode := sanitizeFilenameToken(nodeID)
	if safeNode == "" {
		return filepath.Join(baseDir, "cluster-state.json")
	}
	return filepath.Join(baseDir, "cluster-state-"+safeNode+".json")
}

func sanitizeFilenameToken(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	var sb strings.Builder
	sb.Grow(len(trimmed))
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('_')
		}
	}
	out := strings.Trim(sb.String(), "._ ")
	if len(out) > 96 {
		out = out[:96]
	}
	return out
}

func loadPersistedState(statePath string) (*persistedClusterState, error) {
	trimmed := strings.TrimSpace(statePath)
	if trimmed == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(trimmed)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to read cluster state file %q: %w", trimmed, err)
	}
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}

	var st persistedClusterState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, fmt.Errorf("failed to parse cluster state file %q: %w", trimmed, err)
	}
	return &st, nil
}

func savePersistedState(statePath string, st *persistedClusterState) error {
	trimmed := strings.TrimSpace(statePath)
	if trimmed == "" || st == nil {
		return nil
	}
	cp := *st
	if cp.SchemaVersion <= 0 {
		cp.SchemaVersion = currentStateSchemaVersion
	}

	encoded, err := json.MarshalIndent(&cp, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal cluster state: %w", err)
	}
	encoded = append(encoded, '\n')

	if err := pki.WriteFileAtomic(trimmed, encoded, 0o600); err != nil {
		return fmt.Errorf("failed to write cluster state %q: %w", trimmed, err)
	}
	return nil
}
