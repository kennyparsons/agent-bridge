package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/kennyparsons/agent-bridge/internal/acl"
	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/pki"
)

// Paths holds the standard OS server directory, configuration file, and daemon log paths.
type Paths struct {
	DataDir    string `json:"data_dir"`
	ConfigPath string `json:"config_path"`
	LogPath    string `json:"log_path"`
}

// DefaultPaths returns the standard server Paths for the running operating system.
func DefaultPaths() Paths {
	return DefaultPathsForOS(runtime.GOOS)
}

// DefaultPathsForOS returns the standard server Paths for the specified GOOS ("windows", "linux", "darwin").
func DefaultPathsForOS(goos string) Paths {
	dataDir, configPath, logPath := config.DefaultServerPathsForOS(goos)
	return Paths{
		DataDir:    dataDir,
		ConfigPath: configPath,
		LogPath:    logPath,
	}
}

// ServerDaemonConfig persists long-lived `agent-bridge server` daemon parameters in `server.json`.
// Single-use cluster `join_token` secrets are intentionally omitted and never persisted to disk.
type ServerDaemonConfig struct {
	BindSpecs        []string `json:"bind_specs,omitempty"`
	Port             int      `json:"port,omitempty"`
	ClusterEnabled   bool     `json:"cluster_enabled,omitempty"`
	ClusterBindSpecs []string `json:"cluster_bind_specs,omitempty"`
	ClusterAdvertise string   `json:"cluster_advertise,omitempty"`
	JoinAddr         string   `json:"join_addr,omitempty"`
	SeedPeers        []string `json:"seed_peers,omitempty"`
	NodeID           string   `json:"node_id,omitempty"`
	DataDir          string   `json:"data_dir,omitempty"`
	CertPath         string   `json:"cert_path,omitempty"`
	KeyPath          string   `json:"key_path,omitempty"`
	CAPath           string   `json:"ca_path,omitempty"`
	CAKeyPath        string   `json:"ca_key_path,omitempty"`
	CRLPath          string   `json:"crl_path,omitempty"`
	StatePath        string   `json:"state_path,omitempty"`
	LogPath          string   `json:"log_path,omitempty"`
	PolicyPath       string   `json:"policy_path,omitempty"`
	Shell            string   `json:"shell,omitempty"`
	WaitBind         string   `json:"wait_bind,omitempty"`
	SANIPs           []string `json:"san_ips,omitempty"`
	SANDNS           []string `json:"san_dns,omitempty"`
	NoAutoSANs       bool     `json:"no_auto_sans,omitempty"`
}

// SaveServerDaemonConfig writes cfg as indented JSON to path (defaulting to DefaultPaths().ConfigPath
// when path is empty) and locks down both the parent directory and server.json via internal/acl.
func SaveServerDaemonConfig(path string, cfg *ServerDaemonConfig) error {
	if cfg == nil {
		return errors.New("server daemon config cannot be nil")
	}
	target := strings.TrimSpace(path)
	if target == "" {
		target = DefaultPaths().ConfigPath
	}
	cleanPath := filepath.Clean(target)
	parentDir := filepath.Dir(cleanPath)

	if err := acl.LockdownServerDir(parentDir); err != nil {
		return fmt.Errorf("failed to lock down server config directory %q: %w", parentDir, err)
	}

	encoded, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal server daemon config: %w", err)
	}
	encoded = append(encoded, '\n')

	if err := pki.WriteFileAtomic(cleanPath, encoded, 0o600); err != nil {
		return fmt.Errorf("failed to write server daemon config %q: %w", cleanPath, err)
	}
	if err := acl.LockdownPrivateFile(cleanPath); err != nil {
		return fmt.Errorf("failed to lock down server daemon config %q: %w", cleanPath, err)
	}
	return nil
}

// LoadServerDaemonConfig reads and parses a JSON ServerDaemonConfig from path (defaulting to
// DefaultPaths().ConfigPath when path is empty).
func LoadServerDaemonConfig(path string) (*ServerDaemonConfig, error) {
	target := strings.TrimSpace(path)
	if target == "" {
		target = DefaultPaths().ConfigPath
	}
	cleanPath := filepath.Clean(target)

	raw, err := os.ReadFile(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read server daemon config %q: %w", cleanPath, err)
	}
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))

	var cfg ServerDaemonConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse server daemon config %q: %w", cleanPath, err)
	}
	return &cfg, nil
}
