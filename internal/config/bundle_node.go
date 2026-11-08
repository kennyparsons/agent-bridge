package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/kennyparsons/agent-bridge/internal/acl"
	"github.com/kennyparsons/agent-bridge/internal/pki"
)

// InstallClientBundleOptions configures InstallClientBundleWithOptions.
type InstallClientBundleOptions struct {
	ConfigDir string
	Overwrite bool
	HomeDir   string
	GOOS      string
	EnvLookup func(key string) (string, bool)
}

// InstallClientBundleResult describes the installed client PKI assets and configuration file.
type InstallClientBundleResult struct {
	ConfigDir      string   `json:"config_dir"`
	ConfigPath     string   `json:"config_path"`
	CACertPath     string   `json:"ca_cert_path"`
	ClientCertPath string   `json:"client_cert_path"`
	ClientKeyPath  string   `json:"client_key_path"`
	DefaultHost    string   `json:"default_host,omitempty"`
	InstalledHosts []string `json:"installed_hosts,omitempty"`
}

// ResolveNodeCertPaths returns the leaf certificate and private key paths inside dataDir,
// preferring server.{crt,key} if both exist on disk, falling back to peer.{crt,key} if both
// exist on disk, and defaulting to server.{crt,key} otherwise.
func ResolveNodeCertPaths(dataDir string) (certPath, keyPath string) {
	cleanDir := filepath.Clean(strings.TrimSpace(dataDir))
	srvCert := filepath.Join(cleanDir, pki.ServerCertFilename)
	srvKey := filepath.Join(cleanDir, pki.ServerKeyFilename)
	if regularFileExists(srvCert) && regularFileExists(srvKey) {
		return srvCert, srvKey
	}

	peerCert := filepath.Join(cleanDir, pki.PeerCertFilename)
	peerKey := filepath.Join(cleanDir, pki.PeerKeyFilename)
	if regularFileExists(peerCert) && regularFileExists(peerKey) {
		return peerCert, peerKey
	}

	return srvCert, srvKey
}

// DefaultServerPathsForOS returns the standard OS server DataDir, ConfigPath (server.json), and LogPath.
func DefaultServerPathsForOS(goos string) (dataDir, configPath, logPath string) {
	switch strings.ToLower(strings.TrimSpace(goos)) {
	case "windows":
		return `C:\ProgramData\agent-bridge\node`,
			`C:\ProgramData\agent-bridge\server.json`,
			`C:\ProgramData\agent-bridge\logs\daemon.log`
	case "darwin":
		return "/Library/Application Support/agent-bridge/node",
			"/Library/Application Support/agent-bridge/server.json",
			"/Library/Logs/agent-bridge/daemon.log"
	default:
		return "/var/lib/agent-bridge/node",
			"/etc/agent-bridge/server.json",
			"/var/log/agent-bridge/daemon.log"
	}
}

// DefaultClientConfigDir resolves the target client configuration directory
// (`%APPDATA%\agent-bridge` on Windows, `~/.config/agent-bridge` on Unix).
func DefaultClientConfigDir() (string, error) {
	homeDir, _ := os.UserHomeDir()
	dir := resolveTargetClientConfigDir(runtime.GOOS, homeDir, os.LookupEnv)
	if dir == "" {
		return "", errors.New("unable to determine default client configuration directory")
	}
	return dir, nil
}

func resolveTargetClientConfigDir(goos, homeDir string, envLookup func(string) (string, bool)) string {
	if envLookup == nil {
		envLookup = os.LookupEnv
	}
	if strings.EqualFold(goos, "windows") {
		if appData, ok := envLookup("APPDATA"); ok && strings.TrimSpace(appData) != "" {
			return filepath.Join(strings.TrimSpace(appData), GlobalConfigSubdir)
		}
	}
	if homeDir != "" {
		return filepath.Join(homeDir, ".config", GlobalConfigSubdir)
	}
	return ""
}

// InstallClientBundle installs a parsed ClientBundle into configDir (or the OS default client
// configuration directory when configDir is empty), locking down directories and private files via internal/acl.
func InstallClientBundle(bundle *pki.ClientBundle, configDir string) (*InstallClientBundleResult, error) {
	return InstallClientBundleWithOptions(bundle, InstallClientBundleOptions{
		ConfigDir: configDir,
	})
}

// InstallClientBundleWithOptions installs a parsed ClientBundle with hermetic path/OS overrides.
func InstallClientBundleWithOptions(bundle *pki.ClientBundle, opts InstallClientBundleOptions) (*InstallClientBundleResult, error) {
	if bundle == nil {
		return nil, errors.New("client bundle cannot be nil")
	}
	if err := bundle.Validate(); err != nil {
		return nil, err
	}

	goos := strings.TrimSpace(opts.GOOS)
	if goos == "" {
		goos = runtime.GOOS
	}
	envLookup := opts.EnvLookup
	if envLookup == nil {
		envLookup = os.LookupEnv
	}
	homeDir := strings.TrimSpace(opts.HomeDir)
	if homeDir == "" {
		if detectedHome, err := os.UserHomeDir(); err == nil {
			homeDir = detectedHome
		}
	}

	var targetDir string
	if explicit := strings.TrimSpace(opts.ConfigDir); explicit != "" {
		expanded, err := expandAndResolvePath(explicit, homeDir, "")
		if err != nil {
			return nil, fmt.Errorf("invalid client config directory %q: %w", explicit, err)
		}
		targetDir = expanded
	} else {
		targetDir = resolveTargetClientConfigDir(goos, homeDir, envLookup)
	}
	if targetDir == "" {
		return nil, errors.New("unable to determine client configuration directory")
	}

	if err := acl.LockdownClientDir(targetDir); err != nil {
		return nil, fmt.Errorf("failed to lock down client config directory %q: %w", targetDir, err)
	}

	caCertPath := filepath.Join(targetDir, pki.CACertFilename)
	clientCertPath := filepath.Join(targetDir, pki.ClientCertFilename)
	clientKeyPath := filepath.Join(targetDir, pki.ClientKeyFilename)
	configPath := filepath.Join(targetDir, GlobalConfigFilename)

	if err := pki.WriteFileAtomic(caCertPath, ensureTrailingNewline([]byte(bundle.CACertPEM)), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write %q: %w", caCertPath, err)
	}
	if err := pki.WriteFileAtomic(clientCertPath, ensureTrailingNewline([]byte(bundle.ClientCertPEM)), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write %q: %w", clientCertPath, err)
	}
	if err := pki.WriteFileAtomic(clientKeyPath, ensureTrailingNewline([]byte(bundle.ClientKeyPEM)), 0o600); err != nil {
		return nil, fmt.Errorf("failed to write %q: %w", clientKeyPath, err)
	}
	if err := acl.LockdownClientFile(clientKeyPath); err != nil {
		return nil, fmt.Errorf("failed to lock down client private key %q: %w", clientKeyPath, err)
	}

	var merged FileConfig
	if !opts.Overwrite {
		if existing, err := loadOptionalFileConfig(configPath); err == nil && existing != nil {
			merged = *existing
		}
	}
	if merged.Hosts == nil && len(bundle.Hosts) > 0 {
		merged.Hosts = make(map[string]HostConfig, len(bundle.Hosts))
	}

	var installedHosts []string
	for name, hb := range bundle.Hosts {
		trimmedName := strings.TrimSpace(name)
		if trimmedName == "" {
			continue
		}
		if merged.Hosts == nil {
			merged.Hosts = make(map[string]HostConfig)
		}
		merged.Hosts[trimmedName] = HostConfig{
			Endpoint:        strings.TrimSpace(hb.Endpoint),
			ClusterEndpoint: strings.TrimSpace(hb.ClusterEndpoint),
			Timeout:         strings.TrimSpace(hb.Timeout),
		}
		installedHosts = append(installedHosts, trimmedName)
	}
	sort.Strings(installedHosts)

	merged.CACert = caCertPath
	merged.ClientCert = clientCertPath
	merged.ClientKey = clientKeyPath

	if dh := strings.TrimSpace(bundle.DefaultHost); dh != "" {
		merged.DefaultHost = dh
	}
	if ep := strings.TrimSpace(bundle.Endpoint); ep != "" {
		merged.Endpoint = ep
	}
	if cep := strings.TrimSpace(bundle.ClusterEndpoint); cep != "" {
		merged.ClusterEndpoint = cep
	}
	if to := strings.TrimSpace(bundle.Timeout); to != "" {
		merged.Timeout = to
	}

	cfgBytes, err := json.MarshalIndent(&merged, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to encode %q: %w", configPath, err)
	}
	cfgBytes = append(cfgBytes, '\n')

	if err := pki.WriteFileAtomic(configPath, cfgBytes, 0o600); err != nil {
		return nil, fmt.Errorf("failed to write %q: %w", configPath, err)
	}
	if err := acl.LockdownClientFile(configPath); err != nil {
		return nil, fmt.Errorf("failed to lock down %q: %w", configPath, err)
	}

	return &InstallClientBundleResult{
		ConfigDir:      targetDir,
		ConfigPath:     configPath,
		CACertPath:     caCertPath,
		ClientCertPath: clientCertPath,
		ClientKeyPath:  clientKeyPath,
		DefaultHost:    merged.DefaultHost,
		InstalledHosts: installedHosts,
	}, nil
}

type serverDaemonConfigSubset struct {
	ClusterBindSpecs []string `json:"cluster_bind_specs"`
	ClusterAdvertise string   `json:"cluster_advertise"`
	DataDir          string   `json:"data_dir"`
	CertPath         string   `json:"cert_path"`
	KeyPath          string   `json:"key_path"`
	CAPath           string   `json:"ca_path"`
}

type serverLocalFallback struct {
	certPath    string
	keyPath     string
	caPath      string
	clusterAddr string
}

func resolveServerLocalClusterFallback(opts ResolveOptions, goos, homeDir string) serverLocalFallback {
	defDataDir, defCfgPath, _ := DefaultServerPathsForOS(goos)

	srvCfgPath := strings.TrimSpace(opts.ServerConfigPath)
	if srvCfgPath == "" {
		srvCfgPath = defCfgPath
	}
	dataDir := strings.TrimSpace(opts.ServerDataDir)
	if dataDir == "" {
		dataDir = defDataDir
	}

	var out serverLocalFallback
	clusterPort := DefaultClusterPort

	if srvCfgPath != "" {
		if raw, err := os.ReadFile(srvCfgPath); err == nil {
			raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
			var parsed serverDaemonConfigSubset
			if json.Unmarshal(raw, &parsed) == nil {
				baseDir := filepath.Dir(srvCfgPath)
				if d := strings.TrimSpace(parsed.DataDir); d != "" {
					dataDir = ExpandPath(d, homeDir, baseDir)
				}
				if c := strings.TrimSpace(parsed.CertPath); c != "" {
					candCert := ExpandPath(c, homeDir, baseDir)
					if k := strings.TrimSpace(parsed.KeyPath); k != "" {
						candKey := ExpandPath(k, homeDir, baseDir)
						if regularFileExists(candCert) && regularFileExists(candKey) {
							out.certPath = candCert
							out.keyPath = candKey
						}
					}
				}
				if ca := strings.TrimSpace(parsed.CAPath); ca != "" {
					candCA := ExpandPath(ca, homeDir, baseDir)
					if regularFileExists(candCA) {
						out.caPath = candCA
					}
				}
				if p := extractClusterPortFromSpecs(parsed.ClusterBindSpecs, parsed.ClusterAdvertise); p > 0 {
					clusterPort = p
				}
			}
		}
	}

	if dataDir != "" {
		if out.certPath == "" || out.keyPath == "" {
			candCert, candKey := ResolveNodeCertPaths(dataDir)
			if regularFileExists(candCert) && regularFileExists(candKey) {
				out.certPath = candCert
				out.keyPath = candKey
			}
		}
		if out.caPath == "" {
			candCA := filepath.Join(dataDir, pki.CACertFilename)
			if regularFileExists(candCA) {
				out.caPath = candCA
			}
		}
	}

	if out.certPath != "" && out.keyPath != "" && out.caPath != "" {
		out.clusterAddr = net.JoinHostPort("127.0.0.1", strconv.Itoa(clusterPort))
	}
	return out
}

func extractClusterPortFromSpecs(bindSpecs []string, advertise string) int {
	for _, spec := range bindSpecs {
		if p := parsePortSuffix(spec); p > 0 {
			return p
		}
	}
	if p := parsePortSuffix(advertise); p > 0 {
		return p
	}
	return 0
}

func parsePortSuffix(spec string) int {
	trimmed := strings.TrimSpace(spec)
	if trimmed == "" {
		return 0
	}
	if idx := strings.Index(trimmed, "://"); idx != -1 {
		trimmed = trimmed[idx+3:]
	}
	if slashIdx := strings.IndexByte(trimmed, '/'); slashIdx != -1 {
		trimmed = trimmed[:slashIdx]
	}
	_, portStr, err := net.SplitHostPort(trimmed)
	if err != nil {
		return 0
	}
	portNum, convErr := strconv.Atoi(portStr)
	if convErr != nil || portNum < 1 || portNum > 65535 {
		return 0
	}
	return portNum
}

func regularFileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func ensureTrailingNewline(b []byte) []byte {
	trimmed := bytes.TrimRight(b, "\r\n")
	out := make([]byte, len(trimmed)+1)
	copy(out, trimmed)
	out[len(trimmed)] = '\n'
	return out
}
