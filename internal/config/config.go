package config

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/protocol"
)

const (
	// Environment variable keys supported in both process environment and CWD .env files.
	EnvHost        = "AGENT_BRIDGE_HOST"
	EnvEndpoint    = "AGENT_BRIDGE_ENDPOINT"
	EnvClusterAddr = "AGENT_BRIDGE_CLUSTER_ADDR"
	EnvCA          = "AGENT_BRIDGE_CA"
	EnvCert        = "AGENT_BRIDGE_CERT"
	EnvKey         = "AGENT_BRIDGE_KEY"
	EnvTimeout     = "AGENT_BRIDGE_TIMEOUT"

	// Default cluster control-plane listener port and loopback endpoint for `agent-bridge cluster` commands.
	DefaultClusterPort     = 8444
	DefaultClusterEndpoint = "127.0.0.1:8444"

	// Standard configuration filenames and directory names.
	LocalConfigFilename  = "agent-bridge.json"
	DotEnvFilename       = ".env"
	GlobalConfigSubdir   = "agent-bridge"
	GlobalConfigFilename = "config.json"
)

// FlagOverrides captures explicit CLI flags passed to `agent-bridge exec`.
// Empty fields indicate the flag was omitted by the caller.
type FlagOverrides struct {
	Host     string
	Endpoint string
	CertPath string
	KeyPath  string
	CAPath   string
	Timeout  string
}

// Flags is a convenience alias for FlagOverrides.
type Flags = FlagOverrides

// ClusterFlagOverrides captures explicit CLI flags passed to `agent-bridge cluster` subcommands.
// Empty fields indicate the flag was omitted by the caller.
type ClusterFlagOverrides struct {
	Host        string
	ClusterAddr string // --cluster-addr <ip:port> or https://...
	CertPath    string
	KeyPath     string
	CAPath      string
	Timeout     string
}

// ClusterFlags is a convenience alias for ClusterFlagOverrides.
type ClusterFlags = ClusterFlagOverrides

// HostConfig defines per-host connection parameters inside a JSON configuration file.
type HostConfig struct {
	Endpoint        string `json:"endpoint,omitempty"`
	ClusterEndpoint string `json:"cluster_endpoint,omitempty"`
	Timeout         string `json:"timeout,omitempty"`
}

// FileConfig represents the JSON schema shared by global (`~/.config/agent-bridge/config.json`
// or `%APPDATA%\agent-bridge\config.json`) and project-local (`./agent-bridge.json`) files.
type FileConfig struct {
	DefaultHost     string                `json:"default_host,omitempty"`
	ClientCert      string                `json:"client_cert,omitempty"`
	ClientKey       string                `json:"client_key,omitempty"`
	CACert          string                `json:"ca_cert,omitempty"`
	Endpoint        string                `json:"endpoint,omitempty"`
	ClusterEndpoint string                `json:"cluster_endpoint,omitempty"`
	Timeout         string                `json:"timeout,omitempty"`
	Hosts           map[string]HostConfig `json:"hosts,omitempty"`
}

// ResolvedConfig holds the fully validated, normalized client configuration ready for mTLS dialing.
type ResolvedConfig struct {
	Host           string
	Endpoint       string
	WSURL          string
	CertPath       string
	KeyPath        string
	CAPath         string
	Timeout        time.Duration
	TimeoutSeconds int
}

// EffectiveTimeoutSeconds returns the command timeout in whole seconds clamped to [1, protocol.MaxTimeoutSeconds],
// defaulting to protocol.DefaultTimeoutSeconds when unset.
func (c *ResolvedConfig) EffectiveTimeoutSeconds() int {
	if c == nil {
		return protocol.DefaultTimeoutSeconds
	}
	return normalizeTimeoutSeconds(c.TimeoutSeconds, c.Timeout)
}

// EffectiveTimeout returns EffectiveTimeoutSeconds as a time.Duration.
func (c *ResolvedConfig) EffectiveTimeout() time.Duration {
	return time.Duration(c.EffectiveTimeoutSeconds()) * time.Second
}

// ResolvedClusterConfig holds the validated, normalized mTLS cluster control-plane configuration
// for `agent-bridge cluster {token-create, status, peers, sync}` subcommands.
type ResolvedClusterConfig struct {
	Host           string
	ClusterAddr    string // Normalized host:port (default port 8444 if omitted; defaults to 127.0.0.1:8444 if no host/cluster_endpoint specified)
	BaseHTTPSURL   string // "https://<host:port>"
	CertPath       string
	KeyPath        string
	CAPath         string
	Timeout        time.Duration
	TimeoutSeconds int
}

// EffectiveTimeoutSeconds returns the cluster request timeout in whole seconds clamped to [1, protocol.MaxTimeoutSeconds],
// defaulting to protocol.DefaultTimeoutSeconds when unset.
func (c *ResolvedClusterConfig) EffectiveTimeoutSeconds() int {
	if c == nil {
		return protocol.DefaultTimeoutSeconds
	}
	return normalizeTimeoutSeconds(c.TimeoutSeconds, c.Timeout)
}

// EffectiveTimeout returns EffectiveTimeoutSeconds as a time.Duration.
func (c *ResolvedClusterConfig) EffectiveTimeout() time.Duration {
	return time.Duration(c.EffectiveTimeoutSeconds()) * time.Second
}

func normalizeTimeoutSeconds(timeoutSec int, timeoutDur time.Duration) int {
	sec := timeoutSec
	if sec <= 0 && timeoutDur > 0 {
		sec = int((timeoutDur + time.Second - 1) / time.Second)
	}
	if sec <= 0 {
		return protocol.DefaultTimeoutSeconds
	}
	if sec > protocol.MaxTimeoutSeconds {
		return protocol.MaxTimeoutSeconds
	}
	return sec
}

// ResolveOptions enables hermetic injection of filesystem paths, OS behavior, and environment
// variable lookups during unit testing. Zero-valued fields fall back to real OS defaults.
type ResolveOptions struct {
	WorkDir          string
	GlobalConfigPath string
	HomeDir          string
	GOOS             string
	EnvLookup        func(key string) (string, bool)
}

// Resolve loads and merges client configuration using real OS working directory, home directory,
// global config location, and process environment variables.
func Resolve(flags FlagOverrides) (*ResolvedConfig, error) {
	return ResolveWithOptions(flags, ResolveOptions{})
}

// Merge named host dictionaries (localCfg.Hosts overrides globalCfg.Hosts field-by-field).
func mergeHostConfigs(globalCfg, localCfg *FileConfig) map[string]HostConfig {
	mergedHosts := make(map[string]HostConfig)
	if globalCfg != nil {
		for name, hc := range globalCfg.Hosts {
			trimmedName := strings.TrimSpace(name)
			if trimmedName == "" {
				continue
			}
			mergedHosts[trimmedName] = HostConfig{
				Endpoint:        strings.TrimSpace(hc.Endpoint),
				ClusterEndpoint: strings.TrimSpace(hc.ClusterEndpoint),
				Timeout:         strings.TrimSpace(hc.Timeout),
			}
		}
	}
	if localCfg != nil {
		for name, hc := range localCfg.Hosts {
			trimmedName := strings.TrimSpace(name)
			if trimmedName == "" {
				continue
			}
			existing := mergedHosts[trimmedName]
			if ep := strings.TrimSpace(hc.Endpoint); ep != "" {
				existing.Endpoint = ep
			}
			if cep := strings.TrimSpace(hc.ClusterEndpoint); cep != "" {
				existing.ClusterEndpoint = cep
			}
			if to := strings.TrimSpace(hc.Timeout); to != "" {
				existing.Timeout = to
			}
			mergedHosts[trimmedName] = existing
		}
	}
	return mergedHosts
}

type loadedLayers struct {
	envLookup     func(string) (string, bool)
	workDir       string
	homeDir       string
	globalCfgPath string
	globalBaseDir string
	localCfgPath  string
	dotEnvPath    string
	globalCfg     *FileConfig
	localCfg      *FileConfig
	dotEnv        map[string]string
	mergedHosts   map[string]HostConfig
}

func loadConfigLayers(opts ResolveOptions) (*loadedLayers, error) {
	envLookup := opts.EnvLookup
	if envLookup == nil {
		envLookup = os.LookupEnv
	}

	goos := strings.TrimSpace(opts.GOOS)
	if goos == "" {
		goos = runtime.GOOS
	}

	workDir := strings.TrimSpace(opts.WorkDir)
	if workDir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("failed to determine current working directory: %w", err)
		}
		workDir = cwd
	}

	homeDir := strings.TrimSpace(opts.HomeDir)
	if homeDir == "" {
		if detectedHome, err := os.UserHomeDir(); err == nil {
			homeDir = detectedHome
		}
	}

	globalCfgPath := strings.TrimSpace(opts.GlobalConfigPath)
	if globalCfgPath == "" {
		globalCfgPath = resolveGlobalConfigPath(goos, homeDir, envLookup)
	}

	var globalBaseDir string
	if globalCfgPath != "" {
		globalBaseDir = filepath.Dir(globalCfgPath)
	}

	var globalCfg *FileConfig
	if globalCfgPath != "" {
		loaded, err := loadOptionalFileConfig(globalCfgPath)
		if err != nil {
			return nil, err
		}
		globalCfg = loaded
	}

	localCfgPath := filepath.Join(workDir, LocalConfigFilename)
	localCfg, err := loadOptionalFileConfig(localCfgPath)
	if err != nil {
		return nil, err
	}

	dotEnvPath := filepath.Join(workDir, DotEnvFilename)
	dotEnv, err := loadOptionalDotEnv(dotEnvPath)
	if err != nil {
		return nil, err
	}

	return &loadedLayers{
		envLookup:     envLookup,
		workDir:       workDir,
		homeDir:       homeDir,
		globalCfgPath: globalCfgPath,
		globalBaseDir: globalBaseDir,
		localCfgPath:  localCfgPath,
		dotEnvPath:    dotEnvPath,
		globalCfg:     globalCfg,
		localCfg:      localCfg,
		dotEnv:        dotEnv,
		mergedHosts:   mergeHostConfigs(globalCfg, localCfg),
	}, nil
}

// ResolveWithOptions loads and merges client configuration across all four precedence tiers:
//  1. Explicit CLI Flags (`flags`)
//  2. Project-Local Overrides (Process Env > CWD `.env` > CWD `agent-bridge.json`)
//  3. Global User Configuration (`~/.config/agent-bridge/config.json` or `%APPDATA%\agent-bridge\config.json`)
//  4. Hardcoded Defaults (`Timeout = 60s`, default port `8443`)
func ResolveWithOptions(flags FlagOverrides, opts ResolveOptions) (*ResolvedConfig, error) {
	layers, err := loadConfigLayers(opts)
	if err != nil {
		return nil, err
	}

	// Track each asset path alongside the base directory of the tier that supplied it:
	// global config.json resolves relative paths against filepath.Dir(globalCfgPath),
	// whereas CWD agent-bridge.json, .env, process env, and CLI flags resolve against workDir.
	type sourcedPath struct {
		raw     string
		baseDir string
	}

	lookupTrimmed := func(key string) string {
		val, ok := layers.envLookup(key)
		if !ok {
			return ""
		}
		return strings.TrimSpace(val)
	}

	var (
		certSrc          sourcedPath
		keySrc           sourcedPath
		caSrc            sourcedPath
		selectedHost     string
		selectedHostTier int
		selectedHostDesc string
		directEndpoint   string
	)

	// Target & Asset Selection across Tiers 1..5 (without expanding non-winning host profiles).
	// Tier 1: Global config.json.
	var globalTimeout string
	if layers.globalCfg != nil {
		if v := strings.TrimSpace(layers.globalCfg.ClientCert); v != "" {
			certSrc = sourcedPath{raw: v, baseDir: layers.globalBaseDir}
		}
		if v := strings.TrimSpace(layers.globalCfg.ClientKey); v != "" {
			keySrc = sourcedPath{raw: v, baseDir: layers.globalBaseDir}
		}
		if v := strings.TrimSpace(layers.globalCfg.CACert); v != "" {
			caSrc = sourcedPath{raw: v, baseDir: layers.globalBaseDir}
		}
		globalTimeout = strings.TrimSpace(layers.globalCfg.Timeout)

		globalDefaultHost := strings.TrimSpace(layers.globalCfg.DefaultHost)
		globalEndpoint := strings.TrimSpace(layers.globalCfg.Endpoint)
		if globalDefaultHost != "" {
			selectedHost = globalDefaultHost
			selectedHostTier = 1
			selectedHostDesc = "default_host in " + layers.globalCfgPath
			directEndpoint = ""
		} else if globalEndpoint != "" {
			directEndpoint = globalEndpoint
		}
	}

	// Tier 2: Project-local agent-bridge.json in CWD.
	var localTimeout string
	if layers.localCfg != nil {
		if v := strings.TrimSpace(layers.localCfg.ClientCert); v != "" {
			certSrc = sourcedPath{raw: v, baseDir: layers.workDir}
		}
		if v := strings.TrimSpace(layers.localCfg.ClientKey); v != "" {
			keySrc = sourcedPath{raw: v, baseDir: layers.workDir}
		}
		if v := strings.TrimSpace(layers.localCfg.CACert); v != "" {
			caSrc = sourcedPath{raw: v, baseDir: layers.workDir}
		}
		localTimeout = strings.TrimSpace(layers.localCfg.Timeout)

		localDefaultHost := strings.TrimSpace(layers.localCfg.DefaultHost)
		localEndpoint := strings.TrimSpace(layers.localCfg.Endpoint)
		switch {
		case localDefaultHost != "" && localEndpoint != "":
			selectedHost = localDefaultHost
			selectedHostTier = 2
			selectedHostDesc = "default_host in " + layers.localCfgPath
			directEndpoint = localEndpoint
		case localDefaultHost != "":
			selectedHost = localDefaultHost
			selectedHostTier = 2
			selectedHostDesc = "default_host in " + layers.localCfgPath
			directEndpoint = ""
		case localEndpoint != "":
			selectedHost = ""
			selectedHostTier = 0
			selectedHostDesc = ""
			directEndpoint = localEndpoint
		}
	}

	// Tier 3: Project-local .env file in CWD.
	var dotTimeout string
	if layers.dotEnv != nil {
		if v := strings.TrimSpace(layers.dotEnv[EnvCert]); v != "" {
			certSrc = sourcedPath{raw: v, baseDir: layers.workDir}
		}
		if v := strings.TrimSpace(layers.dotEnv[EnvKey]); v != "" {
			keySrc = sourcedPath{raw: v, baseDir: layers.workDir}
		}
		if v := strings.TrimSpace(layers.dotEnv[EnvCA]); v != "" {
			caSrc = sourcedPath{raw: v, baseDir: layers.workDir}
		}
		dotTimeout = strings.TrimSpace(layers.dotEnv[EnvTimeout])

		dotHost := strings.TrimSpace(layers.dotEnv[EnvHost])
		dotEndpoint := strings.TrimSpace(layers.dotEnv[EnvEndpoint])
		switch {
		case dotHost != "" && dotEndpoint != "":
			selectedHost = dotHost
			selectedHostTier = 3
			selectedHostDesc = fmt.Sprintf("%s in %s", EnvHost, layers.dotEnvPath)
			directEndpoint = dotEndpoint
		case dotHost != "":
			selectedHost = dotHost
			selectedHostTier = 3
			selectedHostDesc = fmt.Sprintf("%s in %s", EnvHost, layers.dotEnvPath)
			directEndpoint = ""
		case dotEndpoint != "":
			selectedHost = ""
			selectedHostTier = 0
			selectedHostDesc = ""
			directEndpoint = dotEndpoint
		}
	}

	// Tier 4: Process environment variables.
	if v := lookupTrimmed(EnvCert); v != "" {
		certSrc = sourcedPath{raw: v, baseDir: layers.workDir}
	}
	if v := lookupTrimmed(EnvKey); v != "" {
		keySrc = sourcedPath{raw: v, baseDir: layers.workDir}
	}
	if v := lookupTrimmed(EnvCA); v != "" {
		caSrc = sourcedPath{raw: v, baseDir: layers.workDir}
	}
	procTimeout := lookupTrimmed(EnvTimeout)
	procHost := lookupTrimmed(EnvHost)
	procEndpoint := lookupTrimmed(EnvEndpoint)
	switch {
	case procHost != "" && procEndpoint != "":
		selectedHost = procHost
		selectedHostTier = 4
		selectedHostDesc = EnvHost + " environment variable"
		directEndpoint = procEndpoint
	case procHost != "":
		selectedHost = procHost
		selectedHostTier = 4
		selectedHostDesc = EnvHost + " environment variable"
		directEndpoint = ""
	case procEndpoint != "":
		selectedHost = ""
		selectedHostTier = 0
		selectedHostDesc = ""
		directEndpoint = procEndpoint
	}

	// Tier 5: Explicit CLI Flags (highest priority).
	if v := strings.TrimSpace(flags.CertPath); v != "" {
		certSrc = sourcedPath{raw: v, baseDir: layers.workDir}
	}
	if v := strings.TrimSpace(flags.KeyPath); v != "" {
		keySrc = sourcedPath{raw: v, baseDir: layers.workDir}
	}
	if v := strings.TrimSpace(flags.CAPath); v != "" {
		caSrc = sourcedPath{raw: v, baseDir: layers.workDir}
	}
	flagTimeout := strings.TrimSpace(flags.Timeout)
	flagHost := strings.TrimSpace(flags.Host)
	flagEndpoint := strings.TrimSpace(flags.Endpoint)
	switch {
	case flagHost != "" && flagEndpoint != "":
		selectedHost = flagHost
		selectedHostTier = 5
		selectedHostDesc = "--host"
		directEndpoint = flagEndpoint
	case flagHost != "":
		selectedHost = flagHost
		selectedHostTier = 5
		selectedHostDesc = "--host"
		directEndpoint = ""
	case flagEndpoint != "":
		selectedHost = ""
		selectedHostTier = 0
		selectedHostDesc = ""
		directEndpoint = flagEndpoint
	}

	// Expand ONLY the single winning host profile so non-selected hosts (such as default_host)
	// can never leak their endpoint or timeout into another host selection.
	var winningHostCfg HostConfig
	if selectedHost != "" {
		hc, ok := layers.mergedHosts[selectedHost]
		if !ok {
			return nil, fmt.Errorf("unknown host %q specified via %s (not found in configured hosts)", selectedHost, selectedHostDesc)
		}
		winningHostCfg = hc
	}

	var rawEndpoint string
	if directEndpoint != "" {
		rawEndpoint = directEndpoint
	} else if selectedHost != "" {
		rawEndpoint = winningHostCfg.Endpoint
		if rawEndpoint == "" {
			return nil, fmt.Errorf("missing target endpoint: host %q in configured hosts has no endpoint configured", selectedHost)
		}
	}

	// Timeout precedence:
	//   Hardcoded 60s < globalCfg.Timeout < localCfg.Timeout < winningHostCfg.Timeout
	//   (except localCfg.Timeout overrides a Tier-1 globalCfg default_host timeout unless localCfg.Hosts also set it)
	//   < .env AGENT_BRIDGE_TIMEOUT < process env AGENT_BRIDGE_TIMEOUT < CLI --timeout.
	rawTimeout := strconv.Itoa(protocol.DefaultTimeoutSeconds) + "s"
	if globalTimeout != "" {
		rawTimeout = globalTimeout
	}
	if selectedHost != "" && selectedHostTier == 1 && winningHostCfg.Timeout != "" {
		rawTimeout = winningHostCfg.Timeout
	}
	if localTimeout != "" {
		rawTimeout = localTimeout
	}
	if selectedHost != "" && selectedHostTier >= 2 && winningHostCfg.Timeout != "" {
		rawTimeout = winningHostCfg.Timeout
	}
	if dotTimeout != "" {
		rawTimeout = dotTimeout
	}
	if procTimeout != "" {
		rawTimeout = procTimeout
	}
	if flagTimeout != "" {
		rawTimeout = flagTimeout
	}

	// Validate required fields before dialing.
	if strings.TrimSpace(rawEndpoint) == "" {
		return nil, errors.New("missing target endpoint: specify --endpoint, --host, AGENT_BRIDGE_ENDPOINT, or default_host in config.json")
	}
	if strings.TrimSpace(certSrc.raw) == "" {
		return nil, errors.New("missing client certificate path: specify --cert, AGENT_BRIDGE_CERT, or client_cert in config.json")
	}
	if strings.TrimSpace(keySrc.raw) == "" {
		return nil, errors.New("missing client private key path: specify --key, AGENT_BRIDGE_KEY, or client_key in config.json")
	}
	if strings.TrimSpace(caSrc.raw) == "" {
		return nil, errors.New("missing Root CA certificate path: specify --ca, AGENT_BRIDGE_CA, or ca_cert in config.json")
	}

	hostPort, wsURL, err := NormalizeEndpoint(rawEndpoint)
	if err != nil {
		return nil, err
	}

	timeoutDur, timeoutSec, err := ParseTimeout(rawTimeout)
	if err != nil {
		return nil, err
	}

	certPath, err := expandAndResolvePath(certSrc.raw, layers.homeDir, certSrc.baseDir)
	if err != nil {
		return nil, fmt.Errorf("invalid client certificate path %q: %w", certSrc.raw, err)
	}
	keyPath, err := expandAndResolvePath(keySrc.raw, layers.homeDir, keySrc.baseDir)
	if err != nil {
		return nil, fmt.Errorf("invalid client private key path %q: %w", keySrc.raw, err)
	}
	caPath, err := expandAndResolvePath(caSrc.raw, layers.homeDir, caSrc.baseDir)
	if err != nil {
		return nil, fmt.Errorf("invalid Root CA certificate path %q: %w", caSrc.raw, err)
	}

	return &ResolvedConfig{
		Host:           selectedHost,
		Endpoint:       hostPort,
		WSURL:          wsURL,
		CertPath:       certPath,
		KeyPath:        keyPath,
		CAPath:         caPath,
		Timeout:        timeoutDur,
		TimeoutSeconds: timeoutSec,
	}, nil
}

// ResolveClusterConfig loads and merges cluster administration client configuration using real OS
// working directory, home directory, global config location, and process environment variables.
func ResolveClusterConfig(flags ClusterFlagOverrides) (*ResolvedClusterConfig, error) {
	return ResolveClusterConfigWithOptions(flags, ResolveOptions{})
}

// ResolveClusterConfigWithOptions resolves mTLS cluster control-plane target and credentials for
// `agent-bridge cluster {token-create, status, peers, sync}` subcommands.
//
// ClusterAddr Precedence:
//  1. `flags.ClusterAddr` (`--cluster-addr`)
//  2. Process env `AGENT_BRIDGE_CLUSTER_ADDR`
//  3. CWD `.env` `AGENT_BRIDGE_CLUSTER_ADDR`
//  4. Selected host's `HostConfig.ClusterEndpoint` or `localCfg.ClusterEndpoint` / `globalCfg.ClusterEndpoint`
//  5. `DefaultClusterEndpoint` (`"127.0.0.1:8444"`) when no explicit host/cluster address is set
func ResolveClusterConfigWithOptions(flags ClusterFlagOverrides, opts ResolveOptions) (*ResolvedClusterConfig, error) {
	layers, err := loadConfigLayers(opts)
	if err != nil {
		return nil, err
	}

	type sourcedPath struct {
		raw     string
		baseDir string
	}

	lookupTrimmed := func(key string) string {
		val, ok := layers.envLookup(key)
		if !ok {
			return ""
		}
		return strings.TrimSpace(val)
	}

	var (
		certSrc           sourcedPath
		keySrc            sourcedPath
		caSrc             sourcedPath
		selectedHost      string
		selectedHostTier  int
		selectedHostDesc  string
		directClusterAddr string
	)

	// Tier 1: Global config.json.
	var globalTimeout string
	if layers.globalCfg != nil {
		if v := strings.TrimSpace(layers.globalCfg.ClientCert); v != "" {
			certSrc = sourcedPath{raw: v, baseDir: layers.globalBaseDir}
		}
		if v := strings.TrimSpace(layers.globalCfg.ClientKey); v != "" {
			keySrc = sourcedPath{raw: v, baseDir: layers.globalBaseDir}
		}
		if v := strings.TrimSpace(layers.globalCfg.CACert); v != "" {
			caSrc = sourcedPath{raw: v, baseDir: layers.globalBaseDir}
		}
		globalTimeout = strings.TrimSpace(layers.globalCfg.Timeout)

		globalDefaultHost := strings.TrimSpace(layers.globalCfg.DefaultHost)
		globalClusterEp := strings.TrimSpace(layers.globalCfg.ClusterEndpoint)
		if globalDefaultHost != "" {
			selectedHost = globalDefaultHost
			selectedHostTier = 1
			selectedHostDesc = "default_host in " + layers.globalCfgPath
			directClusterAddr = ""
		} else if globalClusterEp != "" {
			directClusterAddr = globalClusterEp
		}
	}

	// Tier 2: Project-local agent-bridge.json in CWD.
	var localTimeout string
	if layers.localCfg != nil {
		if v := strings.TrimSpace(layers.localCfg.ClientCert); v != "" {
			certSrc = sourcedPath{raw: v, baseDir: layers.workDir}
		}
		if v := strings.TrimSpace(layers.localCfg.ClientKey); v != "" {
			keySrc = sourcedPath{raw: v, baseDir: layers.workDir}
		}
		if v := strings.TrimSpace(layers.localCfg.CACert); v != "" {
			caSrc = sourcedPath{raw: v, baseDir: layers.workDir}
		}
		localTimeout = strings.TrimSpace(layers.localCfg.Timeout)

		localDefaultHost := strings.TrimSpace(layers.localCfg.DefaultHost)
		localClusterEp := strings.TrimSpace(layers.localCfg.ClusterEndpoint)
		switch {
		case localDefaultHost != "" && localClusterEp != "":
			selectedHost = localDefaultHost
			selectedHostTier = 2
			selectedHostDesc = "default_host in " + layers.localCfgPath
			directClusterAddr = localClusterEp
		case localDefaultHost != "":
			selectedHost = localDefaultHost
			selectedHostTier = 2
			selectedHostDesc = "default_host in " + layers.localCfgPath
			directClusterAddr = ""
		case localClusterEp != "":
			selectedHost = ""
			selectedHostTier = 0
			selectedHostDesc = ""
			directClusterAddr = localClusterEp
		}
	}

	// Tier 3: Project-local .env file in CWD.
	var dotTimeout string
	if layers.dotEnv != nil {
		if v := strings.TrimSpace(layers.dotEnv[EnvCert]); v != "" {
			certSrc = sourcedPath{raw: v, baseDir: layers.workDir}
		}
		if v := strings.TrimSpace(layers.dotEnv[EnvKey]); v != "" {
			keySrc = sourcedPath{raw: v, baseDir: layers.workDir}
		}
		if v := strings.TrimSpace(layers.dotEnv[EnvCA]); v != "" {
			caSrc = sourcedPath{raw: v, baseDir: layers.workDir}
		}
		dotTimeout = strings.TrimSpace(layers.dotEnv[EnvTimeout])

		dotHost := strings.TrimSpace(layers.dotEnv[EnvHost])
		dotClusterAddr := strings.TrimSpace(layers.dotEnv[EnvClusterAddr])
		switch {
		case dotHost != "" && dotClusterAddr != "":
			selectedHost = dotHost
			selectedHostTier = 3
			selectedHostDesc = fmt.Sprintf("%s in %s", EnvHost, layers.dotEnvPath)
			directClusterAddr = dotClusterAddr
		case dotHost != "":
			selectedHost = dotHost
			selectedHostTier = 3
			selectedHostDesc = fmt.Sprintf("%s in %s", EnvHost, layers.dotEnvPath)
			directClusterAddr = ""
		case dotClusterAddr != "":
			selectedHost = ""
			selectedHostTier = 0
			selectedHostDesc = ""
			directClusterAddr = dotClusterAddr
		}
	}

	// Tier 4: Process environment variables.
	if v := lookupTrimmed(EnvCert); v != "" {
		certSrc = sourcedPath{raw: v, baseDir: layers.workDir}
	}
	if v := lookupTrimmed(EnvKey); v != "" {
		keySrc = sourcedPath{raw: v, baseDir: layers.workDir}
	}
	if v := lookupTrimmed(EnvCA); v != "" {
		caSrc = sourcedPath{raw: v, baseDir: layers.workDir}
	}
	procTimeout := lookupTrimmed(EnvTimeout)
	procHost := lookupTrimmed(EnvHost)
	procClusterAddr := lookupTrimmed(EnvClusterAddr)
	switch {
	case procHost != "" && procClusterAddr != "":
		selectedHost = procHost
		selectedHostTier = 4
		selectedHostDesc = EnvHost + " environment variable"
		directClusterAddr = procClusterAddr
	case procHost != "":
		selectedHost = procHost
		selectedHostTier = 4
		selectedHostDesc = EnvHost + " environment variable"
		directClusterAddr = ""
	case procClusterAddr != "":
		selectedHost = ""
		selectedHostTier = 0
		selectedHostDesc = ""
		directClusterAddr = procClusterAddr
	}

	// Tier 5: Explicit CLI Flags (highest priority).
	if v := strings.TrimSpace(flags.CertPath); v != "" {
		certSrc = sourcedPath{raw: v, baseDir: layers.workDir}
	}
	if v := strings.TrimSpace(flags.KeyPath); v != "" {
		keySrc = sourcedPath{raw: v, baseDir: layers.workDir}
	}
	if v := strings.TrimSpace(flags.CAPath); v != "" {
		caSrc = sourcedPath{raw: v, baseDir: layers.workDir}
	}
	flagTimeout := strings.TrimSpace(flags.Timeout)
	flagHost := strings.TrimSpace(flags.Host)
	flagClusterAddr := strings.TrimSpace(flags.ClusterAddr)
	switch {
	case flagHost != "" && flagClusterAddr != "":
		selectedHost = flagHost
		selectedHostTier = 5
		selectedHostDesc = "--host"
		directClusterAddr = flagClusterAddr
	case flagHost != "":
		selectedHost = flagHost
		selectedHostTier = 5
		selectedHostDesc = "--host"
		directClusterAddr = ""
	case flagClusterAddr != "":
		selectedHost = ""
		selectedHostTier = 0
		selectedHostDesc = ""
		directClusterAddr = flagClusterAddr
	}

	var winningHostCfg HostConfig
	if selectedHost != "" {
		hc, ok := layers.mergedHosts[selectedHost]
		if !ok {
			return nil, fmt.Errorf("unknown host %q specified via %s (not found in configured hosts)", selectedHost, selectedHostDesc)
		}
		winningHostCfg = hc
	}

	var rawClusterAddr string
	if directClusterAddr != "" {
		rawClusterAddr = directClusterAddr
	} else if selectedHost != "" {
		if winningHostCfg.ClusterEndpoint != "" {
			rawClusterAddr = winningHostCfg.ClusterEndpoint
		} else if selectedHostTier >= 3 {
			// Caller explicitly requested --host or AGENT_BRIDGE_HOST, so never silently fall back to 127.0.0.1:8444.
			return nil, fmt.Errorf("missing cluster endpoint: host %q in configured hosts has no cluster_endpoint configured", selectedHost)
		} else {
			// Passive default_host in config.json/agent-bridge.json only configured exec endpoint;
			// check top-level cluster_endpoint or fall back cleanly to local 127.0.0.1:8444.
			selectedHost = ""
			selectedHostTier = 0
			winningHostCfg = HostConfig{}
			if layers.localCfg != nil && strings.TrimSpace(layers.localCfg.ClusterEndpoint) != "" {
				rawClusterAddr = strings.TrimSpace(layers.localCfg.ClusterEndpoint)
			} else if layers.globalCfg != nil && strings.TrimSpace(layers.globalCfg.ClusterEndpoint) != "" {
				rawClusterAddr = strings.TrimSpace(layers.globalCfg.ClusterEndpoint)
			}
		}
	}

	if rawClusterAddr == "" {
		rawClusterAddr = DefaultClusterEndpoint
	}

	rawTimeout := strconv.Itoa(protocol.DefaultTimeoutSeconds) + "s"
	if globalTimeout != "" {
		rawTimeout = globalTimeout
	}
	if selectedHost != "" && selectedHostTier == 1 && winningHostCfg.Timeout != "" {
		rawTimeout = winningHostCfg.Timeout
	}
	if localTimeout != "" {
		rawTimeout = localTimeout
	}
	if selectedHost != "" && selectedHostTier >= 2 && winningHostCfg.Timeout != "" {
		rawTimeout = winningHostCfg.Timeout
	}
	if dotTimeout != "" {
		rawTimeout = dotTimeout
	}
	if procTimeout != "" {
		rawTimeout = procTimeout
	}
	if flagTimeout != "" {
		rawTimeout = flagTimeout
	}

	if strings.TrimSpace(certSrc.raw) == "" {
		return nil, errors.New("missing client certificate path: specify --cert, AGENT_BRIDGE_CERT, or client_cert in config.json")
	}
	if strings.TrimSpace(keySrc.raw) == "" {
		return nil, errors.New("missing client private key path: specify --key, AGENT_BRIDGE_KEY, or client_key in config.json")
	}
	if strings.TrimSpace(caSrc.raw) == "" {
		return nil, errors.New("missing Root CA certificate path: specify --ca, AGENT_BRIDGE_CA, or ca_cert in config.json")
	}

	clusterHostPort, baseHTTPSURL, err := NormalizeClusterAddr(rawClusterAddr)
	if err != nil {
		return nil, err
	}

	timeoutDur, timeoutSec, err := ParseTimeout(rawTimeout)
	if err != nil {
		return nil, err
	}

	certPath, err := expandAndResolvePath(certSrc.raw, layers.homeDir, certSrc.baseDir)
	if err != nil {
		return nil, fmt.Errorf("invalid client certificate path %q: %w", certSrc.raw, err)
	}
	keyPath, err := expandAndResolvePath(keySrc.raw, layers.homeDir, keySrc.baseDir)
	if err != nil {
		return nil, fmt.Errorf("invalid client private key path %q: %w", keySrc.raw, err)
	}
	caPath, err := expandAndResolvePath(caSrc.raw, layers.homeDir, caSrc.baseDir)
	if err != nil {
		return nil, fmt.Errorf("invalid Root CA certificate path %q: %w", caSrc.raw, err)
	}

	return &ResolvedClusterConfig{
		Host:           selectedHost,
		ClusterAddr:    clusterHostPort,
		BaseHTTPSURL:   baseHTTPSURL,
		CertPath:       certPath,
		KeyPath:        keyPath,
		CAPath:         caPath,
		Timeout:        timeoutDur,
		TimeoutSeconds: timeoutSec,
	}, nil
}

// DefaultGlobalConfigPath returns the platform-appropriate global configuration file path,
// checking `%APPDATA%\agent-bridge\config.json` first on Windows (falling back to
// `~/.config/agent-bridge/config.json` if the `%APPDATA%` file does not exist).
func DefaultGlobalConfigPath() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil && runtime.GOOS != "windows" {
		return "", fmt.Errorf("failed to resolve user home directory: %w", err)
	}
	p := resolveGlobalConfigPath(runtime.GOOS, homeDir, os.LookupEnv)
	if p == "" {
		return "", errors.New("unable to determine global configuration path")
	}
	return p, nil
}

func resolveGlobalConfigPath(goos, homeDir string, envLookup func(string) (string, bool)) string {
	var xdgFallback string
	if homeDir != "" {
		xdgFallback = filepath.Join(homeDir, ".config", GlobalConfigSubdir, GlobalConfigFilename)
	}

	if strings.EqualFold(goos, "windows") {
		if appData, ok := envLookup("APPDATA"); ok && strings.TrimSpace(appData) != "" {
			appDataCandidate := filepath.Join(strings.TrimSpace(appData), GlobalConfigSubdir, GlobalConfigFilename)
			if _, err := os.Stat(appDataCandidate); err == nil || !errors.Is(err, os.ErrNotExist) {
				return appDataCandidate
			}
			if xdgFallback == "" {
				return appDataCandidate
			}
		}
	}

	return xdgFallback
}

// NormalizeEndpoint normalizes IPv4, IPv6, or DNS endpoints (with or without explicit port or
// `wss://` / `https://` prefix) into canonical `host:port` (or `[ipv6]:port`) and `wss://<hostPort>/ws/exec`.
func NormalizeEndpoint(raw string) (hostPort string, wsURL string, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", errors.New("endpoint cannot be empty")
	}

	working := trimmed
	if idx := strings.Index(working, "://"); idx != -1 {
		scheme := strings.ToLower(strings.TrimSpace(working[:idx]))
		switch scheme {
		case "wss", "https":
			working = working[idx+3:]
		case "ws", "http":
			return "", "", fmt.Errorf("insecure scheme %q in endpoint %q: agent-bridge requires mTLS (wss://)", scheme+"://", raw)
		default:
			return "", "", fmt.Errorf("unsupported URL scheme %q in endpoint %q", scheme+"://", raw)
		}
	}

	if strings.ContainsAny(working, "?#") {
		return "", "", fmt.Errorf("invalid query or fragment in endpoint %q", raw)
	}

	if slashIdx := strings.IndexByte(working, '/'); slashIdx != -1 {
		pathPart := working[slashIdx:]
		working = working[:slashIdx]
		if pathPart != "/" && pathPart != protocol.ExecWSPath && pathPart != protocol.ExecWSPath+"/" {
			return "", "", fmt.Errorf("unexpected URL path %q in endpoint %q (expected %q or empty)", pathPart, raw, protocol.ExecWSPath)
		}
	}

	hostPort, err = splitAndNormalizeHostPort(working, raw, protocol.DefaultPort)
	if err != nil {
		return "", "", err
	}
	wsURL = "wss://" + hostPort + protocol.ExecWSPath
	return hostPort, wsURL, nil
}

// NormalizeClusterAddr normalizes IPv4, IPv6, or DNS cluster control-plane addresses (with or without
// explicit port or `https://` prefix) into canonical `host:port` (defaulting to port 8444) and
// `https://<hostPort>`, rejecting plaintext `http://` and `ws://` schemes.
func NormalizeClusterAddr(raw string) (hostPort string, baseHTTPSURL string, err error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", "", errors.New("cluster address cannot be empty")
	}

	working := trimmed
	if idx := strings.Index(working, "://"); idx != -1 {
		scheme := strings.ToLower(strings.TrimSpace(working[:idx]))
		switch scheme {
		case "https":
			working = working[idx+3:]
		case "http", "ws":
			return "", "", fmt.Errorf("insecure scheme %q in cluster address %q: cluster control plane requires mTLS (https://)", scheme+"://", raw)
		default:
			return "", "", fmt.Errorf("unsupported URL scheme %q in cluster address %q (expected https:// or host:port)", scheme+"://", raw)
		}
	}

	if strings.ContainsAny(working, "?#") {
		return "", "", fmt.Errorf("invalid query or fragment in cluster address %q", raw)
	}

	if slashIdx := strings.IndexByte(working, '/'); slashIdx != -1 {
		pathPart := working[slashIdx:]
		working = working[:slashIdx]
		if pathPart != "/" {
			return "", "", fmt.Errorf("unexpected URL path %q in cluster address %q (expected base host:port)", pathPart, raw)
		}
	}

	hostPort, err = splitAndNormalizeHostPort(working, raw, DefaultClusterPort)
	if err != nil {
		return "", "", err
	}
	baseHTTPSURL = "https://" + hostPort
	return hostPort, baseHTTPSURL, nil
}

func splitAndNormalizeHostPort(working, raw string, defaultPort int) (string, error) {
	if working == "" {
		return "", fmt.Errorf("missing host in endpoint %q", raw)
	}
	if strings.ContainsAny(working, " \t\r\n@") {
		return "", fmt.Errorf("invalid characters in endpoint host %q", raw)
	}

	defaultPortStr := strconv.Itoa(defaultPort)
	var host, portStr string

	if strings.HasPrefix(working, "[") {
		if strings.HasSuffix(working, "]") {
			inner := working[1 : len(working)-1]
			if inner == "" {
				return "", fmt.Errorf("empty bracketed host in endpoint %q", raw)
			}
			if net.ParseIP(inner) == nil {
				return "", fmt.Errorf("invalid bracketed IPv6 address %q in endpoint %q", inner, raw)
			}
			host = inner
			portStr = defaultPortStr
		} else {
			h, p, splitErr := net.SplitHostPort(working)
			if splitErr != nil {
				return "", fmt.Errorf("invalid bracketed endpoint %q: %w", raw, splitErr)
			}
			if h == "" {
				return "", fmt.Errorf("empty host in endpoint %q", raw)
			}
			if net.ParseIP(h) == nil {
				return "", fmt.Errorf("invalid bracketed IPv6 address %q in endpoint %q", h, raw)
			}
			host = h
			portStr = p
		}
	} else if ip := net.ParseIP(working); ip != nil {
		// Handles both bare IPv4 ("100.64.0.10") and unbracketed IPv6 ("fd7a:115c:a1e0::1", "::1").
		host = working
		portStr = defaultPortStr
	} else {
		colonCount := strings.Count(working, ":")
		switch colonCount {
		case 0:
			host = working
			portStr = defaultPortStr
		case 1:
			h, p, splitErr := net.SplitHostPort(working)
			if splitErr != nil {
				return "", fmt.Errorf("invalid endpoint %q: %w", raw, splitErr)
			}
			if h == "" {
				return "", fmt.Errorf("missing host before port in endpoint %q", raw)
			}
			host = h
			portStr = p
		default:
			return "", fmt.Errorf("invalid endpoint %q: IPv6 addresses with ports must be enclosed in brackets (e.g. [fd7a:115c:a1e0::1]:%d)", raw, defaultPort)
		}
	}

	portNum, convErr := strconv.Atoi(portStr)
	if convErr != nil || portNum < 1 || portNum > 65535 {
		return "", fmt.Errorf("invalid TCP port %q in endpoint %q: must be an integer in [1, 65535]", portStr, raw)
	}

	normalizedPort := strconv.Itoa(portNum)
	return net.JoinHostPort(host, normalizedPort), nil
}

// ParseTimeout parses either a standard Go duration string ("30s", "2m", "1m30s") or bare integer
// seconds ("30" -> 30s). Non-positive values return an error; values exceeding protocol.MaxTimeoutSeconds
// (600s) are clamped to protocol.MaxTimeoutSeconds.
func ParseTimeout(raw string) (time.Duration, int, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return time.Duration(protocol.DefaultTimeoutSeconds) * time.Second, protocol.DefaultTimeoutSeconds, nil
	}

	if isBareInteger(trimmed) {
		sec, err := strconv.Atoi(trimmed)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid timeout %q: %w", raw, err)
		}
		if sec <= 0 {
			return 0, 0, fmt.Errorf("invalid timeout %q: must be strictly positive", raw)
		}
		if sec > protocol.MaxTimeoutSeconds {
			sec = protocol.MaxTimeoutSeconds
		}
		return time.Duration(sec) * time.Second, sec, nil
	}

	dur, err := time.ParseDuration(trimmed)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid timeout %q: expected Go duration (e.g. \"45s\", \"2m\") or positive integer seconds: %w", raw, err)
	}
	if dur <= 0 {
		return 0, 0, fmt.Errorf("invalid timeout %q: must be strictly positive", raw)
	}

	maxDur := time.Duration(protocol.MaxTimeoutSeconds) * time.Second
	if dur > maxDur {
		return maxDur, protocol.MaxTimeoutSeconds, nil
	}

	sec := int((dur + time.Second - 1) / time.Second)
	if sec < 1 {
		sec = 1
	}
	if sec > protocol.MaxTimeoutSeconds {
		sec = protocol.MaxTimeoutSeconds
	}
	return dur, sec, nil
}

func isBareInteger(s string) bool {
	if s == "" {
		return false
	}
	start := 0
	if s[0] == '+' || s[0] == '-' {
		if len(s) == 1 {
			return false
		}
		start = 1
	}
	for i := start; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// ExpandPath expands leading `~`, `~/`, or `~\` prefixes to homeDir and resolves relative paths
// against baseDir when provided.
func ExpandPath(rawPath, homeDir, baseDir string) string {
	resolved, err := expandAndResolvePath(rawPath, homeDir, baseDir)
	if err != nil {
		return strings.TrimSpace(rawPath)
	}
	return resolved
}

func expandAndResolvePath(rawPath, homeDir, baseDir string) (string, error) {
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" {
		return "", errors.New("path cannot be empty")
	}

	expanded := trimmed
	if trimmed == "~" {
		if homeDir == "" {
			return "", errors.New("cannot expand '~': user home directory is unavailable")
		}
		expanded = homeDir
	} else if strings.HasPrefix(trimmed, "~/") || strings.HasPrefix(trimmed, `~\`) {
		if homeDir == "" {
			return "", fmt.Errorf("cannot expand %q: user home directory is unavailable", trimmed)
		}
		rest := trimmed[2:]
		rest = strings.ReplaceAll(rest, `\`, string(filepath.Separator))
		rest = strings.ReplaceAll(rest, "/", string(filepath.Separator))
		expanded = filepath.Join(homeDir, rest)
	}

	if filepath.IsAbs(expanded) || isWindowsAbsPath(expanded) {
		return filepath.Clean(expanded), nil
	}
	if baseDir != "" {
		return filepath.Join(baseDir, expanded), nil
	}
	return filepath.Clean(expanded), nil
}

func isWindowsAbsPath(p string) bool {
	if len(p) >= 3 && ((p[0] >= 'a' && p[0] <= 'z') || (p[0] >= 'A' && p[0] <= 'Z')) && p[1] == ':' && (p[2] == '\\' || p[2] == '/') {
		return true
	}
	return strings.HasPrefix(p, `\\`)
}

// LoadFileConfig reads and unmarshals a JSON FileConfig from disk.
func LoadFileConfig(path string) (*FileConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file %q: %w", path, err)
	}
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	var cfg FileConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse JSON config file %q: %w", path, err)
	}
	return &cfg, nil
}

func loadOptionalFileConfig(path string) (*FileConfig, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to stat config file %q: %w", path, err)
	}
	return LoadFileConfig(path)
}

// LoadDotEnvFile reads and parses a `.env` file from disk.
func LoadDotEnvFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open .env file %q: %w", path, err)
	}
	defer f.Close()

	vals, err := ParseDotEnv(f)
	if err != nil {
		return nil, fmt.Errorf("failed to parse .env file %q: %w", path, err)
	}
	return vals, nil
}

func loadOptionalDotEnv(path string) (map[string]string, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to stat .env file %q: %w", path, err)
	}
	return LoadDotEnvFile(path)
}

// ParseDotEnv parses `.env` key-value pairs without external dependencies, supporting:
//   - Blank lines and full-line `#` comments
//   - Optional `export ` keyword prefix
//   - Single-quoted (`'...'`), double-quoted (`"..."`), and unquoted values
//   - Inline `#` comments outside quotes
func ParseDotEnv(r io.Reader) (map[string]string, error) {
	result := make(map[string]string)
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if lineNum == 1 {
			line = strings.TrimPrefix(line, "\xef\xbb\xbf")
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Strip optional `export` prefix followed by whitespace.
		if strings.HasPrefix(line, "export ") || strings.HasPrefix(line, "export\t") {
			line = strings.TrimSpace(line[len("export"):])
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
		}

		eqIdx := strings.IndexByte(line, '=')
		if eqIdx == -1 {
			return nil, fmt.Errorf("line %d: expected KEY=VALUE assignment", lineNum)
		}

		key := strings.TrimSpace(line[:eqIdx])
		if key == "" {
			return nil, fmt.Errorf("line %d: empty variable name before '='", lineNum)
		}
		if strings.ContainsAny(key, " \t\"'") {
			return nil, fmt.Errorf("line %d: invalid characters in variable name %q", lineNum, key)
		}

		valRaw := strings.TrimSpace(line[eqIdx+1:])
		val, err := parseDotEnvValue(valRaw, lineNum)
		if err != nil {
			return nil, err
		}
		result[key] = val
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading .env stream: %w", err)
	}
	return result, nil
}

func parseDotEnvValue(raw string, lineNum int) (string, error) {
	if raw == "" {
		return "", nil
	}

	switch raw[0] {
	case '\'':
		// Single-quoted literal value: everything up to the next `'` is preserved verbatim.
		closeIdx := strings.IndexByte(raw[1:], '\'')
		if closeIdx == -1 {
			return "", fmt.Errorf("line %d: unterminated single-quoted value", lineNum)
		}
		val := raw[1 : 1+closeIdx]
		trailing := strings.TrimSpace(raw[1+closeIdx+1:])
		if trailing != "" && !strings.HasPrefix(trailing, "#") {
			return "", fmt.Errorf("line %d: unexpected trailing characters %q after closing single quote", lineNum, trailing)
		}
		return val, nil

	case '"':
		// Double-quoted value: supports `\"` and `\\` escapes while preserving Windows path backslashes.
		var sb strings.Builder
		escaped := false
		closedAt := -1
		for i := 1; i < len(raw); i++ {
			ch := raw[i]
			if escaped {
				switch ch {
				case '"', '\\':
					sb.WriteByte(ch)
				default:
					// Preserve unknown escape sequences (e.g. `C:\temp\client.crt`) literally.
					sb.WriteByte('\\')
					sb.WriteByte(ch)
				}
				escaped = false
				continue
			}
			if ch == '\\' {
				escaped = true
				continue
			}
			if ch == '"' {
				closedAt = i
				break
			}
			sb.WriteByte(ch)
		}
		if closedAt == -1 {
			return "", fmt.Errorf("line %d: unterminated double-quoted value", lineNum)
		}
		trailing := strings.TrimSpace(raw[closedAt+1:])
		if trailing != "" && !strings.HasPrefix(trailing, "#") {
			return "", fmt.Errorf("line %d: unexpected trailing characters %q after closing double quote", lineNum, trailing)
		}
		return sb.String(), nil

	default:
		// Unquoted value: `#` outside quotes begins an inline comment.
		if hashIdx := strings.IndexByte(raw, '#'); hashIdx != -1 {
			raw = raw[:hashIdx]
		}
		return strings.TrimSpace(raw), nil
	}
}
