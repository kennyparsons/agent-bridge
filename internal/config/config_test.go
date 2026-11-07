package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/protocol"
)

func TestFullPrecedenceHierarchy(t *testing.T) {
	t.Parallel()

	homeDir := t.TempDir()
	workDir := t.TempDir()
	globalCfgPath := filepath.Join(homeDir, ".config", "agent-bridge", "config.json")

	if err := os.MkdirAll(filepath.Dir(globalCfgPath), 0o755); err != nil {
		t.Fatalf("mkdir global config dir: %v", err)
	}

	// Layer 3: Global config.json
	globalJSON := `{
  "default_host": "global-dc",
  "client_cert": "~/global/client.crt",
  "client_key": "~/global/client.key",
  "ca_cert": "~/global/ca.crt",
  "hosts": {
    "global-dc": {
      "endpoint": "100.64.0.1:8443"
    },
    "global-timed": {
      "endpoint": "100.64.0.2:8443",
      "timeout": "45s"
    }
  }
}`
	if err := os.WriteFile(globalCfgPath, []byte(globalJSON), 0o600); err != nil {
		t.Fatalf("write global config: %v", err)
	}

	emptyEnv := func(string) (string, bool) { return "", false }
	baseOpts := ResolveOptions{
		WorkDir:          workDir,
		GlobalConfigPath: globalCfgPath,
		HomeDir:          homeDir,
		GOOS:             "linux",
		EnvLookup:        emptyEnv,
	}

	// Step A: Global config + hardcoded default timeout (60s because global-dc omits timeout).
	cfg, err := ResolveWithOptions(FlagOverrides{}, baseOpts)
	if err != nil {
		t.Fatalf("Step A ResolveWithOptions failed: %v", err)
	}
	if cfg.Host != "global-dc" {
		t.Errorf("Step A Host = %q, want %q", cfg.Host, "global-dc")
	}
	if cfg.Endpoint != "100.64.0.1:8443" {
		t.Errorf("Step A Endpoint = %q, want %q", cfg.Endpoint, "100.64.0.1:8443")
	}
	if cfg.WSURL != "wss://100.64.0.1:8443/ws/exec" {
		t.Errorf("Step A WSURL = %q, want %q", cfg.WSURL, "wss://100.64.0.1:8443/ws/exec")
	}
	if cfg.Timeout != 60*time.Second || cfg.TimeoutSeconds != 60 {
		t.Errorf("Step A Timeout = %v (%ds), want 60s (60s)", cfg.Timeout, cfg.TimeoutSeconds)
	}
	if cfg.CertPath != filepath.Join(homeDir, "global", "client.crt") {
		t.Errorf("Step A CertPath = %q", cfg.CertPath)
	}

	// Step B: Layer 2b (CWD agent-bridge.json) overrides Global config.json.
	localJSON := `{
  "default_host": "local-app",
  "client_cert": "./local/client.crt",
  "client_key": "./local/client.key",
  "ca_cert": "./local/ca.crt",
  "hosts": {
    "local-app": {
      "endpoint": "100.64.1.10",
      "timeout": "75s"
    }
  }
}`
	localCfgPath := filepath.Join(workDir, LocalConfigFilename)
	if err := os.WriteFile(localCfgPath, []byte(localJSON), 0o600); err != nil {
		t.Fatalf("write local config: %v", err)
	}

	cfg, err = ResolveWithOptions(FlagOverrides{}, baseOpts)
	if err != nil {
		t.Fatalf("Step B ResolveWithOptions failed: %v", err)
	}
	if cfg.Host != "local-app" {
		t.Errorf("Step B Host = %q, want %q", cfg.Host, "local-app")
	}
	if cfg.Endpoint != "100.64.1.10:8443" {
		t.Errorf("Step B Endpoint = %q, want %q", cfg.Endpoint, "100.64.1.10:8443")
	}
	if cfg.Timeout != 75*time.Second || cfg.TimeoutSeconds != 75 {
		t.Errorf("Step B Timeout = %v (%ds), want 75s", cfg.Timeout, cfg.TimeoutSeconds)
	}
	if cfg.CertPath != filepath.Join(workDir, "local", "client.crt") {
		t.Errorf("Step B CertPath = %q, want %q", cfg.CertPath, filepath.Join(workDir, "local", "client.crt"))
	}

	// Step C: Layer 2a-low (CWD .env) overrides CWD agent-bridge.json and Global config.json.
	dotEnvContent := `
AGENT_BRIDGE_ENDPOINT=100.64.2.20:9443
AGENT_BRIDGE_CERT=./dotenv/client.crt
AGENT_BRIDGE_KEY=./dotenv/client.key
AGENT_BRIDGE_CA=./dotenv/ca.crt
AGENT_BRIDGE_TIMEOUT=90s
`
	if err := os.WriteFile(filepath.Join(workDir, DotEnvFilename), []byte(dotEnvContent), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}

	cfg, err = ResolveWithOptions(FlagOverrides{}, baseOpts)
	if err != nil {
		t.Fatalf("Step C ResolveWithOptions failed: %v", err)
	}
	if cfg.Host != "" {
		t.Errorf("Step C Host = %q, want empty (direct .env endpoint override)", cfg.Host)
	}
	if cfg.Endpoint != "100.64.2.20:9443" {
		t.Errorf("Step C Endpoint = %q, want %q", cfg.Endpoint, "100.64.2.20:9443")
	}
	if cfg.Timeout != 90*time.Second || cfg.TimeoutSeconds != 90 {
		t.Errorf("Step C Timeout = %v (%ds), want 90s", cfg.Timeout, cfg.TimeoutSeconds)
	}
	if cfg.CertPath != filepath.Join(workDir, "dotenv", "client.crt") {
		t.Errorf("Step C CertPath = %q", cfg.CertPath)
	}

	// Step D: Layer 2a-high (Process Env) overrides CWD .env, CWD agent-bridge.json, and Global config.json.
	procEnvMap := map[string]string{
		EnvEndpoint: "env-node.tailnet-example.ts.net",
		EnvCert:     "~/procenv/client.crt",
		EnvKey:      "~/procenv/client.key",
		EnvCA:       "~/procenv/ca.crt",
		EnvTimeout:  "120",
	}
	optsWithProcEnv := baseOpts
	optsWithProcEnv.EnvLookup = func(k string) (string, bool) {
		v, ok := procEnvMap[k]
		return v, ok
	}

	cfg, err = ResolveWithOptions(FlagOverrides{}, optsWithProcEnv)
	if err != nil {
		t.Fatalf("Step D ResolveWithOptions failed: %v", err)
	}
	if cfg.Endpoint != "env-node.tailnet-example.ts.net:8443" {
		t.Errorf("Step D Endpoint = %q, want %q", cfg.Endpoint, "env-node.tailnet-example.ts.net:8443")
	}
	if cfg.Timeout != 120*time.Second || cfg.TimeoutSeconds != 120 {
		t.Errorf("Step D Timeout = %v (%ds), want 120s", cfg.Timeout, cfg.TimeoutSeconds)
	}
	if cfg.CertPath != filepath.Join(homeDir, "procenv", "client.crt") {
		t.Errorf("Step D CertPath = %q", cfg.CertPath)
	}

	// Step E: Layer 1 (Explicit CLI Flags) overrides Process Env, .env, local JSON, and global JSON.
	cliFlags := FlagOverrides{
		Endpoint: "[fd7a:115c:a1e0::99]:7443",
		CertPath: "~/flags/client.crt",
		KeyPath:  "~/flags/client.key",
		CAPath:   "~/flags/ca.crt",
		Timeout:  "2m30s",
	}
	cfg, err = ResolveWithOptions(cliFlags, optsWithProcEnv)
	if err != nil {
		t.Fatalf("Step E ResolveWithOptions failed: %v", err)
	}
	if cfg.Endpoint != "[fd7a:115c:a1e0::99]:7443" {
		t.Errorf("Step E Endpoint = %q, want %q", cfg.Endpoint, "[fd7a:115c:a1e0::99]:7443")
	}
	if cfg.WSURL != "wss://[fd7a:115c:a1e0::99]:7443/ws/exec" {
		t.Errorf("Step E WSURL = %q", cfg.WSURL)
	}
	if cfg.Timeout != 150*time.Second || cfg.TimeoutSeconds != 150 {
		t.Errorf("Step E Timeout = %v (%ds), want 150s", cfg.Timeout, cfg.TimeoutSeconds)
	}
	if cfg.CertPath != filepath.Join(homeDir, "flags", "client.crt") {
		t.Errorf("Step E CertPath = %q", cfg.CertPath)
	}
}

func TestMultiHostResolutionAndUnknownHostErrors(t *testing.T) {
	t.Parallel()

	homeDir := t.TempDir()
	workDir := t.TempDir()
	globalCfgPath := filepath.Join(homeDir, "config.json")

	globalJSON := `{
  "default_host": "win-dc-01",
  "client_cert": "~/certs/client.crt",
  "client_key": "~/certs/client.key",
  "ca_cert": "~/certs/ca.crt",
  "hosts": {
    "win-dc-01": {
      "endpoint": "100.64.0.10:8443",
      "timeout": "45s"
    },
    "db-01": {
      "endpoint": "100.64.0.11:8443",
      "timeout": "90s"
    }
  }
}`
	if err := os.WriteFile(globalCfgPath, []byte(globalJSON), 0o600); err != nil {
		t.Fatalf("write global config: %v", err)
	}

	opts := ResolveOptions{
		WorkDir:          workDir,
		GlobalConfigPath: globalCfgPath,
		HomeDir:          homeDir,
		GOOS:             "linux",
		EnvLookup:        func(string) (string, bool) { return "", false },
	}

	// 1. Default host (`win-dc-01`)
	cfg, err := ResolveWithOptions(FlagOverrides{}, opts)
	if err != nil {
		t.Fatalf("default_host resolve failed: %v", err)
	}
	if cfg.Host != "win-dc-01" || cfg.Endpoint != "100.64.0.10:8443" || cfg.TimeoutSeconds != 45 {
		t.Fatalf("unexpected default_host config: %+v", cfg)
	}

	// 2. CLI `--host db-01`
	cfg, err = ResolveWithOptions(FlagOverrides{Host: "db-01"}, opts)
	if err != nil {
		t.Fatalf("--host db-01 resolve failed: %v", err)
	}
	if cfg.Host != "db-01" || cfg.Endpoint != "100.64.0.11:8443" || cfg.TimeoutSeconds != 90 {
		t.Fatalf("unexpected --host db-01 config: %+v", cfg)
	}

	// 3. Process env `AGENT_BRIDGE_HOST=db-01`, plus CLI `--host win-dc-01` overriding env
	optsEnvHost := opts
	optsEnvHost.EnvLookup = func(k string) (string, bool) {
		if k == EnvHost {
			return "db-01", true
		}
		return "", false
	}
	cfg, err = ResolveWithOptions(FlagOverrides{}, optsEnvHost)
	if err != nil {
		t.Fatalf("AGENT_BRIDGE_HOST resolve failed: %v", err)
	}
	if cfg.Host != "db-01" || cfg.Endpoint != "100.64.0.11:8443" {
		t.Fatalf("expected AGENT_BRIDGE_HOST=db-01, got %+v", cfg)
	}

	cfg, err = ResolveWithOptions(FlagOverrides{Host: "win-dc-01"}, optsEnvHost)
	if err != nil {
		t.Fatalf("CLI --host overriding AGENT_BRIDGE_HOST failed: %v", err)
	}
	if cfg.Host != "win-dc-01" || cfg.Endpoint != "100.64.0.10:8443" {
		t.Fatalf("expected CLI --host=win-dc-01 to win, got %+v", cfg)
	}

	// 4. Unknown host via `--host`
	if _, err := ResolveWithOptions(FlagOverrides{Host: "nonexistent"}, opts); err == nil {
		t.Fatal("expected error for unknown --host, got nil")
	} else if !strings.Contains(err.Error(), "nonexistent") {
		t.Fatalf("expected unknown host name in error, got: %v", err)
	}

	// 5. Unknown host via `AGENT_BRIDGE_HOST`
	optsBadEnvHost := opts
	optsBadEnvHost.EnvLookup = func(k string) (string, bool) {
		if k == EnvHost {
			return "ghost-host", true
		}
		return "", false
	}
	if _, err := ResolveWithOptions(FlagOverrides{}, optsBadEnvHost); err == nil {
		t.Fatal("expected error for unknown AGENT_BRIDGE_HOST, got nil")
	}

	// 6. Unknown `default_host` in config.json fails when not overridden, but succeeds when `--endpoint` is passed.
	badDefaultPath := filepath.Join(homeDir, "bad-default.json")
	badDefaultJSON := `{
  "default_host": "deleted-dc",
  "client_cert": "~/certs/client.crt",
  "client_key": "~/certs/client.key",
  "ca_cert": "~/certs/ca.crt",
  "hosts": {
    "win-dc-01": { "endpoint": "100.64.0.10:8443" }
  }
}`
	if err := os.WriteFile(badDefaultPath, []byte(badDefaultJSON), 0o600); err != nil {
		t.Fatalf("write bad-default.json: %v", err)
	}
	optsBadDefault := opts
	optsBadDefault.GlobalConfigPath = badDefaultPath

	if _, err := ResolveWithOptions(FlagOverrides{}, optsBadDefault); err == nil {
		t.Fatal("expected error for unknown default_host, got nil")
	}
	cfg, err = ResolveWithOptions(FlagOverrides{Endpoint: "100.64.0.100:8443"}, optsBadDefault)
	if err != nil {
		t.Fatalf("direct --endpoint should bypass broken default_host, got error: %v", err)
	}
	if cfg.Endpoint != "100.64.0.100:8443" {
		t.Fatalf("unexpected endpoint: %q", cfg.Endpoint)
	}

	// 7. Single-host CWD agent-bridge.json convenience (`endpoint` + `timeout` at top-level) overrides global `default_host`.
	singleHostWorkDir := t.TempDir()
	singleHostLocalJSON := `{"endpoint": "100.64.0.99", "timeout": "25s"}`
	if err := os.WriteFile(filepath.Join(singleHostWorkDir, LocalConfigFilename), []byte(singleHostLocalJSON), 0o600); err != nil {
		t.Fatalf("write single-host agent-bridge.json: %v", err)
	}
	optsSingleLocal := opts
	optsSingleLocal.WorkDir = singleHostLocalDir(singleHostWorkDir)
	cfg, err = ResolveWithOptions(FlagOverrides{}, optsSingleLocal)
	if err != nil {
		t.Fatalf("single-host local config resolve failed: %v", err)
	}
	if cfg.Endpoint != "100.64.0.99:8443" || cfg.TimeoutSeconds != 25 || cfg.Host != "" {
		t.Fatalf("unexpected single-host local config result: %+v", cfg)
	}
}

func singleHostLocalDir(dir string) string { return dir }

func TestParseDotEnvEdgeCases(t *testing.T) {
	t.Parallel()

	raw := "\xef\xbb\xbf" + // UTF-8 BOM
		"# Leading comment\r\n" +
		"\r\n" +
		"   # Indented comment\n" +
		"AGENT_BRIDGE_ENDPOINT = 100.64.0.10:8443   # inline comment\r\n" +
		"export AGENT_BRIDGE_HOST=win-dc-01\n" +
		"export\tAGENT_BRIDGE_TIMEOUT = \"45s\" # comment after double quotes\n" +
		"AGENT_BRIDGE_CERT='./dir#with#hash/client.crt' # comment after single quotes\n" +
		`AGENT_BRIDGE_KEY="C:\Users\admin\temp\client.key"` + "\n" +
		`ESCAPED_QUOTES="val\"with\\escapes"` + "\n" +
		"EMPTY_UNQUOTED=   # comment after empty\n"

	parsed, err := ParseDotEnv(strings.NewReader(raw))
	if err != nil {
		t.Fatalf("ParseDotEnv failed: %v", err)
	}

	expected := map[string]string{
		EnvEndpoint:      "100.64.0.10:8443",
		EnvHost:          "win-dc-01",
		EnvTimeout:       "45s",
		EnvCert:          "./dir#with#hash/client.crt",
		EnvKey:           `C:\Users\admin\temp\client.key`,
		"ESCAPED_QUOTES": `val"with\escapes`,
		"EMPTY_UNQUOTED": "",
	}

	for k, want := range expected {
		if got := parsed[k]; got != want {
			t.Errorf("parsed[%q] = %q, want %q", k, got, want)
		}
	}

	invalidInputs := []string{
		"MISSING_EQUALS_SIGN",
		"=missing_key",
		"BAD KEY=value",
		`UNCLOSED_DOUBLE="hello`,
		`UNCLOSED_SINGLE='hello`,
		`TRAILING_GARBAGE="hello" extra_stuff`,
		`TRAILING_SINGLE='hello' extra_stuff`,
	}
	for _, bad := range invalidInputs {
		if _, err := ParseDotEnv(strings.NewReader(bad)); err == nil {
			t.Errorf("ParseDotEnv(%q) succeeded, expected syntax error", bad)
		}
	}
}

func TestNormalizeEndpoint(t *testing.T) {
	t.Parallel()

	validCases := []struct {
		raw          string
		wantHostPort string
		wantWSURL    string
	}{
		{
			raw:          "100.64.0.10",
			wantHostPort: "100.64.0.10:8443",
			wantWSURL:    "wss://100.64.0.10:8443/ws/exec",
		},
		{
			raw:          "100.64.0.10:9443",
			wantHostPort: "100.64.0.10:9443",
			wantWSURL:    "wss://100.64.0.10:9443/ws/exec",
		},
		{
			raw:          "win-dc-01.tailnet-example.ts.net",
			wantHostPort: "win-dc-01.tailnet-example.ts.net:8443",
			wantWSURL:    "wss://win-dc-01.tailnet-example.ts.net:8443/ws/exec",
		},
		{
			raw:          "win-dc-01.tailnet-example.ts.net:8443",
			wantHostPort: "win-dc-01.tailnet-example.ts.net:8443",
			wantWSURL:    "wss://win-dc-01.tailnet-example.ts.net:8443/ws/exec",
		},
		{
			raw:          "fd7a:115c:a1e0::1",
			wantHostPort: "[fd7a:115c:a1e0::1]:8443",
			wantWSURL:    "wss://[fd7a:115c:a1e0::1]:8443/ws/exec",
		},
		{
			raw:          "[fd7a:115c:a1e0::1]",
			wantHostPort: "[fd7a:115c:a1e0::1]:8443",
			wantWSURL:    "wss://[fd7a:115c:a1e0::1]:8443/ws/exec",
		},
		{
			raw:          "[fd7a:115c:a1e0::1]:9443",
			wantHostPort: "[fd7a:115c:a1e0::1]:9443",
			wantWSURL:    "wss://[fd7a:115c:a1e0::1]:9443/ws/exec",
		},
		{
			raw:          "wss://100.64.0.10:8443/ws/exec",
			wantHostPort: "100.64.0.10:8443",
			wantWSURL:    "wss://100.64.0.10:8443/ws/exec",
		},
		{
			raw:          "WSS://win-dc-01.tailnet-example.ts.net/",
			wantHostPort: "win-dc-01.tailnet-example.ts.net:8443",
			wantWSURL:    "wss://win-dc-01.tailnet-example.ts.net:8443/ws/exec",
		},
		{
			raw:          "https://[fd7a:115c:a1e0::1]:9443",
			wantHostPort: "[fd7a:115c:a1e0::1]:9443",
			wantWSURL:    "wss://[fd7a:115c:a1e0::1]:9443/ws/exec",
		},
	}

	for _, tc := range validCases {
		gotHP, gotWS, err := NormalizeEndpoint(tc.raw)
		if err != nil {
			t.Errorf("NormalizeEndpoint(%q) unexpected error: %v", tc.raw, err)
			continue
		}
		if gotHP != tc.wantHostPort || gotWS != tc.wantWSURL {
			t.Errorf("NormalizeEndpoint(%q) = (%q, %q), want (%q, %q)", tc.raw, gotHP, gotWS, tc.wantHostPort, tc.wantWSURL)
		}
	}

	invalidCases := []string{
		"",
		"   ",
		"ws://100.64.0.10:8443",
		"http://100.64.0.10:8443",
		"ftp://100.64.0.10:8443",
		"100.64.0.10:0",
		"100.64.0.10:70000",
		"100.64.0.10:notaport",
		":8443",
		"[]",
		"[not-an-ip]:8443",
		"wss://100.64.0.10:8443/wrong/path",
		"host with spaces:8443",
	}
	for _, bad := range invalidCases {
		if hp, ws, err := NormalizeEndpoint(bad); err == nil {
			t.Errorf("NormalizeEndpoint(%q) = (%q, %q, nil), expected error", bad, hp, ws)
		}
	}
}

func TestTildeExpansionAndWindowsGlobalFallback(t *testing.T) {
	t.Parallel()

	homeDir := t.TempDir()
	workDir := t.TempDir()
	appDataDir := t.TempDir()

	// Forward-slash `~/` and Windows backslash `~\` expansion.
	gotUnix := ExpandPath("~/.config/agent-bridge/client.crt", homeDir, workDir)
	wantUnix := filepath.Join(homeDir, ".config", "agent-bridge", "client.crt")
	if gotUnix != wantUnix {
		t.Errorf("ExpandPath('~/...') = %q, want %q", gotUnix, wantUnix)
	}

	gotWin := ExpandPath(`~\.config\agent-bridge\client.key`, homeDir, workDir)
	wantWin := filepath.Join(homeDir, ".config", "agent-bridge", "client.key")
	if gotWin != wantWin {
		t.Errorf("ExpandPath('~\\...') = %q, want %q", gotWin, wantWin)
	}

	gotExactHome := ExpandPath("~", homeDir, workDir)
	if gotExactHome != homeDir {
		t.Errorf("ExpandPath('~') = %q, want %q", gotExactHome, homeDir)
	}

	// Windows global config resolution: when %APPDATA%\agent-bridge\config.json does NOT exist,
	// falls back to ~/.config/agent-bridge/config.json.
	xdgConfigPath := filepath.Join(homeDir, ".config", "agent-bridge", "config.json")
	if err := os.MkdirAll(filepath.Dir(xdgConfigPath), 0o755); err != nil {
		t.Fatalf("mkdir xdg config: %v", err)
	}
	if err := os.WriteFile(xdgConfigPath, []byte(`{
  "endpoint": "100.64.0.21:8443",
  "client_cert": "~/c.crt",
  "client_key": "~/c.key",
  "ca_cert": "~/ca.crt"
}`), 0o600); err != nil {
		t.Fatalf("write xdg config: %v", err)
	}

	winEnv := func(k string) (string, bool) {
		if k == "APPDATA" {
			return appDataDir, true
		}
		return "", false
	}

	cfg, err := ResolveWithOptions(FlagOverrides{}, ResolveOptions{
		WorkDir:   workDir,
		HomeDir:   homeDir,
		GOOS:      "windows",
		EnvLookup: winEnv,
	})
	if err != nil {
		t.Fatalf("Windows fallback to ~/.config failed: %v", err)
	}
	if cfg.Endpoint != "100.64.0.21:8443" {
		t.Errorf("fallback Endpoint = %q, want 100.64.0.21:8443", cfg.Endpoint)
	}

	// Once %APPDATA%\agent-bridge\config.json exists, it takes precedence over ~/.config/agent-bridge/config.json.
	appDataConfigPath := filepath.Join(appDataDir, "agent-bridge", "config.json")
	if err := os.MkdirAll(filepath.Dir(appDataConfigPath), 0o755); err != nil {
		t.Fatalf("mkdir appdata config: %v", err)
	}
	if err := os.WriteFile(appDataConfigPath, []byte(`{
  "endpoint": "100.64.0.22:8443",
  "client_cert": "~/c.crt",
  "client_key": "~/c.key",
  "ca_cert": "~/ca.crt"
}`), 0o600); err != nil {
		t.Fatalf("write appdata config: %v", err)
	}

	cfg, err = ResolveWithOptions(FlagOverrides{}, ResolveOptions{
		WorkDir:   workDir,
		HomeDir:   homeDir,
		GOOS:      "windows",
		EnvLookup: winEnv,
	})
	if err != nil {
		t.Fatalf("Windows APPDATA primary config failed: %v", err)
	}
	if cfg.Endpoint != "100.64.0.22:8443" {
		t.Errorf("APPDATA primary Endpoint = %q, want 100.64.0.22:8443", cfg.Endpoint)
	}
}

func TestParseTimeoutAndMissingRequiredFields(t *testing.T) {
	t.Parallel()

	validDurations := []struct {
		raw     string
		wantDur time.Duration
		wantSec int
	}{
		{"", 60 * time.Second, 60},
		{"45s", 45 * time.Second, 45},
		{"2m", 120 * time.Second, 120},
		{"1m30s", 90 * time.Second, 90},
		{"45", 45 * time.Second, 45},
		{"+30", 30 * time.Second, 30},
		{"900s", time.Duration(protocol.MaxTimeoutSeconds) * time.Second, protocol.MaxTimeoutSeconds},
		{"900", time.Duration(protocol.MaxTimeoutSeconds) * time.Second, protocol.MaxTimeoutSeconds},
	}

	for _, tc := range validDurations {
		dur, sec, err := ParseTimeout(tc.raw)
		if err != nil {
			t.Errorf("ParseTimeout(%q) unexpected error: %v", tc.raw, err)
			continue
		}
		if dur != tc.wantDur || sec != tc.wantSec {
			t.Errorf("ParseTimeout(%q) = (%v, %d), want (%v, %d)", tc.raw, dur, sec, tc.wantDur, tc.wantSec)
		}
	}

	invalidDurations := []string{
		"0",
		"0s",
		"-5",
		"-10s",
		"abc",
		"30seconds",
		"+",
		"-",
	}
	for _, bad := range invalidDurations {
		if _, _, err := ParseTimeout(bad); err == nil {
			t.Errorf("ParseTimeout(%q) succeeded, expected error", bad)
		}
	}

	// Verify missing required fields (`endpoint`, `cert`, `key`, `ca`).
	emptyOpts := ResolveOptions{
		WorkDir:          t.TempDir(),
		GlobalConfigPath: filepath.Join(t.TempDir(), "missing-global.json"),
		HomeDir:          t.TempDir(),
		EnvLookup:        func(string) (string, bool) { return "", false },
	}

	missingCases := []struct {
		name  string
		flags FlagOverrides
	}{
		{
			name: "missing endpoint",
			flags: FlagOverrides{
				CertPath: "/tmp/c.crt",
				KeyPath:  "/tmp/c.key",
				CAPath:   "/tmp/ca.crt",
			},
		},
		{
			name: "missing cert",
			flags: FlagOverrides{
				Endpoint: "100.64.0.10:8443",
				KeyPath:  "/tmp/c.key",
				CAPath:   "/tmp/ca.crt",
			},
		},
		{
			name: "missing key",
			flags: FlagOverrides{
				Endpoint: "100.64.0.10:8443",
				CertPath: "/tmp/c.crt",
				CAPath:   "/tmp/ca.crt",
			},
		},
		{
			name: "missing ca",
			flags: FlagOverrides{
				Endpoint: "100.64.0.10:8443",
				CertPath: "/tmp/c.crt",
				KeyPath:  "/tmp/c.key",
			},
		},
	}

	for _, tc := range missingCases {
		if _, err := ResolveWithOptions(tc.flags, emptyOpts); err == nil {
			t.Errorf("%s: expected validation error, got nil", tc.name)
		}
	}
}

func TestNamedHostProfileIsolationNoCrossPollution(t *testing.T) {
	t.Parallel()

	homeDir := t.TempDir()
	globalCfgPath := filepath.Join(homeDir, ".config", "agent-bridge", "config.json")
	if err := os.MkdirAll(filepath.Dir(globalCfgPath), 0o755); err != nil {
		t.Fatalf("mkdir global config dir: %v", err)
	}

	globalJSON := `{
  "default_host": "win-dc-01",
  "client_cert": "~/certs/client.crt",
  "client_key": "~/certs/client.key",
  "ca_cert": "~/certs/ca.crt",
  "hosts": {
    "win-dc-01": {
      "endpoint": "10.0.0.1:8443",
      "timeout": "1s"
    },
    "db-no-endpoint": {
      "timeout": "60s"
    },
    "db-no-timeout": {
      "endpoint": "10.0.0.2:8443"
    }
  }
}`
	if err := os.WriteFile(globalCfgPath, []byte(globalJSON), 0o600); err != nil {
		t.Fatalf("write global config: %v", err)
	}

	emptyEnv := func(string) (string, bool) { return "", false }

	// 1. CLI `--host db-no-endpoint`: MUST fail with missing-endpoint error, NEVER bleed 10.0.0.1:8443 from default_host.
	optsCLI := ResolveOptions{
		WorkDir:          t.TempDir(),
		GlobalConfigPath: globalCfgPath,
		HomeDir:          homeDir,
		GOOS:             "linux",
		EnvLookup:        emptyEnv,
	}
	if got, err := ResolveWithOptions(FlagOverrides{Host: "db-no-endpoint"}, optsCLI); err == nil {
		t.Fatalf("expected missing-endpoint error for --host db-no-endpoint, got %+v", got)
	} else if !strings.Contains(strings.ToLower(err.Error()), "endpoint") {
		t.Fatalf("expected missing endpoint message, got: %v", err)
	}

	// 2. CLI `--host db-no-timeout`: MUST resolve to 10.0.0.2:8443 with default 60s timeout, NEVER bleed 1s from default_host.
	cfgCLI, err := ResolveWithOptions(FlagOverrides{Host: "db-no-timeout"}, optsCLI)
	if err != nil {
		t.Fatalf("ResolveWithOptions(--host db-no-timeout) failed: %v", err)
	}
	if cfgCLI.Host != "db-no-timeout" || cfgCLI.Endpoint != "10.0.0.2:8443" {
		t.Fatalf("unexpected CLI host/endpoint: %+v", cfgCLI)
	}
	if cfgCLI.Timeout != 60*time.Second || cfgCLI.TimeoutSeconds != 60 {
		t.Fatalf("CLI --host db-no-timeout bled timeout: got %v (%ds), want 60s", cfgCLI.Timeout, cfgCLI.TimeoutSeconds)
	}

	// 3. Process env `AGENT_BRIDGE_HOST`: verify both missing-endpoint rejection and timeout isolation.
	optsProcMissing := optsCLI
	optsProcMissing.EnvLookup = func(k string) (string, bool) {
		if k == EnvHost {
			return "db-no-endpoint", true
		}
		return "", false
	}
	if got, err := ResolveWithOptions(FlagOverrides{}, optsProcMissing); err == nil {
		t.Fatalf("expected missing-endpoint error via process env AGENT_BRIDGE_HOST, got %+v", got)
	}

	optsProcValid := optsCLI
	optsProcValid.EnvLookup = func(k string) (string, bool) {
		if k == EnvHost {
			return "db-no-timeout", true
		}
		return "", false
	}
	cfgProc, err := ResolveWithOptions(FlagOverrides{}, optsProcValid)
	if err != nil {
		t.Fatalf("process env AGENT_BRIDGE_HOST=db-no-timeout failed: %v", err)
	}
	if cfgProc.Endpoint != "10.0.0.2:8443" || cfgProc.TimeoutSeconds != 60 {
		t.Fatalf("process env cross-host bleed detected: %+v", cfgProc)
	}

	// 4. CWD `.env` `AGENT_BRIDGE_HOST`: verify both missing-endpoint rejection and timeout isolation.
	dotMissingDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dotMissingDir, DotEnvFilename), []byte("AGENT_BRIDGE_HOST=db-no-endpoint\n"), 0o600); err != nil {
		t.Fatalf("write .env (missing endpoint): %v", err)
	}
	optsDotMissing := optsCLI
	optsDotMissing.WorkDir = dotMissingDir
	if got, err := ResolveWithOptions(FlagOverrides{}, optsDotMissing); err == nil {
		t.Fatalf("expected missing-endpoint error via .env AGENT_BRIDGE_HOST, got %+v", got)
	}

	dotValidDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dotValidDir, DotEnvFilename), []byte("AGENT_BRIDGE_HOST=db-no-timeout\n"), 0o600); err != nil {
		t.Fatalf("write .env (no timeout): %v", err)
	}
	optsDotValid := optsCLI
	optsDotValid.WorkDir = dotValidDir
	cfgDot, err := ResolveWithOptions(FlagOverrides{}, optsDotValid)
	if err != nil {
		t.Fatalf(".env AGENT_BRIDGE_HOST=db-no-timeout failed: %v", err)
	}
	if cfgDot.Endpoint != "10.0.0.2:8443" || cfgDot.TimeoutSeconds != 60 {
		t.Fatalf(".env cross-host bleed detected: %+v", cfgDot)
	}

	// 5. CWD `agent-bridge.json` `default_host`: verify isolation from global `default_host`.
	localHostDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(localHostDir, LocalConfigFilename), []byte(`{"default_host":"db-no-timeout"}`), 0o600); err != nil {
		t.Fatalf("write local agent-bridge.json: %v", err)
	}
	optsLocalHost := optsCLI
	optsLocalHost.WorkDir = localHostDir
	cfgLocalHost, err := ResolveWithOptions(FlagOverrides{}, optsLocalHost)
	if err != nil {
		t.Fatalf("local default_host=db-no-timeout failed: %v", err)
	}
	if cfgLocalHost.Endpoint != "10.0.0.2:8443" || cfgLocalHost.TimeoutSeconds != 60 {
		t.Fatalf("local default_host cross-host bleed detected: %+v", cfgLocalHost)
	}
}

func TestGlobalConfigRelativeAssetPathsResolveAgainstGlobalDir(t *testing.T) {
	t.Parallel()

	homeDir := t.TempDir()
	unrelatedWorkDir := filepath.Join(t.TempDir(), "somewhere-else")
	if err := os.MkdirAll(unrelatedWorkDir, 0o755); err != nil {
		t.Fatalf("mkdir unrelatedWorkDir: %v", err)
	}

	globalDir := filepath.Join(homeDir, ".config", "agent-bridge")
	if err := os.MkdirAll(globalDir, 0o755); err != nil {
		t.Fatalf("mkdir globalDir: %v", err)
	}
	globalCfgPath := filepath.Join(globalDir, "config.json")

	globalJSON := `{
  "endpoint": "100.64.0.10:8443",
  "client_cert": "./certs/client.crt",
  "client_key": "certs/client.key",
  "ca_cert": "./certs/ca.crt"
}`
	if err := os.WriteFile(globalCfgPath, []byte(globalJSON), 0o600); err != nil {
		t.Fatalf("write global config: %v", err)
	}

	opts := ResolveOptions{
		WorkDir:          unrelatedWorkDir,
		GlobalConfigPath: globalCfgPath,
		HomeDir:          homeDir,
		GOOS:             "linux",
		EnvLookup:        func(string) (string, bool) { return "", false },
	}

	cfg, err := ResolveWithOptions(FlagOverrides{}, opts)
	if err != nil {
		t.Fatalf("ResolveWithOptions failed: %v", err)
	}

	wantCert := filepath.Join(globalDir, "certs", "client.crt")
	wantKey := filepath.Join(globalDir, "certs", "client.key")
	wantCA := filepath.Join(globalDir, "certs", "ca.crt")
	if cfg.CertPath != wantCert {
		t.Errorf("CertPath = %q, want %q", cfg.CertPath, wantCert)
	}
	if cfg.KeyPath != wantKey {
		t.Errorf("KeyPath = %q, want %q", cfg.KeyPath, wantKey)
	}
	if cfg.CAPath != wantCA {
		t.Errorf("CAPath = %q, want %q", cfg.CAPath, wantCA)
	}

	// Overriding ClientCert via CLI flag with a relative path resolves against WorkDir while Key/CA stay rooted at globalDir.
	cfgOverride, err := ResolveWithOptions(FlagOverrides{CertPath: "./override/client.crt"}, opts)
	if err != nil {
		t.Fatalf("ResolveWithOptions(CLI cert override) failed: %v", err)
	}
	wantWorkCert := filepath.Join(unrelatedWorkDir, "override", "client.crt")
	if cfgOverride.CertPath != wantWorkCert {
		t.Errorf("override CertPath = %q, want %q", cfgOverride.CertPath, wantWorkCert)
	}
	if cfgOverride.KeyPath != wantKey {
		t.Errorf("KeyPath = %q, want %q", cfgOverride.KeyPath, wantKey)
	}
}

func TestNormalizeClusterAddr(t *testing.T) {
	t.Parallel()

	validCases := []struct {
		raw          string
		wantHostPort string
		wantHTTPSURL string
	}{
		{
			raw:          "127.0.0.1",
			wantHostPort: "127.0.0.1:8444",
			wantHTTPSURL: "https://127.0.0.1:8444",
		},
		{
			raw:          "100.64.0.10:9444",
			wantHostPort: "100.64.0.10:9444",
			wantHTTPSURL: "https://100.64.0.10:9444",
		},
		{
			raw:          "::1",
			wantHostPort: "[::1]:8444",
			wantHTTPSURL: "https://[::1]:8444",
		},
		{
			raw:          "[::1]",
			wantHostPort: "[::1]:8444",
			wantHTTPSURL: "https://[::1]:8444",
		},
		{
			raw:          "[fd7a:115c:a1e0::1]:8444",
			wantHostPort: "[fd7a:115c:a1e0::1]:8444",
			wantHTTPSURL: "https://[fd7a:115c:a1e0::1]:8444",
		},
		{
			raw:          "win-dc-01.tailnet-example.ts.net",
			wantHostPort: "win-dc-01.tailnet-example.ts.net:8444",
			wantHTTPSURL: "https://win-dc-01.tailnet-example.ts.net:8444",
		},
		{
			raw:          "https://100.64.0.10:8444",
			wantHostPort: "100.64.0.10:8444",
			wantHTTPSURL: "https://100.64.0.10:8444",
		},
		{
			raw:          "HTTPS://win-dc-01.tailnet-example.ts.net/",
			wantHostPort: "win-dc-01.tailnet-example.ts.net:8444",
			wantHTTPSURL: "https://win-dc-01.tailnet-example.ts.net:8444",
		},
	}

	for _, tc := range validCases {
		gotHP, gotURL, err := NormalizeClusterAddr(tc.raw)
		if err != nil {
			t.Errorf("NormalizeClusterAddr(%q) unexpected error: %v", tc.raw, err)
			continue
		}
		if gotHP != tc.wantHostPort || gotURL != tc.wantHTTPSURL {
			t.Errorf("NormalizeClusterAddr(%q) = (%q, %q), want (%q, %q)", tc.raw, gotHP, gotURL, tc.wantHostPort, tc.wantHTTPSURL)
		}
	}

	invalidCases := []string{
		"",
		"   ",
		"http://127.0.0.1:8444",
		"ws://127.0.0.1:8444",
		"wss://127.0.0.1:8444",
		"https://127.0.0.1:8444/cluster/status",
		"127.0.0.1:0",
		"127.0.0.1:70000",
		"[not-an-ip]:8444",
		"host with spaces:8444",
	}
	for _, bad := range invalidCases {
		if hp, u, err := NormalizeClusterAddr(bad); err == nil {
			t.Errorf("NormalizeClusterAddr(%q) = (%q, %q, nil), expected error", bad, hp, u)
		}
	}
}

func TestResolveClusterConfigPrecedenceAndIsolation(t *testing.T) {
	t.Parallel()

	homeDir := t.TempDir()
	emptyEnv := func(string) (string, bool) { return "", false }

	// 1. Default 127.0.0.1:8444 fallback when no config files or cluster address flags exist.
	noCfgOpts := ResolveOptions{
		WorkDir:          t.TempDir(),
		GlobalConfigPath: filepath.Join(t.TempDir(), "nonexistent.json"),
		HomeDir:          homeDir,
		GOOS:             "linux",
		EnvLookup:        emptyEnv,
	}
	zeroTargetCfg, err := ResolveClusterConfigWithOptions(ClusterFlagOverrides{
		CertPath: "~/certs/c.crt",
		KeyPath:  "~/certs/c.key",
		CAPath:   "~/certs/ca.crt",
	}, noCfgOpts)
	if err != nil {
		t.Fatalf("default 127.0.0.1:8444 ResolveClusterConfigWithOptions failed: %v", err)
	}
	if zeroTargetCfg.ClusterAddr != "127.0.0.1:8444" || zeroTargetCfg.BaseHTTPSURL != "https://127.0.0.1:8444" {
		t.Fatalf("unexpected default cluster addr: %+v", zeroTargetCfg)
	}
	if zeroTargetCfg.Host != "" || zeroTargetCfg.TimeoutSeconds != 60 {
		t.Fatalf("unexpected Host/Timeout on zero-target cluster config: %+v", zeroTargetCfg)
	}

	// 2. Legacy pre-Phase-3 config.json (default_host has only `endpoint`, no `cluster_endpoint`):
	//    falls back cleanly to 127.0.0.1:8444 when no --host is requested while reusing certs!
	legacyGlobalPath := filepath.Join(homeDir, ".config", "agent-bridge", "legacy.json")
	if err := os.MkdirAll(filepath.Dir(legacyGlobalPath), 0o755); err != nil {
		t.Fatalf("mkdir legacy global dir: %v", err)
	}
	legacyJSON := `{
  "default_host": "legacy-dc",
  "client_cert": "./certs/client.crt",
  "client_key": "./certs/client.key",
  "ca_cert": "./certs/ca.crt",
  "hosts": {
    "legacy-dc": {
      "endpoint": "100.64.0.10:8443",
      "timeout": "15s"
    }
  }
}`
	if err := os.WriteFile(legacyGlobalPath, []byte(legacyJSON), 0o600); err != nil {
		t.Fatalf("write legacy.json: %v", err)
	}
	legacyOpts := ResolveOptions{
		WorkDir:          t.TempDir(),
		GlobalConfigPath: legacyGlobalPath,
		HomeDir:          homeDir,
		GOOS:             "linux",
		EnvLookup:        emptyEnv,
	}
	legacyResolved, err := ResolveClusterConfigWithOptions(ClusterFlagOverrides{}, legacyOpts)
	if err != nil {
		t.Fatalf("legacy config fallback failed: %v", err)
	}
	if legacyResolved.ClusterAddr != "127.0.0.1:8444" || legacyResolved.Host != "" {
		t.Fatalf("expected legacy config without cluster_endpoint to fall back to 127.0.0.1:8444, got %+v", legacyResolved)
	}
	if legacyResolved.CertPath != filepath.Join(filepath.Dir(legacyGlobalPath), "certs", "client.crt") {
		t.Fatalf("unexpected CertPath from legacy global config: %q", legacyResolved.CertPath)
	}

	// 3. Multi-host `cluster_endpoint` isolation & full 5-tier precedence.
	globalDir := filepath.Join(homeDir, "cluster-global")
	if err := os.MkdirAll(globalDir, 0o755); err != nil {
		t.Fatalf("mkdir cluster-global: %v", err)
	}
	globalCfgPath := filepath.Join(globalDir, "config.json")
	globalJSON := `{
  "default_host": "win-dc-01",
  "client_cert": "~/global/client.crt",
  "client_key": "~/global/client.key",
  "ca_cert": "~/global/ca.crt",
  "hosts": {
    "win-dc-01": {
      "endpoint": "10.0.0.1:8443",
      "cluster_endpoint": "10.0.0.1",
      "timeout": "1s"
    },
    "win-dc-02": {
      "endpoint": "10.0.0.2:8443",
      "cluster_endpoint": "10.0.0.2:8444"
    },
    "win-dc-03-exec-only": {
      "endpoint": "10.0.0.3:8443",
      "timeout": "30s"
    }
  }
}`
	if err := os.WriteFile(globalCfgPath, []byte(globalJSON), 0o600); err != nil {
		t.Fatalf("write global cluster config: %v", err)
	}

	workDir := t.TempDir()
	opts := ResolveOptions{
		WorkDir:          workDir,
		GlobalConfigPath: globalCfgPath,
		HomeDir:          homeDir,
		GOOS:             "linux",
		EnvLookup:        emptyEnv,
	}

	// Tier 1 default_host (`win-dc-01`): appends default port :8444 and uses 1s host timeout.
	c1, err := ResolveClusterConfigWithOptions(ClusterFlagOverrides{}, opts)
	if err != nil {
		t.Fatalf("Tier 1 default_host failed: %v", err)
	}
	if c1.Host != "win-dc-01" || c1.ClusterAddr != "10.0.0.1:8444" || c1.BaseHTTPSURL != "https://10.0.0.1:8444" || c1.TimeoutSeconds != 1 {
		t.Fatalf("unexpected Tier 1 cluster config: %+v", c1)
	}

	// Isolation A: `--host win-dc-02` resolves to 10.0.0.2:8444 with 60s timeout (no 1s timeout bleed from win-dc-01!).
	c2, err := ResolveClusterConfigWithOptions(ClusterFlagOverrides{Host: "win-dc-02"}, opts)
	if err != nil {
		t.Fatalf("--host win-dc-02 failed: %v", err)
	}
	if c2.Host != "win-dc-02" || c2.ClusterAddr != "10.0.0.2:8444" || c2.TimeoutSeconds != 60 {
		t.Fatalf("cross-host bleed on --host win-dc-02: %+v", c2)
	}

	// Isolation B: explicit `--host win-dc-03-exec-only` (missing cluster_endpoint) MUST fail, never hit 10.0.0.1:8444 or 127.0.0.1:8444.
	if got, err := ResolveClusterConfigWithOptions(ClusterFlagOverrides{Host: "win-dc-03-exec-only"}, opts); err == nil {
		t.Fatalf("expected error for explicit --host without cluster_endpoint, got %+v", got)
	}

	// Tier 2: CWD agent-bridge.json top-level `cluster_endpoint` overrides global `default_host`.
	localJSON := `{"cluster_endpoint": "10.0.1.10:9444", "timeout": "20s"}`
	if err := os.WriteFile(filepath.Join(workDir, LocalConfigFilename), []byte(localJSON), 0o600); err != nil {
		t.Fatalf("write local agent-bridge.json: %v", err)
	}
	cLocal, err := ResolveClusterConfigWithOptions(ClusterFlagOverrides{}, opts)
	if err != nil {
		t.Fatalf("Tier 2 local cluster_endpoint failed: %v", err)
	}
	if cLocal.Host != "" || cLocal.ClusterAddr != "10.0.1.10:9444" || cLocal.TimeoutSeconds != 20 {
		t.Fatalf("unexpected Tier 2 cluster config: %+v", cLocal)
	}

	// Tier 3: CWD .env `AGENT_BRIDGE_CLUSTER_ADDR` overrides local JSON.
	if err := os.WriteFile(filepath.Join(workDir, DotEnvFilename), []byte("AGENT_BRIDGE_CLUSTER_ADDR=10.0.2.20\nAGENT_BRIDGE_TIMEOUT=35s\n"), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}
	cDot, err := ResolveClusterConfigWithOptions(ClusterFlagOverrides{}, opts)
	if err != nil {
		t.Fatalf("Tier 3 .env AGENT_BRIDGE_CLUSTER_ADDR failed: %v", err)
	}
	if cDot.ClusterAddr != "10.0.2.20:8444" || cDot.TimeoutSeconds != 35 {
		t.Fatalf("unexpected Tier 3 cluster config: %+v", cDot)
	}

	// Tier 4: Process env `AGENT_BRIDGE_CLUSTER_ADDR` overrides .env.
	optsProc := opts
	optsProc.EnvLookup = func(k string) (string, bool) {
		switch k {
		case EnvClusterAddr:
			return "https://leader-node.tailnet-example.ts.net", true
		case EnvTimeout:
			return "50s", true
		default:
			return "", false
		}
	}
	cProc, err := ResolveClusterConfigWithOptions(ClusterFlagOverrides{}, optsProc)
	if err != nil {
		t.Fatalf("Tier 4 process env AGENT_BRIDGE_CLUSTER_ADDR failed: %v", err)
	}
	if cProc.ClusterAddr != "leader-node.tailnet-example.ts.net:8444" || cProc.BaseHTTPSURL != "https://leader-node.tailnet-example.ts.net:8444" || cProc.TimeoutSeconds != 50 {
		t.Fatalf("unexpected Tier 4 cluster config: %+v", cProc)
	}

	// Tier 5: CLI `--cluster-addr` overrides all lower tiers.
	cFlag, err := ResolveClusterConfigWithOptions(ClusterFlagOverrides{
		ClusterAddr: "[fd7a:115c:a1e0::77]:7444",
		Timeout:     "90s",
	}, optsProc)
	if err != nil {
		t.Fatalf("Tier 5 --cluster-addr failed: %v", err)
	}
	if cFlag.ClusterAddr != "[fd7a:115c:a1e0::77]:7444" || cFlag.BaseHTTPSURL != "https://[fd7a:115c:a1e0::77]:7444" || cFlag.TimeoutSeconds != 90 {
		t.Fatalf("unexpected Tier 5 cluster config: %+v", cFlag)
	}
}
