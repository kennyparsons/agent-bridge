package service

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/acl"
)

func TestDefaultPathsForOS(t *testing.T) {
	win := DefaultPathsForOS("windows")
	if win.DataDir != `C:\ProgramData\agent-bridge\node` {
		t.Fatalf("windows DataDir = %q", win.DataDir)
	}
	if win.ConfigPath != `C:\ProgramData\agent-bridge\server.json` {
		t.Fatalf("windows ConfigPath = %q", win.ConfigPath)
	}
	if win.LogPath != `C:\ProgramData\agent-bridge\logs\daemon.log` {
		t.Fatalf("windows LogPath = %q", win.LogPath)
	}

	lin := DefaultPathsForOS("linux")
	if lin.DataDir != "/var/lib/agent-bridge/node" {
		t.Fatalf("linux DataDir = %q", lin.DataDir)
	}
	if lin.ConfigPath != "/etc/agent-bridge/server.json" {
		t.Fatalf("linux ConfigPath = %q", lin.ConfigPath)
	}
	if lin.LogPath != "/var/log/agent-bridge/daemon.log" {
		t.Fatalf("linux LogPath = %q", lin.LogPath)
	}

	mac := DefaultPathsForOS("darwin")
	if mac.DataDir != "/Library/Application Support/agent-bridge/node" {
		t.Fatalf("darwin DataDir = %q", mac.DataDir)
	}
	if mac.ConfigPath != "/Library/Application Support/agent-bridge/server.json" {
		t.Fatalf("darwin ConfigPath = %q", mac.ConfigPath)
	}
	if mac.LogPath != "/Library/Logs/agent-bridge/daemon.log" {
		t.Fatalf("darwin LogPath = %q", mac.LogPath)
	}
}

func TestSaveAndLoadServerDaemonConfig(t *testing.T) {
	tmp := t.TempDir()
	cfgDir := filepath.Join(tmp, "etc", "agent-bridge")
	cfgPath := filepath.Join(cfgDir, "server.json")

	want := &ServerDaemonConfig{
		BindSpecs:        []string{"100.64.0.10:8765", "127.0.0.1:8765"},
		Port:             8765,
		ClusterBindSpecs: []string{"100.64.0.10:8766", "127.0.0.1:8766"},
		ClusterAdvertise: "100.64.0.10:8766",
		JoinAddr:         "100.64.0.1:8766",
		NodeID:           "win-dc-01",
		DataDir:          filepath.Join(tmp, "node"),
		CertPath:         filepath.Join(tmp, "node", "server.crt"),
		KeyPath:          filepath.Join(tmp, "node", "server.key"),
		CAPath:           filepath.Join(tmp, "node", "ca.crt"),
		CAKeyPath:        filepath.Join(tmp, "node", "ca.key"),
		CRLPath:          filepath.Join(tmp, "node", "ca.crl"),
		StatePath:        filepath.Join(tmp, "node", "cluster-state.json"),
		LogPath:          filepath.Join(tmp, "logs", "daemon.log"),
		Shell:            "pwsh",
		WaitBind:         "60s",
		SANIPs:           []string{"100.64.0.10", "198.51.100.10"},
		SANDNS:           []string{"win-dc-01", "win-dc-01.example.internal"},
	}

	if err := SaveServerDaemonConfig(cfgPath, want); err != nil {
		t.Fatalf("SaveServerDaemonConfig failed: %v", err)
	}

	rawBytes, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", cfgPath, err)
	}
	if strings.Contains(string(rawBytes), "join_token") {
		t.Fatalf("server.json must never persist join_token, got:\n%s", string(rawBytes))
	}

	dirACL, err := acl.AuditPathACL(cfgDir, false)
	if err != nil {
		t.Fatalf("AuditPathACL(cfgDir): %v", err)
	}
	if !dirACL.Secure {
		t.Fatalf("expected locked-down config directory, got %+v", dirACL)
	}

	fileACL, err := acl.AuditPathACL(cfgPath, false)
	if err != nil {
		t.Fatalf("AuditPathACL(cfgPath): %v", err)
	}
	if !fileACL.Secure {
		t.Fatalf("expected locked-down server.json, got %+v", fileACL)
	}

	got, err := LoadServerDaemonConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadServerDaemonConfig failed: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ServerDaemonConfig mismatch:\ngot:  %+v\nwant: %+v", got, want)
	}

	// Verify UTF-8 BOM tolerance (PowerShell Out-File / Set-Content compatibility).
	bomPath := filepath.Join(cfgDir, "bom-server.json")
	withBOM := append([]byte("\xef\xbb\xbf"), rawBytes...)
	if err := os.WriteFile(bomPath, withBOM, 0o600); err != nil {
		t.Fatalf("WriteFile(bomPath): %v", err)
	}
	gotBOM, err := LoadServerDaemonConfig(bomPath)
	if err != nil {
		t.Fatalf("LoadServerDaemonConfig(bomPath) failed: %v", err)
	}
	if !reflect.DeepEqual(gotBOM, want) {
		t.Fatalf("BOM ServerDaemonConfig mismatch")
	}
}

func TestValidateServiceName(t *testing.T) {
	gotDefault, err := ValidateServiceName("   ")
	if err != nil || gotDefault != DefaultServiceName {
		t.Fatalf("expected default %q, got %q (err=%v)", DefaultServiceName, gotDefault, err)
	}
	for _, valid := range []string{"agent-bridge", "agent_bridge-2.0", "AgentBridge"} {
		if got, err := ValidateServiceName(valid); err != nil || got != valid {
			t.Fatalf("ValidateServiceName(%q) = %q, %v", valid, got, err)
		}
	}
	for _, invalid := range []string{".hidden", "../escape", "bad/name", `bad\name`, "bad name", "a;b", strings.Repeat("a", 129)} {
		if _, err := ValidateServiceName(invalid); err == nil {
			t.Fatalf("expected ValidateServiceName(%q) to fail", invalid)
		}
	}
}

func TestRenderSystemdUnitAndParse(t *testing.T) {
	unit, err := RenderSystemdUnit(
		"agent-bridge",
		"",
		"/opt/agent bridge/bin/agent-bridge",
		"/etc/agent-bridge/server.json",
	)
	if err != nil {
		t.Fatalf("RenderSystemdUnit failed: %v", err)
	}
	for _, snippet := range []string{
		"After=network-online.target tailscaled.service",
		"Wants=network-online.target",
		`ExecStart="/opt/agent bridge/bin/agent-bridge" server --service-config "/etc/agent-bridge/server.json"`,
		"Restart=always",
		"RestartSec=3",
		"LimitNOFILE=65536",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(unit, snippet) {
			t.Fatalf("systemd unit missing %q:\n%s", snippet, unit)
		}
	}

	if _, err := RenderSystemdUnit("agent-bridge", "bad\ndesc", "/usr/bin/agent-bridge", "/etc/agent-bridge/server.json"); err == nil {
		t.Fatalf("expected newline injection in description to be rejected")
	}

	props := ParseSystemctlShow("LoadState=loaded\r\nActiveState=active\nSubState=running\nMainPID=4242\n")
	if props["LoadState"] != "loaded" || props["ActiveState"] != "active" || props["SubState"] != "running" || props["MainPID"] != "4242" {
		t.Fatalf("unexpected ParseSystemctlShow result: %+v", props)
	}
}

func TestRenderLaunchdPlistAndParse(t *testing.T) {
	exe := "/Library/Application Support/Agent&Bridge/agent-bridge"
	cfg := "/Library/Application Support/agent-bridge/server.json"
	plist, err := RenderLaunchdPlist("agent-bridge", exe, cfg)
	if err != nil {
		t.Fatalf("RenderLaunchdPlist failed: %v", err)
	}
	for _, snippet := range []string{
		"<string>io.agent-bridge.agent-bridge</string>",
		"Agent&amp;Bridge",
		"<key>RunAtLoad</key>",
		"<key>KeepAlive</key>",
		"<key>ThrottleInterval</key>",
		"<integer>3</integer>",
	} {
		if !strings.Contains(plist, snippet) {
			t.Fatalf("plist missing %q:\n%s", snippet, plist)
		}
	}

	gotExe, gotCfg := ParseLaunchdPlistProgramArgs(plist)
	if gotExe != exe || gotCfg != cfg {
		t.Fatalf("ParseLaunchdPlistProgramArgs = (%q, %q), want (%q, %q)", gotExe, gotCfg, exe, cfg)
	}

	running, state, pid := ParseLaunchctlPrint("\tstate = running\n\tpid = 9182\n")
	if !running || state != "running" || pid != 9182 {
		t.Fatalf("ParseLaunchctlPrint = (%v, %q, %d)", running, state, pid)
	}
}

func TestFormatAndParseWindowsServiceCommandLine(t *testing.T) {
	cases := []struct {
		exe string
		cfg string
	}{
		{
			exe: `C:\ProgramData\agent-bridge\agent-bridge.exe`,
			cfg: `C:\ProgramData\agent-bridge\server.json`,
		},
		{
			exe: `C:\Program Files\Agent Bridge\agent-bridge.exe`,
			cfg: `C:\ProgramData\Agent Bridge\config dir\server.json`,
		},
		{
			exe: `C:\Tools\agent-bridge\agent-bridge.exe`,
			cfg: `C:\ProgramData\agent-bridge\trailing\`,
		},
	}

	for _, tc := range cases {
		cmdLine := FormatWindowsServiceCommandLine(tc.exe, tc.cfg)
		if !strings.HasPrefix(cmdLine, `"`) || !strings.HasSuffix(cmdLine, `"`) {
			t.Fatalf("expected explicitly quoted command line, got %q", cmdLine)
		}
		gotExe, gotCfg := ParseServiceCommandLine(cmdLine)
		if gotExe != tc.exe || gotCfg != tc.cfg {
			t.Fatalf("round-trip mismatch for %q:\ngot  (%q, %q)\nwant (%q, %q)", cmdLine, gotExe, gotCfg, tc.exe, tc.cfg)
		}
	}
}

func TestNormalizeFirewallSubnetsAndBuildNetsh(t *testing.T) {
	defCSV, err := NormalizeFirewallSubnets(nil)
	if err != nil {
		t.Fatalf("NormalizeFirewallSubnets(nil): %v", err)
	}
	if defCSV != DefaultFirewallSubnetsCSV {
		t.Fatalf("default subnets = %q, want %q", defCSV, DefaultFirewallSubnetsCSV)
	}

	customCSV, err := NormalizeFirewallSubnets([]string{"100.64.0.0/10, 198.51.100.0/24", "100.64.0.0/10", "203.0.113.5"})
	if err != nil {
		t.Fatalf("NormalizeFirewallSubnets(custom): %v", err)
	}
	if customCSV != "100.64.0.0/10,198.51.100.0/24,203.0.113.5" {
		t.Fatalf("custom subnets = %q", customCSV)
	}

	if _, err := NormalizeFirewallSubnets([]string{"not-a-cidr"}); err == nil {
		t.Fatalf("expected invalid CIDR to fail")
	}

	exePath := `C:\Program Files\agent-bridge\agent-bridge.exe`
	cmds, rules, err := BuildNetshFirewallCommands(exePath, 8765, 8766, nil)
	if err != nil {
		t.Fatalf("BuildNetshFirewallCommands failed: %v", err)
	}
	if len(rules) != 2 || rules[0] != FirewallRuleExecName || rules[1] != FirewallRuleClusterName {
		t.Fatalf("unexpected rules: %+v", rules)
	}
	if len(cmds) != 4 {
		t.Fatalf("expected 4 netsh commands (2 delete + 2 add), got %d", len(cmds))
	}
	joinedAddExec := strings.Join(cmds[1], " | ")
	for _, wantArg := range []string{
		"name=AgentBridge-Exec",
		"localport=8765",
		"program=" + exePath,
		"remoteip=" + DefaultFirewallSubnetsCSV,
	} {
		if !strings.Contains(joinedAddExec, wantArg) {
			t.Fatalf("exec firewall add rule missing %q: %s", wantArg, joinedAddExec)
		}
	}
	joinedAddCluster := strings.Join(cmds[3], " | ")
	if !strings.Contains(joinedAddCluster, "name=AgentBridge-Cluster") || !strings.Contains(joinedAddCluster, "localport=8766") {
		t.Fatalf("cluster firewall add rule unexpected: %s", joinedAddCluster)
	}
}

type mockServiceManager struct {
	restartErr error
	startErr   error
	stopCalled bool
	startCount int
	status     *ServiceStatus
}

func (m *mockServiceManager) Install(context.Context, InstallOptions) (*InstallResult, error) {
	return nil, nil
}
func (m *mockServiceManager) Uninstall(context.Context, string) error { return nil }
func (m *mockServiceManager) Start(context.Context, string) error {
	m.startCount++
	if m.startErr != nil {
		return m.startErr
	}
	if m.status != nil {
		m.status.Running = true
		m.status.State = "running"
	}
	return nil
}
func (m *mockServiceManager) Stop(context.Context, string) error {
	m.stopCalled = true
	return nil
}
func (m *mockServiceManager) Restart(context.Context, string) error {
	return m.restartErr
}
func (m *mockServiceManager) Status(context.Context, string) (*ServiceStatus, error) {
	return m.status, nil
}
func (m *mockServiceManager) IsManagedServiceProcess() bool { return false }
func (m *mockServiceManager) RunManagedService(_ string, fn func(context.Context) int) (int, error) {
	return fn(context.Background()), nil
}

func TestBuildAndExecuteDetachedRestartWithRollback(t *testing.T) {
	rbPath := filepath.Join(t.TempDir(), "agent-bridge.old")
	args, err := BuildDetachedRestartArgs("agent-bridge", rbPath, 1500*time.Millisecond)
	if err != nil {
		t.Fatalf("BuildDetachedRestartArgs: %v", err)
	}
	wantArgs := []string{"service", "_detached-restart", "--name", "agent-bridge", "--delay", "1.5s", "--rollback-bin", rbPath}
	if !reflect.DeepEqual(args, wantArgs) {
		t.Fatalf("BuildDetachedRestartArgs = %v, want %v", args, wantArgs)
	}

	// 1. Happy path: restart succeeds and service is Running.
	okMgr := &mockServiceManager{
		status: &ServiceStatus{Name: "agent-bridge", Installed: true, Running: true, State: "running"},
	}
	if err := ExecuteDetachedRestart(context.Background(), DetachedRestartOptions{
		ServiceName: "agent-bridge",
		Delay:       5 * time.Millisecond,
		Manager:     okMgr,
	}); err != nil {
		t.Fatalf("ExecuteDetachedRestart happy path failed: %v", err)
	}

	// 2. Failure + automatic rollback path: upgraded binary fails to start, RollbackBin is restored over TargetBin.
	tmp := t.TempDir()
	targetBin := filepath.Join(tmp, "agent-bridge")
	rollbackBin := filepath.Join(tmp, "agent-bridge.prev")
	if err := os.WriteFile(targetBin, []byte("broken-v2-binary"), 0o755); err != nil {
		t.Fatalf("WriteFile(targetBin): %v", err)
	}
	if err := os.WriteFile(rollbackBin, []byte("healthy-v1-binary"), 0o755); err != nil {
		t.Fatalf("WriteFile(rollbackBin): %v", err)
	}

	failMgr := &mockServiceManager{
		restartErr: errors.New("exit status 1"),
		status: &ServiceStatus{
			Name:       "agent-bridge",
			Installed:  true,
			Running:    false,
			State:      "failed",
			BinaryPath: targetBin,
		},
	}

	err = ExecuteDetachedRestart(context.Background(), DetachedRestartOptions{
		ServiceName: "agent-bridge",
		Delay:       1 * time.Millisecond,
		RollbackBin: rollbackBin,
		Manager:     failMgr,
	})
	if err == nil || !strings.Contains(err.Error(), "automatically rolled back") {
		t.Fatalf("expected rollback diagnostic error, got: %v", err)
	}
	if !failMgr.stopCalled || failMgr.startCount != 1 {
		t.Fatalf("expected Stop and Start(1) during rollback, got stop=%v startCount=%d", failMgr.stopCalled, failMgr.startCount)
	}
	restored, err := os.ReadFile(targetBin)
	if err != nil {
		t.Fatalf("ReadFile(targetBin): %v", err)
	}
	if string(restored) != "healthy-v1-binary" {
		t.Fatalf("target binary was not rolled back, got %q", string(restored))
	}
}
