package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// DefaultServiceName is the default OS service identifier across Windows SCM, systemd, and launchd.
	DefaultServiceName = "agent-bridge"
	// DefaultDisplayName is the human-readable service display name.
	DefaultDisplayName = "Agent-Bridge mTLS Execution & Cluster Service"
	// DefaultDescription describes the managed background daemon.
	DefaultDescription = "Agent-Bridge TLS 1.3 mutual-TLS remote execution and cluster service"

	// LegacyWindowsScheduledTaskName is the legacy pre-SCM Windows Scheduled Task migrated during Install.
	LegacyWindowsScheduledTaskName = `\AgentBridge-Server`
	// TransientDetachedRestartTaskName is the fallback Windows Scheduled Task name used if job breakaway and WMI are blocked.
	TransientDetachedRestartTaskName = `\AgentBridge-DetachedRestart`
	// LegacyWindowsRunScriptFilename is the legacy PowerShell wrapper cleaned up during Scheduled Task migration.
	LegacyWindowsRunScriptFilename = "run-daemon.ps1"

	// FirewallRuleExecName and FirewallRuleClusterName are the Windows Firewall inbound rule names.
	FirewallRuleExecName    = "AgentBridge-Exec"
	FirewallRuleClusterName = "AgentBridge-Cluster"

	// DefaultFirewallSubnetsCSV restricts Windows Firewall inbound rules to CGNAT/Tailscale and RFC 1918 subnets by default.
	DefaultFirewallSubnetsCSV = "100.64.0.0/10,192.168.0.0/16,10.0.0.0/8,172.16.0.0/12"

	// EnvInExec marks child processes spawned inside an active `/ws/exec` command session.
	EnvInExec = "AGENT_BRIDGE_IN_EXEC"
)

// ErrServiceNotInstalled indicates the target OS service has not been installed.
var ErrServiceNotInstalled = errors.New("service is not installed")

// InstallOptions configures OS service registration, server.json persistence, and optional OS hardening.
type InstallOptions struct {
	Name                   string
	DisplayName            string
	Description            string
	BinaryPath             string
	ConfigPath             string
	Config                 *ServerDaemonConfig
	StartNow               bool
	ConfigureFirewall      bool
	FirewallAllowedSubnets []string
	ExecPort               int
	ClusterPort            int
	DefenderExclusion      bool
}

// InstallResult reports the outcome of Manager.Install.
type InstallResult struct {
	Name                  string   `json:"name"`
	ServiceType           string   `json:"service_type"`
	BinaryPath            string   `json:"binary_path"`
	ConfigPath            string   `json:"config_path"`
	LogPath               string   `json:"log_path,omitempty"`
	UnitPath              string   `json:"unit_path,omitempty"`
	MigratedScheduledTask bool     `json:"migrated_scheduled_task,omitempty"`
	FirewallConfigured    bool     `json:"firewall_configured,omitempty"`
	FirewallRules         []string `json:"firewall_rules,omitempty"`
	DefenderExcluded      bool     `json:"defender_excluded,omitempty"`
	Started               bool     `json:"started"`
	Warnings              []string `json:"warnings,omitempty"`
}

// ServiceStatus describes the current installation and runtime state of an OS service.
type ServiceStatus struct {
	Name        string `json:"name"`
	Installed   bool   `json:"installed"`
	Running     bool   `json:"running"`
	State       string `json:"state"`
	PID         int    `json:"pid"`
	BinaryPath  string `json:"binary_path,omitempty"`
	ConfigPath  string `json:"config_path,omitempty"`
	LogPath     string `json:"log_path,omitempty"`
	ServiceType string `json:"service_type"`
	UnitPath    string `json:"unit_path,omitempty"`
}

// Manager abstracts native OS service lifecycle operations (Windows SCM, Linux systemd, macOS launchd).
type Manager interface {
	Install(ctx context.Context, opts InstallOptions) (*InstallResult, error)
	Uninstall(ctx context.Context, name string) error
	Start(ctx context.Context, name string) error
	Stop(ctx context.Context, name string) error
	Restart(ctx context.Context, name string) error
	Status(ctx context.Context, name string) (*ServiceStatus, error)
	IsManagedServiceProcess() bool
	RunManagedService(name string, runFn func(ctx context.Context) int) (int, error)
}

// NewManager returns the native OS service Manager for the current platform.
func NewManager() Manager {
	return newPlatformManager()
}

// ValidateServiceName normalizes name (defaulting empty strings to DefaultServiceName) and rejects
// path separators, whitespace, or shell/unit metacharacters.
func ValidateServiceName(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return DefaultServiceName, nil
	}
	if len(trimmed) > 128 {
		return "", fmt.Errorf("service name %q exceeds 128 characters", trimmed)
	}
	for i := 0; i < len(trimmed); i++ {
		ch := trimmed[i]
		valid := (ch >= 'a' && ch <= 'z') ||
			(ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == '-' || ch == '_' || ch == '.'
		if !valid || (i == 0 && ch == '.') {
			return "", fmt.Errorf("invalid service name %q: must contain only [A-Za-z0-9._-] and not start with '.'", name)
		}
	}
	return trimmed, nil
}

// DetachedRestartOptions configures ExecuteDetachedRestart (`agent-bridge service _detached-restart`).
type DetachedRestartOptions struct {
	ServiceName string
	Delay       time.Duration
	RollbackBin string
	TargetBin   string
	Manager     Manager
}

// BuildDetachedRestartArgs constructs the exact CLI argument slice passed to `<exePath>` by
// SpawnDetachedServiceRestart.
func BuildDetachedRestartArgs(serviceName, rollbackPath string, delay time.Duration) ([]string, error) {
	normName, err := ValidateServiceName(serviceName)
	if err != nil {
		return nil, err
	}
	if delay < 0 {
		delay = 0
	}
	args := []string{
		"service",
		"_detached-restart",
		"--name", normName,
		"--delay", delay.String(),
	}
	if rb := strings.TrimSpace(rollbackPath); rb != "" {
		args = append(args, "--rollback-bin", filepath.Clean(rb))
	}
	return args, nil
}

// ExecuteDetachedRestart waits `opts.Delay`, restarts `opts.ServiceName` via `opts.Manager` (or NewManager()),
// verifies the service reaches Running state, and automatically restores `opts.RollbackBin` and starts
// the previous binary if the upgraded service fails to restart cleanly.
func ExecuteDetachedRestart(ctx context.Context, opts DetachedRestartOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	svcName, err := ValidateServiceName(opts.ServiceName)
	if err != nil {
		return err
	}
	mgr := opts.Manager
	if mgr == nil {
		mgr = NewManager()
	}

	if opts.Delay > 0 {
		timer := time.NewTimer(opts.Delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}

	restartErr := mgr.Restart(ctx, svcName)
	if restartErr == nil {
		st, stErr := mgr.Status(ctx, svcName)
		if stErr == nil && st != nil && st.Running {
			return nil
		}
		if stErr != nil {
			restartErr = stErr
		} else {
			restartErr = fmt.Errorf("service %q is not running after restart (state=%s)", svcName, st.State)
		}
	}

	rollbackBin := strings.TrimSpace(opts.RollbackBin)
	if rollbackBin == "" {
		return fmt.Errorf("service restart failed: %w", restartErr)
	}

	targetBin := strings.TrimSpace(opts.TargetBin)
	if targetBin == "" {
		if st, stErr := mgr.Status(ctx, svcName); stErr == nil && st != nil && st.BinaryPath != "" {
			targetBin = st.BinaryPath
		}
	}
	if targetBin == "" {
		if exe, exeErr := os.Executable(); exeErr == nil {
			targetBin = exe
		}
	}
	if targetBin == "" {
		return fmt.Errorf("service restart failed (%v) and target binary path could not be determined for rollback", restartErr)
	}

	_ = mgr.Stop(ctx, svcName)
	if rbErr := restoreRollbackBinary(rollbackBin, targetBin); rbErr != nil {
		return fmt.Errorf("service restart failed (%v) and binary rollback (%q -> %q) failed: %w", restartErr, rollbackBin, targetBin, rbErr)
	}
	if startErr := mgr.Start(ctx, svcName); startErr != nil {
		return fmt.Errorf("service restart failed (%v); restored %q -> %q, but starting rolled-back service failed: %w", restartErr, rollbackBin, targetBin, startErr)
	}
	return fmt.Errorf("upgraded service failed to start (%v); automatically rolled back to %q and restarted", restartErr, rollbackBin)
}

func restoreRollbackBinary(rollbackBin, targetBin string) error {
	cleanRB := filepath.Clean(rollbackBin)
	cleanTarget := filepath.Clean(targetBin)
	if cleanRB == cleanTarget {
		return nil
	}
	if _, err := os.Stat(cleanRB); err != nil {
		return err
	}
	if err := os.Rename(cleanRB, cleanTarget); err == nil {
		return nil
	}
	data, err := os.ReadFile(cleanRB)
	if err != nil {
		return err
	}
	tmpPath := cleanTarget + ".rollback-tmp"
	if err := os.WriteFile(tmpPath, data, 0o755); err != nil {
		return err
	}
	return os.Rename(tmpPath, cleanTarget)
}

func resolveInstallBasics(opts InstallOptions) (svcName, displayName, description, exePath, cfgPath, logPath string, err error) {
	svcName, err = ValidateServiceName(opts.Name)
	if err != nil {
		return "", "", "", "", "", "", err
	}

	displayName = strings.TrimSpace(opts.DisplayName)
	if displayName == "" {
		displayName = DefaultDisplayName
	}
	description = strings.TrimSpace(opts.Description)
	if description == "" {
		description = DefaultDescription
	}

	rawExe := strings.TrimSpace(opts.BinaryPath)
	if rawExe == "" {
		detectedExe, exeErr := os.Executable()
		if exeErr != nil {
			return "", "", "", "", "", "", fmt.Errorf("failed to determine executable path: %w", exeErr)
		}
		rawExe = detectedExe
	}
	absExe, err := filepath.Abs(rawExe)
	if err != nil {
		return "", "", "", "", "", "", fmt.Errorf("failed to resolve absolute executable path %q: %w", rawExe, err)
	}
	exePath = filepath.Clean(absExe)

	defaults := DefaultPaths()
	rawCfg := strings.TrimSpace(opts.ConfigPath)
	if rawCfg == "" {
		rawCfg = defaults.ConfigPath
	}
	absCfg, err := filepath.Abs(rawCfg)
	if err != nil {
		return "", "", "", "", "", "", fmt.Errorf("failed to resolve absolute config path %q: %w", rawCfg, err)
	}
	cfgPath = filepath.Clean(absCfg)

	logPath = defaults.LogPath
	if opts.Config != nil && strings.TrimSpace(opts.Config.LogPath) != "" {
		logPath = filepath.Clean(strings.TrimSpace(opts.Config.LogPath))
	}
	return svcName, displayName, description, exePath, cfgPath, logPath, nil
}

func resolveLogPathFromConfig(cfgPath string) string {
	if trimmed := strings.TrimSpace(cfgPath); trimmed != "" {
		if cfg, err := LoadServerDaemonConfig(trimmed); err == nil && cfg != nil && strings.TrimSpace(cfg.LogPath) != "" {
			return filepath.Clean(strings.TrimSpace(cfg.LogPath))
		}
	}
	return DefaultPaths().LogPath
}

func stripInExecEnv(environ []string) []string {
	prefix := EnvInExec + "="
	filtered := make([]string, 0, len(environ))
	for _, kv := range environ {
		if strings.HasPrefix(kv, prefix) || strings.EqualFold(strings.SplitN(kv, "=", 2)[0], EnvInExec) {
			continue
		}
		filtered = append(filtered, kv)
	}
	return filtered
}
