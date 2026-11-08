//go:build linux

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/kennyparsons/agent-bridge/internal/acl"
	"github.com/kennyparsons/agent-bridge/internal/pki"
)

const defaultSystemdUnitDir = "/etc/systemd/system"

type cmdRunnerFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

func defaultCmdRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

type linuxManager struct {
	unitDir string
	runCmd  cmdRunnerFunc
}

func newPlatformManager() Manager {
	return &linuxManager{
		unitDir: defaultSystemdUnitDir,
		runCmd:  defaultCmdRunner,
	}
}

// IsManagedServiceProcess returns false on Linux because systemd (`Type=simple`) runs the binary
// directly as a standard foreground process managed via POSIX signals rather than Win32 SCM pipes.
func IsManagedServiceProcess() bool {
	return false
}

// RunManagedService executes runFn with a context canceled on SIGINT or SIGTERM.
func RunManagedService(_ string, runFn func(ctx context.Context) int) (int, error) {
	if runFn == nil {
		return 1, errors.New("service runFn cannot be nil")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runFn(ctx), nil
}

func (m *linuxManager) IsManagedServiceProcess() bool {
	return IsManagedServiceProcess()
}

func (m *linuxManager) RunManagedService(name string, runFn func(ctx context.Context) int) (int, error) {
	return RunManagedService(name, runFn)
}

func (m *linuxManager) unitPath(svcName string) string {
	dir := m.unitDir
	if strings.TrimSpace(dir) == "" {
		dir = defaultSystemdUnitDir
	}
	return filepath.Join(dir, svcName+".service")
}

func (m *linuxManager) execSystemctl(ctx context.Context, args ...string) (string, error) {
	runner := m.runCmd
	if runner == nil {
		runner = defaultCmdRunner
	}
	out, err := runner(ctx, "systemctl", args...)
	trimmed := strings.TrimSpace(string(out))
	if err != nil {
		if trimmed != "" {
			return trimmed, fmt.Errorf("systemctl %s failed: %w: %s", strings.Join(args, " "), err, trimmed)
		}
		return "", fmt.Errorf("systemctl %s failed: %w", strings.Join(args, " "), err)
	}
	return trimmed, nil
}

func (m *linuxManager) Install(ctx context.Context, opts InstallOptions) (*InstallResult, error) {
	svcName, _, description, exePath, cfgPath, logPath, err := resolveInstallBasics(opts)
	if err != nil {
		return nil, err
	}

	if opts.Config != nil {
		if strings.TrimSpace(opts.Config.DataDir) != "" {
			if err := acl.LockdownServerDir(opts.Config.DataDir); err != nil {
				return nil, fmt.Errorf("failed to lock down server data directory %q: %w", opts.Config.DataDir, err)
			}
		}
		if strings.TrimSpace(logPath) != "" {
			if err := acl.LockdownServerDir(filepath.Dir(logPath)); err != nil {
				return nil, fmt.Errorf("failed to lock down server log directory %q: %w", filepath.Dir(logPath), err)
			}
		}
		if err := SaveServerDaemonConfig(cfgPath, opts.Config); err != nil {
			return nil, err
		}
	}

	unitContent, err := RenderSystemdUnit(svcName, description, exePath, cfgPath)
	if err != nil {
		return nil, err
	}

	uPath := m.unitPath(svcName)
	if err := os.MkdirAll(filepath.Dir(uPath), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create systemd unit directory %q: %w", filepath.Dir(uPath), err)
	}
	if err := pki.WriteFileAtomic(uPath, []byte(unitContent), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write systemd unit %q: %w", uPath, err)
	}
	if err := os.Chmod(uPath, 0o644); err != nil {
		return nil, fmt.Errorf("failed to chmod systemd unit %q: %w", uPath, err)
	}

	unitName := svcName + ".service"
	if _, err := m.execSystemctl(ctx, "daemon-reload"); err != nil {
		return nil, err
	}
	if _, err := m.execSystemctl(ctx, "enable", unitName); err != nil {
		return nil, err
	}

	var warnings []string
	if opts.ConfigureFirewall {
		warnings = append(warnings, "ConfigureFirewall is Windows-only and was skipped on linux")
	}
	if opts.DefenderExclusion {
		warnings = append(warnings, "DefenderExclusion is Windows-only and was skipped on linux")
	}

	started := false
	if opts.StartNow {
		if _, err := m.execSystemctl(ctx, "restart", unitName); err != nil {
			return nil, err
		}
		started = true
	}

	return &InstallResult{
		Name:        svcName,
		ServiceType: "systemd",
		BinaryPath:  exePath,
		ConfigPath:  cfgPath,
		LogPath:     logPath,
		UnitPath:    uPath,
		Started:     started,
		Warnings:    warnings,
	}, nil
}

func (m *linuxManager) Uninstall(ctx context.Context, name string) error {
	svcName, err := ValidateServiceName(name)
	if err != nil {
		return err
	}
	unitName := svcName + ".service"
	_, _ = m.execSystemctl(ctx, "stop", unitName)
	_, _ = m.execSystemctl(ctx, "disable", unitName)

	uPath := m.unitPath(svcName)
	if rmErr := os.Remove(uPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		return fmt.Errorf("failed to remove systemd unit %q: %w", uPath, rmErr)
	}

	_, _ = m.execSystemctl(ctx, "daemon-reload")
	_, _ = m.execSystemctl(ctx, "reset-failed", unitName)
	return nil
}

func (m *linuxManager) Start(ctx context.Context, name string) error {
	svcName, err := ValidateServiceName(name)
	if err != nil {
		return err
	}
	_, err = m.execSystemctl(ctx, "start", svcName+".service")
	return err
}

func (m *linuxManager) Stop(ctx context.Context, name string) error {
	svcName, err := ValidateServiceName(name)
	if err != nil {
		return err
	}
	_, err = m.execSystemctl(ctx, "stop", svcName+".service")
	return err
}

func (m *linuxManager) Restart(ctx context.Context, name string) error {
	svcName, err := ValidateServiceName(name)
	if err != nil {
		return err
	}
	_, err = m.execSystemctl(ctx, "restart", svcName+".service")
	return err
}

func (m *linuxManager) Status(ctx context.Context, name string) (*ServiceStatus, error) {
	svcName, err := ValidateServiceName(name)
	if err != nil {
		return nil, err
	}

	uPath := m.unitPath(svcName)
	unitExists := false
	var exePath, cfgPath string
	if rawUnit, readErr := os.ReadFile(uPath); readErr == nil {
		unitExists = true
		for _, line := range strings.Split(string(rawUnit), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "ExecStart=") {
				cmdLine := strings.TrimSpace(strings.TrimPrefix(trimmed, "ExecStart="))
				exePath, cfgPath = ParseServiceCommandLine(cmdLine)
				break
			}
		}
	}

	unitName := svcName + ".service"
	out, showErr := m.execSystemctl(
		ctx,
		"show",
		unitName,
		"--no-pager",
		"--property=LoadState,ActiveState,SubState,MainPID,FragmentPath",
	)
	props := ParseSystemctlShow(out)

	loadState := props["LoadState"]
	activeState := props["ActiveState"]
	subState := props["SubState"]
	if frag := props["FragmentPath"]; frag != "" && !unitExists {
		if _, statErr := os.Stat(frag); statErr == nil {
			unitExists = true
			uPath = frag
		}
	}

	installed := unitExists || (showErr == nil && loadState != "" && loadState != "not-found")
	pid := 0
	if rawPID := props["MainPID"]; rawPID != "" {
		if p, convErr := strconv.Atoi(rawPID); convErr == nil && p > 0 {
			pid = p
		}
	}

	running := activeState == "active" && (subState == "running" || subState == "listening" || subState == "")
	state := "not-installed"
	if installed {
		switch {
		case running:
			state = "running"
		case activeState == "inactive" || activeState == "deactivating" || activeState == "":
			state = "stopped"
		default:
			state = activeState
		}
	}

	if cfgPath == "" && installed {
		cfgPath = DefaultPaths().ConfigPath
	}
	logPath := ""
	if installed {
		logPath = resolveLogPathFromConfig(cfgPath)
	}

	return &ServiceStatus{
		Name:        svcName,
		Installed:   installed,
		Running:     running,
		State:       state,
		PID:         pid,
		BinaryPath:  exePath,
		ConfigPath:  cfgPath,
		LogPath:     logPath,
		ServiceType: "systemd",
		UnitPath:    uPath,
	}, nil
}
