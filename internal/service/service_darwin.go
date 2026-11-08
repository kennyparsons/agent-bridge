//go:build darwin

package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/kennyparsons/agent-bridge/internal/acl"
	"github.com/kennyparsons/agent-bridge/internal/pki"
)

const defaultLaunchDaemonsDir = "/Library/LaunchDaemons"

type cmdRunnerFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

func defaultCmdRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.CombinedOutput()
}

type darwinManager struct {
	plistDir string
	runCmd   cmdRunnerFunc
}

func newPlatformManager() Manager {
	return &darwinManager{
		plistDir: defaultLaunchDaemonsDir,
		runCmd:   defaultCmdRunner,
	}
}

// IsManagedServiceProcess returns false on macOS because launchd runs the binary directly as a
// standard foreground process managed via POSIX signals rather than Win32 SCM pipes.
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

func (m *darwinManager) IsManagedServiceProcess() bool {
	return IsManagedServiceProcess()
}

func (m *darwinManager) RunManagedService(name string, runFn func(ctx context.Context) int) (int, error) {
	return RunManagedService(name, runFn)
}

func (m *darwinManager) plistPath(label string) string {
	dir := m.plistDir
	if strings.TrimSpace(dir) == "" {
		dir = defaultLaunchDaemonsDir
	}
	return filepath.Join(dir, label+".plist")
}

func (m *darwinManager) execLaunchctl(ctx context.Context, args ...string) (string, error) {
	runner := m.runCmd
	if runner == nil {
		runner = defaultCmdRunner
	}
	out, err := runner(ctx, "launchctl", args...)
	trimmed := strings.TrimSpace(string(out))
	if err != nil {
		if trimmed != "" {
			return trimmed, fmt.Errorf("launchctl %s failed: %w: %s", strings.Join(args, " "), err, trimmed)
		}
		return "", fmt.Errorf("launchctl %s failed: %w", strings.Join(args, " "), err)
	}
	return trimmed, nil
}

func (m *darwinManager) Install(ctx context.Context, opts InstallOptions) (*InstallResult, error) {
	svcName, _, _, exePath, cfgPath, logPath, err := resolveInstallBasics(opts)
	if err != nil {
		return nil, err
	}
	label, err := LaunchdLabel(svcName)
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

	plistContent, err := RenderLaunchdPlist(svcName, exePath, cfgPath)
	if err != nil {
		return nil, err
	}

	pPath := m.plistPath(label)
	if err := os.MkdirAll(filepath.Dir(pPath), 0o755); err != nil {
		return nil, fmt.Errorf("failed to create LaunchDaemons directory %q: %w", filepath.Dir(pPath), err)
	}
	if err := pki.WriteFileAtomic(pPath, []byte(plistContent), 0o644); err != nil {
		return nil, fmt.Errorf("failed to write LaunchDaemon plist %q: %w", pPath, err)
	}
	if err := os.Chmod(pPath, 0o644); err != nil {
		return nil, fmt.Errorf("failed to chmod LaunchDaemon plist %q: %w", pPath, err)
	}

	var warnings []string
	if opts.ConfigureFirewall {
		warnings = append(warnings, "ConfigureFirewall is Windows-only and was skipped on darwin")
	}
	if opts.DefenderExclusion {
		warnings = append(warnings, "DefenderExclusion is Windows-only and was skipped on darwin")
	}

	domainTarget := "system/" + label
	_, _ = m.execLaunchctl(ctx, "enable", domainTarget)

	started := false
	if opts.StartNow {
		_, _ = m.execLaunchctl(ctx, "bootout", domainTarget)
		if _, err := m.execLaunchctl(ctx, "bootstrap", "system", pPath); err != nil {
			return nil, err
		}
		_, _ = m.execLaunchctl(ctx, "kickstart", "-k", domainTarget)
		started = true
	}

	return &InstallResult{
		Name:        svcName,
		ServiceType: "launchd",
		BinaryPath:  exePath,
		ConfigPath:  cfgPath,
		LogPath:     logPath,
		UnitPath:    pPath,
		Started:     started,
		Warnings:    warnings,
	}, nil
}

func (m *darwinManager) Uninstall(ctx context.Context, name string) error {
	label, err := LaunchdLabel(name)
	if err != nil {
		return err
	}
	_, _ = m.execLaunchctl(ctx, "bootout", "system/"+label)

	pPath := m.plistPath(label)
	if rmErr := os.Remove(pPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		return fmt.Errorf("failed to remove LaunchDaemon plist %q: %w", pPath, rmErr)
	}
	return nil
}

func (m *darwinManager) Start(ctx context.Context, name string) error {
	label, err := LaunchdLabel(name)
	if err != nil {
		return err
	}
	pPath := m.plistPath(label)
	domainTarget := "system/" + label

	if _, printErr := m.execLaunchctl(ctx, "print", domainTarget); printErr == nil {
		_, err = m.execLaunchctl(ctx, "kickstart", domainTarget)
		return err
	}
	if _, statErr := os.Stat(pPath); statErr != nil {
		return fmt.Errorf("%w: %s (%s)", ErrServiceNotInstalled, name, pPath)
	}
	_, err = m.execLaunchctl(ctx, "bootstrap", "system", pPath)
	return err
}

func (m *darwinManager) Stop(ctx context.Context, name string) error {
	label, err := LaunchdLabel(name)
	if err != nil {
		return err
	}
	domainTarget := "system/" + label
	if _, printErr := m.execLaunchctl(ctx, "print", domainTarget); printErr != nil {
		return nil
	}
	_, err = m.execLaunchctl(ctx, "bootout", domainTarget)
	return err
}

func (m *darwinManager) Restart(ctx context.Context, name string) error {
	label, err := LaunchdLabel(name)
	if err != nil {
		return err
	}
	pPath := m.plistPath(label)
	domainTarget := "system/" + label

	if _, printErr := m.execLaunchctl(ctx, "print", domainTarget); printErr == nil {
		_, err = m.execLaunchctl(ctx, "kickstart", "-k", domainTarget)
		return err
	}
	if _, statErr := os.Stat(pPath); statErr != nil {
		return fmt.Errorf("%w: %s (%s)", ErrServiceNotInstalled, name, pPath)
	}
	_, err = m.execLaunchctl(ctx, "bootstrap", "system", pPath)
	return err
}

func (m *darwinManager) Status(ctx context.Context, name string) (*ServiceStatus, error) {
	svcName, err := ValidateServiceName(name)
	if err != nil {
		return nil, err
	}
	label, err := LaunchdLabel(svcName)
	if err != nil {
		return nil, err
	}

	pPath := m.plistPath(label)
	plistExists := false
	var exePath, cfgPath string
	if rawPlist, readErr := os.ReadFile(pPath); readErr == nil {
		plistExists = true
		exePath, cfgPath = ParseLaunchdPlistProgramArgs(string(rawPlist))
	}

	out, printErr := m.execLaunchctl(ctx, "print", "system/"+label)
	installed := plistExists || printErr == nil
	running := false
	state := "not-installed"
	pid := 0

	if printErr == nil {
		running, state, pid = ParseLaunchctlPrint(out)
	} else if installed {
		state = "stopped"
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
		ServiceType: "launchd",
		UnitPath:    pPath,
	}, nil
}
