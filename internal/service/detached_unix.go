//go:build !windows

package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

// ConfigureWindowsFirewall is a non-Windows stub returning an error if invoked directly outside Windows.
func ConfigureWindowsFirewall(
	_ context.Context,
	_ string,
	_ int,
	_ int,
	_ []string,
) ([]string, error) {
	return nil, fmt.Errorf("Windows Firewall configuration is not supported on %s", runtime.GOOS)
}

// AddWindowsDefenderExclusion is a non-Windows stub returning an error if invoked directly outside Windows.
func AddWindowsDefenderExclusion(_ context.Context, _ string) error {
	return fmt.Errorf("Microsoft Defender exclusions are not supported on %s", runtime.GOOS)
}

// SpawnDetachedServiceRestart spawns `<exePath> service _detached-restart --name <serviceName> --delay <delay> [--rollback-bin <rollbackPath>]`
// in a new POSIX session (`Setsid: true`) detached from the current process group so an active `/ws/exec`
// session (`AGENT_BRIDGE_IN_EXEC=1`) can return its upgrade response before restarting the daemon.
func SpawnDetachedServiceRestart(exePath, serviceName, rollbackPath string, delay time.Duration) error {
	resolvedExe := strings.TrimSpace(exePath)
	if resolvedExe == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("failed to resolve executable path for detached restart: %w", err)
		}
		resolvedExe = exe
	}
	absExe, err := filepath.Abs(resolvedExe)
	if err != nil {
		return fmt.Errorf("failed to resolve absolute executable path %q: %w", resolvedExe, err)
	}
	cleanExe := filepath.Clean(absExe)

	args, err := BuildDetachedRestartArgs(serviceName, rollbackPath, delay)
	if err != nil {
		return err
	}

	cmd := exec.Command(cleanExe, args...)
	cmd.Dir = os.TempDir()
	cmd.Env = stripInExecEnv(os.Environ())
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to spawn detached service restart (%s %s): %w", cleanExe, strings.Join(args, " "), err)
	}
	if cmd.Process != nil {
		_ = cmd.Process.Release()
	}
	return nil
}
