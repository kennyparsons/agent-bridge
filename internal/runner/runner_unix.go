//go:build !windows

package runner

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"time"
)

func runCommandIsolated(
	ctx context.Context,
	executable string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) (startErr error, waitErr error) {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Env = commandEnv()
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}
	cmd.WaitDelay = defaultWaitDelay
	cmd.Cancel = func() error {
		return killProcessGroup(cmd.Process)
	}

	if err := cmd.Start(); err != nil {
		return err, nil
	}

	pgid := cmd.Process.Pid
	waitErr = cmd.Wait()

	// Terminate any remaining background children in the process group and wait briefly
	// for OS reaping so killed descendants are completely gone before returning.
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	waitForProcessGroupExit(pgid, 150*time.Millisecond)

	if errors.Is(waitErr, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 0 {
		waitErr = nil
	}

	return nil, waitErr
}

func killProcessGroup(proc *os.Process) error {
	if proc == nil || proc.Pid <= 0 {
		return os.ErrProcessDone
	}
	err := syscall.Kill(-proc.Pid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return os.ErrProcessDone
	}
	return err
}

func waitForProcessGroupExit(pgid int, maxWait time.Duration) {
	if pgid <= 0 {
		return
	}
	if err := syscall.Kill(-pgid, 0); errors.Is(err, syscall.ESRCH) {
		return
	}
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
		if err := syscall.Kill(-pgid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
	}
}

func normalizeExitCode(exitErr *exec.ExitError) int {
	if exitErr == nil {
		return 1
	}
	if code := exitErr.ExitCode(); code >= 0 {
		return code
	}
	if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return 1
}
