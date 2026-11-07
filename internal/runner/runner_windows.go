//go:build windows

package runner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsJobHandle struct {
	mu     sync.Mutex
	handle windows.Handle
	closed bool
}

func newWindowsJobObject() (*windowsJobHandle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("CreateJobObject failed: %w", err)
	}

	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

	_, err = windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	)
	if err != nil {
		_ = windows.CloseHandle(job)
		return nil, fmt.Errorf("SetInformationJobObject failed: %w", err)
	}

	return &windowsJobHandle{handle: job}, nil
}

func (j *windowsJobHandle) assignPID(pid int) error {
	if pid <= 0 {
		return errors.New("invalid process PID for Job Object assignment")
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.handle == 0 {
		return errors.New("job object already closed")
	}

	procHandle, err := windows.OpenProcess(
		windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE,
		false,
		uint32(pid),
	)
	if err != nil {
		return err
	}
	defer func() {
		_ = windows.CloseHandle(procHandle)
	}()

	return windows.AssignProcessToJobObject(j.handle, procHandle)
}

func (j *windowsJobHandle) terminate() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.handle == 0 {
		return nil
	}
	return windows.TerminateJobObject(j.handle, 1)
}

func (j *windowsJobHandle) close() {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed || j.handle == 0 {
		return
	}
	_ = windows.TerminateJobObject(j.handle, 1)
	_ = windows.CloseHandle(j.handle)
	j.handle = 0
	j.closed = true
}

func runCommandIsolated(
	ctx context.Context,
	executable string,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
) (startErr error, waitErr error) {
	job, err := newWindowsJobObject()
	if err != nil {
		return err, nil
	}
	defer job.close()

	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true,
	}
	cmd.WaitDelay = defaultWaitDelay
	cmd.Cancel = func() error {
		jobErr := job.terminate()
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		return jobErr
	}

	if err := cmd.Start(); err != nil {
		return err, nil
	}

	if assignErr := job.assignPID(cmd.Process.Pid); assignErr != nil {
		if ctx.Err() != nil {
			_ = cmd.Process.Kill()
		}
	} else if ctx.Err() != nil {
		_ = job.terminate()
	}

	waitErr = cmd.Wait()
	if errors.Is(waitErr, exec.ErrWaitDelay) && cmd.ProcessState != nil && cmd.ProcessState.ExitCode() == 0 {
		waitErr = nil
	}
	return nil, waitErr
}

func normalizeExitCode(exitErr *exec.ExitError) int {
	if exitErr == nil {
		return 1
	}
	if code := exitErr.ExitCode(); code >= 0 {
		return code
	}
	return 1
}
