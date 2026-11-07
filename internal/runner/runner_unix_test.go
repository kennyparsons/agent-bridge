//go:build !windows

package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/protocol"
)

func TestRunCleanExitAndWhitespaceTrimming(t *testing.T) {
	resp := Run(context.Background(), protocol.CommandRequest{
		Command: "printf '  \\n\\t  hello agent-bridge  \\r\\n\\n  '",
	}, "")

	if resp.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 (stderr=%q)", resp.ExitCode, resp.Stderr)
	}
	if resp.Stdout != "hello agent-bridge" {
		t.Fatalf("Stdout = %q, want %q", resp.Stdout, "hello agent-bridge")
	}
	if resp.Stderr != "" {
		t.Fatalf("Stderr = %q, want empty", resp.Stderr)
	}
}

func TestRunNonZeroExitCodeMirroring(t *testing.T) {
	resp := Run(context.Background(), protocol.CommandRequest{
		Command: "printf '  object not found  \\n' >&2; exit 42",
	}, "sh")

	if resp.ExitCode != 42 {
		t.Fatalf("ExitCode = %d, want 42", resp.ExitCode)
	}
	if resp.Stdout != "" {
		t.Fatalf("Stdout = %q, want empty", resp.Stdout)
	}
	if resp.Stderr != "object not found" {
		t.Fatalf("Stderr = %q, want %q", resp.Stderr, "object not found")
	}

	silentFail := Run(context.Background(), protocol.CommandRequest{
		Command: "exit 7",
	}, "/bin/sh")
	if silentFail.ExitCode != 7 {
		t.Fatalf("ExitCode = %d, want 7", silentFail.ExitCode)
	}
	if silentFail.Stdout != "" || silentFail.Stderr != "" {
		t.Fatalf("expected empty streams on silent exit 7, got stdout=%q stderr=%q", silentFail.Stdout, silentFail.Stderr)
	}
}

func TestRunTimeoutKillsGrandchildProcessGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	cmd := fmt.Sprintf(`sh -c 'echo $$ > %q; exec sleep 30' & wait`, pidFile)

	start := time.Now()
	resp := Run(context.Background(), protocol.CommandRequest{
		Command:        cmd,
		TimeoutSeconds: 1,
	}, "sh")
	elapsed := time.Since(start)

	if elapsed > 3*time.Second {
		t.Fatalf("timeout took too long (%v), expected ~1s", elapsed)
	}
	if resp.ExitCode != ExitCodeTimeout {
		t.Fatalf("ExitCode = %d, want %d (stderr=%q)", resp.ExitCode, ExitCodeTimeout, resp.Stderr)
	}
	if !strings.Contains(resp.Stderr, "command timed out after 1s") {
		t.Fatalf("Stderr = %q, want timeout diagnostic", resp.Stderr)
	}

	childPID := readPIDFileEventually(t, pidFile, time.Second)
	if err := syscall.Kill(childPID, 0); !errors.Is(err, syscall.ESRCH) {
		_ = syscall.Kill(childPID, syscall.SIGKILL)
		t.Fatalf("grandchild PID %d survived timeout: Kill(pid, 0) err = %v, want ESRCH", childPID, err)
	}
}

func TestRunParentContextCancelKillsGrandchildImmediately(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "disconnect-grandchild.pid")
	cmd := fmt.Sprintf(`sh -c 'echo $$ > %q; exec sleep 30' & wait`, pidFile)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	doneCh := make(chan protocol.CommandResponse, 1)
	go func() {
		doneCh <- Run(ctx, protocol.CommandRequest{
			Command:        cmd,
			TimeoutSeconds: 30,
		}, "sh")
	}()

	childPID := readPIDFileEventually(t, pidFile, 3*time.Second)

	cancelStart := time.Now()
	cancel()

	var resp protocol.CommandResponse
	select {
	case resp = <-doneCh:
	case <-time.After(2 * time.Second):
		_ = syscall.Kill(childPID, syscall.SIGKILL)
		t.Fatal("Run did not return within 2s after parent context cancellation")
	}

	if elapsed := time.Since(cancelStart); elapsed > time.Second {
		t.Fatalf("cancellation took %v, expected < 1s", elapsed)
	}
	if resp.ExitCode != ExitCodeCanceled {
		t.Fatalf("ExitCode = %d, want %d (stderr=%q)", resp.ExitCode, ExitCodeCanceled, resp.Stderr)
	}
	if err := syscall.Kill(childPID, 0); !errors.Is(err, syscall.ESRCH) {
		_ = syscall.Kill(childPID, syscall.SIGKILL)
		t.Fatalf("grandchild PID %d survived parent ctx cancel: Kill(pid, 0) err = %v, want ESRCH", childPID, err)
	}
}

func TestRunStdoutAndStderrOverflowHaltsImmediately(t *testing.T) {
	t.Run("stdout overflow > 10 MiB", func(t *testing.T) {
		pidFile := filepath.Join(t.TempDir(), "overflow-child.pid")
		// Spawn a background sleeper in the same process group plus a fast >10 MiB stdout flood.
		cmd := fmt.Sprintf(`sh -c 'echo $$ > %q; exec sleep 30' & head -c 12582912 /dev/zero | tr '\0' 'A'; wait`, pidFile)

		start := time.Now()
		resp := Run(context.Background(), protocol.CommandRequest{
			Command:        cmd,
			TimeoutSeconds: 30,
		}, "sh")
		elapsed := time.Since(start)

		if elapsed >= 2*time.Second {
			t.Fatalf("stdout overflow took %v, want < 2s", elapsed)
		}
		if resp.ExitCode == 0 {
			t.Fatal("expected non-zero ExitCode on stdout overflow")
		}
		if resp.Stdout != "" {
			t.Fatalf("expected omitted Stdout on overflow, got %d bytes", len(resp.Stdout))
		}
		wantSub := "stream output exceeded maximum 10485760 bytes limit"
		if !strings.Contains(resp.Stderr, wantSub) {
			t.Fatalf("Stderr = %q, want substring %q", resp.Stderr, wantSub)
		}

		if raw, err := os.ReadFile(pidFile); err == nil {
			if pid, parseErr := strconv.Atoi(strings.TrimSpace(string(raw))); parseErr == nil && pid > 0 {
				if killErr := syscall.Kill(pid, 0); !errors.Is(killErr, syscall.ESRCH) {
					_ = syscall.Kill(pid, syscall.SIGKILL)
					t.Fatalf("background child PID %d survived stdout overflow: %v", pid, killErr)
				}
			}
		}
	})

	t.Run("stderr overflow > 10 MiB", func(t *testing.T) {
		cmd := `head -c 12582912 /dev/zero | tr '\0' 'E' >&2`

		start := time.Now()
		resp := Run(context.Background(), protocol.CommandRequest{
			Command:        cmd,
			TimeoutSeconds: 30,
		}, "sh")
		elapsed := time.Since(start)

		if elapsed >= 2*time.Second {
			t.Fatalf("stderr overflow took %v, want < 2s", elapsed)
		}
		if resp.ExitCode == 0 {
			t.Fatal("expected non-zero ExitCode on stderr overflow")
		}
		if resp.Stdout != "" {
			t.Fatalf("expected empty Stdout, got %d bytes", len(resp.Stdout))
		}
		wantSub := "stream output exceeded maximum 10485760 bytes limit"
		if !strings.Contains(resp.Stderr, wantSub) {
			t.Fatalf("Stderr = %q, want substring %q", resp.Stderr, wantSub)
		}
	})
}

func readPIDFileEventually(t *testing.T, pidFile string, maxWait time.Duration) int {
	t.Helper()
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(pidFile)
		if err == nil {
			trimmed := strings.TrimSpace(string(raw))
			if trimmed != "" {
				pid, parseErr := strconv.Atoi(trimmed)
				if parseErr == nil && pid > 0 {
					return pid
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for valid PID in %q", pidFile)
	return 0
}
