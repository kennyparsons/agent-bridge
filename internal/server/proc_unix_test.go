//go:build !windows

package server

import (
	"errors"
	"fmt"
	"syscall"
	"testing"
	"time"
)

func echoTrimTestCommand() string {
	return "printf '  \\n\\t  hello compact json  \\r\\n  '"
}

func stderrExit7Command() string {
	return "printf '  domain lookup failed  \\n' >&2; exit 7"
}

func sleepFiveSecondsCommand() string {
	return "sleep 5"
}

func grandchildSleepCommand(pidFile string) string {
	return fmt.Sprintf(`sh -c 'echo $$ > %q; exec sleep 30' & wait`, pidFile)
}

func waitProcessDead(t *testing.T, pid int, maxWait time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	deadline := start.Add(maxWait)
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return time.Since(start)
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("grandchild PID %d still alive after %v (Kill err=%v)", pid, maxWait, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
