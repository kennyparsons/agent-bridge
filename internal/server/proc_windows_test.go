//go:build windows

package server

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

const stillActiveExitCode = 259

func echoTrimTestCommand() string {
	return `Write-Output "   hello compact json   "`
}

func stderrExit7Command() string {
	return `[Console]::Error.WriteLine("  domain lookup failed  "); exit 7`
}

func sleepFiveSecondsCommand() string {
	return "Start-Sleep -Seconds 5"
}

func grandchildSleepCommand(pidFile string) string {
	return fmt.Sprintf(`$p = Start-Process -FilePath powershell.exe -ArgumentList '-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30' -PassThru; Set-Content -Path '%s' -Value $p.Id -NoNewline; Wait-Process -Id $p.Id`, pidFile)
}

func waitProcessDead(t *testing.T, pid int, maxWait time.Duration) time.Duration {
	t.Helper()
	start := time.Now()
	deadline := start.Add(maxWait)
	for {
		h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
		if err != nil {
			return time.Since(start)
		}
		var code uint32
		codeErr := windows.GetExitCodeProcess(h, &code)
		_ = windows.CloseHandle(h)
		if codeErr != nil || code != stillActiveExitCode {
			return time.Since(start)
		}
		if time.Now().After(deadline) {
			if termH, openErr := windows.OpenProcess(windows.PROCESS_TERMINATE, false, uint32(pid)); openErr == nil {
				_ = windows.TerminateProcess(termH, 1)
				_ = windows.CloseHandle(termH)
			}
			t.Fatalf("grandchild PID %d still active after %v", pid, maxWait)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
