package runner

import (
	"context"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/protocol"
)

func TestDefaultAndResolveShellCrossPlatform(t *testing.T) {
	if got := defaultShellForOS("windows"); got != ShellPowerShell {
		t.Fatalf("defaultShellForOS(windows) = %q, want %q", got, ShellPowerShell)
	}
	if got := defaultShellForOS("linux"); got != ShellSh {
		t.Fatalf("defaultShellForOS(linux) = %q, want %q", got, ShellSh)
	}
	if got := defaultShellForOS("darwin"); got != ShellSh {
		t.Fatalf("defaultShellForOS(darwin) = %q, want %q", got, ShellSh)
	}

	tests := []struct {
		name     string
		goos     string
		shell    string
		wantExe  string
		wantArgs []string
	}{
		{
			name:     "windows default powershell",
			goos:     "windows",
			shell:    "",
			wantExe:  "powershell.exe",
			wantArgs: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Get-Date"},
		},
		{
			name:     "linux default sh",
			goos:     "linux",
			shell:    "",
			wantExe:  "/bin/sh",
			wantArgs: []string{"-c", "Get-Date"},
		},
		{
			name:     "explicit pwsh on windows",
			goos:     "windows",
			shell:    "pwsh",
			wantExe:  "pwsh.exe",
			wantArgs: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Get-Date"},
		},
		{
			name:     "explicit pwsh on linux",
			goos:     "linux",
			shell:    "pwsh",
			wantExe:  "pwsh",
			wantArgs: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Get-Date"},
		},
		{
			name:     "explicit cmd",
			goos:     "windows",
			shell:    "cmd",
			wantExe:  "cmd.exe",
			wantArgs: []string{"/c", "Get-Date"},
		},
		{
			name:     "explicit bash",
			goos:     "linux",
			shell:    "bash",
			wantExe:  "bash",
			wantArgs: []string{"-c", "Get-Date"},
		},
		{
			name:     "explicit windows powershell full path",
			goos:     "windows",
			shell:    `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			wantExe:  `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			wantArgs: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", "Get-Date"},
		},
		{
			name:     "explicit unix shell path",
			goos:     "darwin",
			shell:    "/bin/zsh",
			wantExe:  "/bin/zsh",
			wantArgs: []string{"-c", "Get-Date"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			spec := resolveShellForOS(tc.goos, tc.shell)
			gotExe, gotArgs := spec.CommandArgs("Get-Date")
			if gotExe != tc.wantExe {
				t.Fatalf("Executable = %q, want %q", gotExe, tc.wantExe)
			}
			if !reflect.DeepEqual(gotArgs, tc.wantArgs) {
				t.Fatalf("Args = %#v, want %#v", gotArgs, tc.wantArgs)
			}
		})
	}
}

func TestRunValidationAndPreCanceledContext(t *testing.T) {
	emptyResp := Run(context.Background(), protocol.CommandRequest{Command: "   \n\t  "}, "")
	if emptyResp.ExitCode != ExitCodeInvalidRequest {
		t.Fatalf("empty command ExitCode = %d, want %d", emptyResp.ExitCode, ExitCodeInvalidRequest)
	}
	if emptyResp.Stderr == "" {
		t.Fatal("expected non-empty Stderr on empty command")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceledResp := Run(ctx, protocol.CommandRequest{Command: "echo hi"}, "")
	if canceledResp.ExitCode != ExitCodeCanceled {
		t.Fatalf("pre-canceled ExitCode = %d, want %d", canceledResp.ExitCode, ExitCodeCanceled)
	}
	if !strings.Contains(canceledResp.Stderr, "canceled") {
		t.Fatalf("unexpected Stderr on pre-canceled context: %q", canceledResp.Stderr)
	}

	missingShellResp := Run(context.Background(), protocol.CommandRequest{Command: "echo hi"}, "/nonexistent/agent-bridge-missing-shell")
	if missingShellResp.ExitCode != ExitCodeExecError {
		t.Fatalf("missing shell ExitCode = %d, want %d", missingShellResp.ExitCode, ExitCodeExecError)
	}
	if !strings.Contains(missingShellResp.Stderr, "failed to start shell") {
		t.Fatalf("unexpected Stderr for missing shell: %q", missingShellResp.Stderr)
	}
}

func TestBoundedBufferExactBoundary(t *testing.T) {
	triggered := 0
	buf := newBoundedBuffer(protocol.MaxStreamBytes, func() {
		triggered++
	})

	chunk := bytesRepeat('x', 1024*1024) // 1 MiB
	for i := 0; i < 10; i++ {
		n, err := buf.Write(chunk)
		if err != nil || n != len(chunk) {
			t.Fatalf("write %d failed: n=%d err=%v", i, n, err)
		}
	}
	if buf.Exceeded() || triggered != 0 {
		t.Fatalf("buffer marked exceeded at exact 10 MiB boundary (exceeded=%v triggered=%d)", buf.Exceeded(), triggered)
	}

	_, err := buf.Write([]byte("a"))
	if err == nil {
		t.Fatal("expected overflow error writing 1 byte past MaxStreamBytes")
	}
	if !buf.Exceeded() || triggered != 1 {
		t.Fatalf("expected exceeded=true and triggered=1, got exceeded=%v triggered=%d", buf.Exceeded(), triggered)
	}
}

func TestRunWithPolicyShellPrecedenceAndTimeoutBounds(t *testing.T) {
	t.Run("EffectiveShell precedence matrix", func(t *testing.T) {
		polWithBash := &protocol.ExecutionPolicy{DefaultShell: "bash"}
		polEmpty := &protocol.ExecutionPolicy{}

		if got := EffectiveShell("", false, nil); got != DefaultShell() {
			t.Fatalf("nil policy empty shell = %q, want %q", got, DefaultShell())
		}
		if got := EffectiveShell("sh", false, polWithBash); got != "bash" {
			t.Fatalf("non-explicit local shell should yield to policy.DefaultShell: got %q, want %q", got, "bash")
		}
		if got := EffectiveShell("sh", true, polWithBash); got != "sh" {
			t.Fatalf("explicit local shell must override policy.DefaultShell: got %q, want %q", got, "sh")
		}
		if got := EffectiveShell("   ", true, polWithBash); got != "bash" {
			t.Fatalf("empty explicit local shell should fall back to policy.DefaultShell: got %q, want %q", got, "bash")
		}
		if got := EffectiveShell("", false, polEmpty); got != DefaultShell() {
			t.Fatalf("empty policy DefaultShell should fall back to DefaultShell(): got %q, want %q", got, DefaultShell())
		}
	})

	t.Run("policy DefaultShell override vs shellExplicit=true", func(t *testing.T) {
		pol := &protocol.ExecutionPolicy{
			Version:      1,
			DefaultShell: "/nonexistent/cluster-policy-shell",
		}

		// When shellExplicit is false, policy.DefaultShell takes effect.
		overriddenResp := RunWithPolicy(
			context.Background(),
			protocol.CommandRequest{Command: "echo policy-check"},
			DefaultShell(),
			false,
			pol,
		)
		if overriddenResp.ExitCode != ExitCodeExecError || !strings.Contains(overriddenResp.Stderr, "/nonexistent/cluster-policy-shell") {
			t.Fatalf("expected policy.DefaultShell to be invoked when shellExplicit=false, got %+v", overriddenResp)
		}

		// When shellExplicit is true, local shell takes precedence over policy.DefaultShell.
		explicitResp := RunWithPolicy(
			context.Background(),
			protocol.CommandRequest{Command: "echo explicit-wins"},
			DefaultShell(),
			true,
			pol,
		)
		if explicitResp.ExitCode != 0 || explicitResp.Stdout != "explicit-wins" {
			t.Fatalf("expected explicit local shell to succeed and override policy.DefaultShell, got %+v", explicitResp)
		}
	})

	t.Run("policy DefaultTimeoutSeconds and MaxTimeoutSeconds clamping", func(t *testing.T) {
		sleepCmd := "sleep 5"
		if runtime.GOOS == "windows" {
			sleepCmd = "Start-Sleep -Seconds 5"
		}

		// 1. Omitted TimeoutSeconds (0) adopts policy.DefaultTimeoutSeconds (1s instead of 60s).
		defaultTimeoutPol := &protocol.ExecutionPolicy{
			Version:               2,
			DefaultTimeoutSeconds: 1,
			MaxTimeoutSeconds:     10,
		}
		start := time.Now()
		respDefault := RunWithPolicy(
			context.Background(),
			protocol.CommandRequest{Command: sleepCmd, TimeoutSeconds: 0},
			"",
			false,
			defaultTimeoutPol,
		)
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("policy DefaultTimeoutSeconds=1 took %v, expected ~1s", elapsed)
		}
		if respDefault.ExitCode != ExitCodeTimeout || !strings.Contains(respDefault.Stderr, "command timed out after 1s") {
			t.Fatalf("expected 1s timeout from policy DefaultTimeoutSeconds, got %+v", respDefault)
		}

		// 2. Requested TimeoutSeconds=30 is clamped down to policy.MaxTimeoutSeconds=1.
		maxClampPol := &protocol.ExecutionPolicy{
			Version:               3,
			DefaultTimeoutSeconds: 5,
			MaxTimeoutSeconds:     1,
		}
		start = time.Now()
		respClamped := RunWithPolicy(
			context.Background(),
			protocol.CommandRequest{Command: sleepCmd, TimeoutSeconds: 30},
			"",
			false,
			maxClampPol,
		)
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Fatalf("policy MaxTimeoutSeconds=1 clamp took %v, expected ~1s", elapsed)
		}
		if respClamped.ExitCode != ExitCodeTimeout || !strings.Contains(respClamped.Stderr, "command timed out after 1s") {
			t.Fatalf("expected 1s timeout from policy MaxTimeoutSeconds clamping, got %+v", respClamped)
		}
	})
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
