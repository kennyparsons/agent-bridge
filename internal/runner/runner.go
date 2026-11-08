package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"os"
	"os/exec"

	"github.com/kennyparsons/agent-bridge/internal/protocol"
)

const (
	// EnvInExec is set to "1" inside every subprocess spawned by Runner so child processes
	// (such as `agent-bridge upgrade` or `service restart`) can detect in-band execution.
	EnvInExec = "AGENT_BRIDGE_IN_EXEC"

	// Logical shell identifiers supported by --shell.
	ShellPowerShell = "powershell"
	ShellPWSH       = "pwsh"
	ShellCmd        = "cmd"
	ShellSh         = "sh"
	ShellBash       = "bash"

	// Standard synthetic exit codes for abnormal execution termination.
	ExitCodeInvalidRequest = 2
	ExitCodeTimeout        = 124
	ExitCodeExecError      = 127
	ExitCodeCanceled       = 130
	ExitCodeStreamOverflow = 137

	defaultWaitDelay          = 200 * time.Millisecond
	maxTimeoutStderrPreserved = 4096
)

var errStreamLimitExceeded = errors.New("stream output exceeded maximum bytes limit")

// ShellSpec describes the resolved executable and invocation arguments for a target shell.
type ShellSpec struct {
	Name       string
	Executable string
	ArgsPrefix []string
}

// CommandArgs returns the executable and full argument slice to execute command non-interactively.
func (s ShellSpec) CommandArgs(command string) (string, []string) {
	args := make([]string, 0, len(s.ArgsPrefix)+1)
	args = append(args, s.ArgsPrefix...)
	args = append(args, command)
	return s.Executable, args
}

// DefaultShell returns the default shell name for the current operating system
// ("powershell" on Windows, "sh" on Linux/macOS/Unix).
func DefaultShell() string {
	return defaultShellForOS(runtime.GOOS)
}

func defaultShellForOS(goos string) string {
	if goos == "windows" {
		return ShellPowerShell
	}
	return ShellSh
}

// ResolveShell resolves an optional --shell value ("powershell", "pwsh", "cmd", "sh", "bash",
// or an explicit executable path) into an executable and non-interactive argument prefix.
func ResolveShell(shell string) ShellSpec {
	return resolveShellForOS(runtime.GOOS, shell)
}

func resolveShellForOS(goos, shell string) ShellSpec {
	trimmed := strings.TrimSpace(shell)
	if trimmed == "" {
		trimmed = defaultShellForOS(goos)
	}

	lower := strings.ToLower(trimmed)
	switch lower {
	case "powershell", "powershell.exe":
		return ShellSpec{
			Name:       ShellPowerShell,
			Executable: "powershell.exe",
			ArgsPrefix: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"},
		}
	case "pwsh", "pwsh.exe":
		exe := "pwsh"
		if goos == "windows" || lower == "pwsh.exe" {
			exe = "pwsh.exe"
		}
		return ShellSpec{
			Name:       ShellPWSH,
			Executable: exe,
			ArgsPrefix: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"},
		}
	case "cmd", "cmd.exe":
		return ShellSpec{
			Name:       ShellCmd,
			Executable: "cmd.exe",
			ArgsPrefix: []string{"/c"},
		}
	case "sh":
		exe := "/bin/sh"
		if goos == "windows" {
			exe = "sh"
		}
		return ShellSpec{
			Name:       ShellSh,
			Executable: exe,
			ArgsPrefix: []string{"-c"},
		}
	case "bash":
		return ShellSpec{
			Name:       ShellBash,
			Executable: "bash",
			ArgsPrefix: []string{"-c"},
		}
	default:
		base := trimmed
		if idx := strings.LastIndexAny(base, `/\`); idx >= 0 {
			base = base[idx+1:]
		}
		baseLower := strings.TrimSuffix(strings.ToLower(base), ".exe")
		switch baseLower {
		case "powershell", "pwsh":
			return ShellSpec{
				Name:       baseLower,
				Executable: trimmed,
				ArgsPrefix: []string{"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command"},
			}
		case "cmd":
			return ShellSpec{
				Name:       ShellCmd,
				Executable: trimmed,
				ArgsPrefix: []string{"/c"},
			}
		default:
			if baseLower == "" {
				baseLower = trimmed
			}
			return ShellSpec{
				Name:       baseLower,
				Executable: trimmed,
				ArgsPrefix: []string{"-c"},
			}
		}
	}
}

// EffectiveShell resolves the effective shell name or executable path given a local shell setting,
// whether that local shell was explicitly configured via CLI/config, and an optional cluster policy.
func EffectiveShell(shell string, shellExplicit bool, policy *protocol.ExecutionPolicy) string {
	trimmedLocal := strings.TrimSpace(shell)
	if shellExplicit && trimmedLocal != "" {
		return trimmedLocal
	}
	if policy != nil {
		if trimmedPolicy := strings.TrimSpace(policy.DefaultShell); trimmedPolicy != "" {
			return trimmedPolicy
		}
	}
	if trimmedLocal != "" {
		return trimmedLocal
	}
	return DefaultShell()
}

// Runner executes non-interactive shell commands with timeout, stream cap, and process-tree isolation.
type Runner struct {
	Shell          string
	ShellExplicit  bool
	MaxStreamBytes int
}

// New creates a Runner configured with the specified shell (or DefaultShell() when empty)
// and protocol.MaxStreamBytes (10 MiB) per stream.
func New(shell string) *Runner {
	return &Runner{
		Shell:          shell,
		MaxStreamBytes: protocol.MaxStreamBytes,
	}
}

// Run executes req using the specified shell (or DefaultShell() if shell is empty),
// enforcing req.EffectiveTimeout(), protocol.MaxStreamBytes per stream, and full process-tree cleanup.
func Run(ctx context.Context, req protocol.CommandRequest, shell string) protocol.CommandResponse {
	return New(shell).Run(ctx, req)
}

// RunWithPolicy executes req applying optional cluster ExecutionPolicy defaults and ceilings.
// If shellExplicit is true and shell is non-empty, shell overrides policy.DefaultShell.
func RunWithPolicy(
	ctx context.Context,
	req protocol.CommandRequest,
	shell string,
	shellExplicit bool,
	policy *protocol.ExecutionPolicy,
) protocol.CommandResponse {
	return (&Runner{
		Shell:          shell,
		ShellExplicit:  shellExplicit,
		MaxStreamBytes: protocol.MaxStreamBytes,
	}).RunWithPolicy(ctx, req, policy)
}

// Run executes req on this Runner instance.
func (r *Runner) Run(ctx context.Context, req protocol.CommandRequest) protocol.CommandResponse {
	return r.RunWithPolicy(ctx, req, nil)
}

// RunWithPolicy executes req on this Runner instance governed by an optional cluster ExecutionPolicy.
func (r *Runner) RunWithPolicy(
	ctx context.Context,
	req protocol.CommandRequest,
	policy *protocol.ExecutionPolicy,
) protocol.CommandResponse {
	if ctx == nil {
		ctx = context.Background()
	}

	if strings.TrimSpace(req.Command) == "" {
		return protocol.CommandResponse{
			ExitCode: ExitCodeInvalidRequest,
			Stderr:   "command cannot be empty",
		}
	}

	if err := ctx.Err(); err != nil {
		return protocol.CommandResponse{
			ExitCode: ExitCodeCanceled,
			Stderr:   fmt.Sprintf("command execution canceled: %v", err),
		}
	}

	maxBytes := protocol.MaxStreamBytes
	var rawShell string
	var shellExplicit bool
	if r != nil {
		rawShell = r.Shell
		shellExplicit = r.ShellExplicit
		if r.MaxStreamBytes > 0 {
			maxBytes = r.MaxStreamBytes
		}
	}

	effectiveShell := EffectiveShell(rawShell, shellExplicit, policy)
	timeoutDur := req.EffectiveTimeoutWithPolicy(policy)
	timeoutCtx, cancelTimeout := context.WithTimeout(ctx, timeoutDur)
	defer cancelTimeout()

	execCtx, cancelExec := context.WithCancel(timeoutCtx)
	defer cancelExec()

	var overflowOnce sync.Once
	var overflowStream atomic.Value

	stdoutBuf := newBoundedBuffer(maxBytes, func() {
		overflowOnce.Do(func() {
			overflowStream.Store("stdout")
			cancelExec()
		})
	})
	stderrBuf := newBoundedBuffer(maxBytes, func() {
		overflowOnce.Do(func() {
			overflowStream.Store("stderr")
			cancelExec()
		})
	})

	spec := ResolveShell(effectiveShell)
	executable, args := spec.CommandArgs(req.Command)

	startErr, waitErr := runCommandIsolated(execCtx, executable, args, stdoutBuf, stderrBuf)
	if startErr != nil {
		if ctx.Err() != nil {
			return protocol.CommandResponse{
				ExitCode: ExitCodeCanceled,
				Stderr:   fmt.Sprintf("command execution canceled: %v", ctx.Err()),
			}
		}
		if errors.Is(timeoutCtx.Err(), context.DeadlineExceeded) {
			return protocol.CommandResponse{
				ExitCode: ExitCodeTimeout,
				Stderr:   fmt.Sprintf("command timed out after %s", timeoutDur),
			}
		}
		return protocol.CommandResponse{
			ExitCode: ExitCodeExecError,
			Stderr:   protocol.SanitizeOutput(fmt.Sprintf("failed to start shell %q: %v", executable, startErr)),
		}
	}

	// 1. Per-stream 10 MiB buffer cap overflow takes precedence over context errors caused by cancelExec().
	if stdoutBuf.Exceeded() || stderrBuf.Exceeded() {
		streamName := "stdout"
		if v, ok := overflowStream.Load().(string); ok && v != "" {
			streamName = v
		} else if stderrBuf.Exceeded() {
			streamName = "stderr"
		}
		return protocol.CommandResponse{
			ExitCode: ExitCodeStreamOverflow,
			Stderr:   fmt.Sprintf("%s: stream output exceeded maximum %d bytes limit", streamName, maxBytes),
		}
	}

	// 2. Parent context cancellation (e.g., client WebSocket disconnect or server shutdown).
	if err := ctx.Err(); err != nil {
		return protocol.CommandResponse{
			ExitCode: ExitCodeCanceled,
			Stderr:   fmt.Sprintf("command execution canceled: %v", err),
		}
	}

	// 3. Command execution timeout.
	if errors.Is(timeoutCtx.Err(), context.DeadlineExceeded) {
		diag := fmt.Sprintf("command timed out after %s", timeoutDur)
		capturedStderr := protocol.SanitizeOutput(stderrBuf.String())
		if capturedStderr != "" && len(capturedStderr) <= maxTimeoutStderrPreserved {
			diag = capturedStderr + "\n" + diag
		}
		var capturedStdout string
		if rawOut := protocol.SanitizeOutput(stdoutBuf.String()); len(rawOut) <= maxTimeoutStderrPreserved {
			capturedStdout = rawOut
		}
		return protocol.CommandResponse{
			ExitCode: ExitCodeTimeout,
			Stdout:   capturedStdout,
			Stderr:   diag,
		}
	}

	// 4. Clean zero exit.
	if waitErr == nil {
		return protocol.CommandResponse{
			ExitCode: 0,
			Stdout:   protocol.SanitizeOutput(stdoutBuf.String()),
			Stderr:   protocol.SanitizeOutput(stderrBuf.String()),
		}
	}

	// 5. Non-zero child exit code mirroring.
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return protocol.CommandResponse{
			ExitCode: normalizeExitCode(exitErr),
			Stdout:   protocol.SanitizeOutput(stdoutBuf.String()),
			Stderr:   protocol.SanitizeOutput(stderrBuf.String()),
		}
	}

	stderrOut := protocol.SanitizeOutput(stderrBuf.String())
	if stderrOut == "" {
		stderrOut = protocol.SanitizeOutput(waitErr.Error())
	}
	return protocol.CommandResponse{
		ExitCode: 1,
		Stdout:   protocol.SanitizeOutput(stdoutBuf.String()),
		Stderr:   stderrOut,
	}
}

type boundedBuffer struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	maxBytes int
	exceeded atomic.Bool
	onExceed func()
}

func newBoundedBuffer(maxBytes int, onExceed func()) *boundedBuffer {
	return &boundedBuffer{
		maxBytes: maxBytes,
		onExceed: onExceed,
	}
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	b.mu.Lock()
	if b.exceeded.Load() {
		b.mu.Unlock()
		return 0, errStreamLimitExceeded
	}

	remaining := b.maxBytes - b.buf.Len()
	if len(p) <= remaining {
		n, err := b.buf.Write(p)
		b.mu.Unlock()
		return n, err
	}

	if remaining > 0 {
		_, _ = b.buf.Write(p[:remaining])
	}
	b.exceeded.Store(true)
	trigger := b.onExceed
	b.mu.Unlock()

	if trigger != nil {
		trigger()
	}
	return remaining, errStreamLimitExceeded
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *boundedBuffer) Exceeded() bool {
	return b.exceeded.Load()
}

func commandEnv() []string {
	return buildCommandEnv(os.Environ())
}

func buildCommandEnv(base []string) []string {
	env := make([]string, 0, len(base)+1)
	for _, kv := range base {
		if eq := strings.IndexByte(kv, '='); eq > 0 {
			if strings.EqualFold(kv[:eq], EnvInExec) {
				continue
			}
		}
		env = append(env, kv)
	}
	env = append(env, EnvInExec+"=1")
	return env
}
