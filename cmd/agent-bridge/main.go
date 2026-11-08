package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/kennyparsons/agent-bridge/internal/client"
	"github.com/kennyparsons/agent-bridge/internal/config"
	"github.com/kennyparsons/agent-bridge/internal/upgrade"
)

var version = "dev"

const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

type stringSliceFlag []string

func (s *stringSliceFlag) String() string {
	if s == nil {
		return ""
	}
	return strings.Join(*s, ",")
}

func (s *stringSliceFlag) Set(val string) error {
	for _, item := range strings.Split(val, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			*s = append(*s, trimmed)
		}
	}
	return nil
}

func main() {
	os.Exit(normalizeProcessExitCode(run(os.Args[1:], os.Stdout, os.Stderr), runtime.GOOS))
}

// normalizeProcessExitCode ensures non-zero 32-bit remote exit codes (such as 256, -1, or
// 0xC0000000 whose low 8 bits are 0x00) never collapse to 0 under POSIX 8-bit os.Exit masking.
func normalizeProcessExitCode(code int, goos string) int {
	if goos == "windows" {
		return code
	}
	if code == 0 {
		return 0
	}
	if code >= 1 && code <= 255 {
		return code
	}
	if masked := code & 0xFF; masked != 0 {
		return masked
	}
	return exitError
}

func run(args []string, stdout, stderr io.Writer) int {
	return runContext(context.Background(), args, stdout, stderr)
}

func runContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runWithIO(ctx, args, os.Stdin, stdout, stderr)
}

func runWithIO(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if ctx == nil {
		ctx = context.Background()
	}
	if stdin == nil {
		stdin = os.Stdin
	}

	// Best-effort cleanup of leftover .old / .exe.old binaries from prior self-upgrades.
	upgrade.SweepOldExecutables("")

	if len(args) == 0 {
		printRootUsage(stderr)
		return exitUsage
	}

	switch args[0] {
	case "server":
		return runServer(ctx, args[1:], stdin, stdout, stderr)
	case "service":
		return runService(ctx, args[1:], stdin, stdout, stderr)
	case "doctor":
		return runDoctor(ctx, args[1:], stdout, stderr)
	case "ca":
		return runCA(ctx, args[1:], stdout, stderr)
	case "client":
		return runClient(ctx, args[1:], stdin, stdout, stderr)
	case "cluster":
		return runCluster(ctx, args[1:], stdin, stdout, stderr)
	case "exec":
		return runExec(ctx, args[1:], stdout, stderr)
	case "health":
		return runHealth(ctx, args[1:], stdout, stderr)
	case "host":
		return runHost(args[1:], stdout, stderr)
	case "selfupgrade", "upgrade":
		return runSelfUpgrade(ctx, args[1:], stdin, stdout, stderr)
	case "_detached-restart":
		return runServiceDetachedRestart(ctx, args[1:], stdout, stderr)
	case "version", "--version", "-version", "-v":
		return runVersion(args[1:], stdout, stderr)
	case "help", "--help", "-help", "-h":
		printRootUsage(stdout)
		return exitOK
	default:
		_, _ = fmt.Fprintf(stderr, "Error: unknown command %q\n\n", args[0])
		printRootUsage(stderr)
		return exitUsage
	}
}

type versionOutput struct {
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("version")
	jsonOut := fs.Bool("json", false, "Format version metadata as indented JSON")

	if code, handled := parseFlags(fs, args, stdout, stderr, printVersionUsage); handled {
		return code
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(stderr, "Error: unexpected positional arguments: %s\n", strings.Join(fs.Args(), " "))
		printVersionUsage(stderr)
		return exitUsage
	}

	if *jsonOut {
		return writeIndentedJSON(stdout, stderr, versionOutput{
			Version:   version,
			GoVersion: runtime.Version(),
			GOOS:      runtime.GOOS,
			GOARCH:    runtime.GOARCH,
		})
	}

	_, _ = fmt.Fprintf(stdout, "agent-bridge %s\n", version)
	return exitOK
}

func runExec(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := newFlagSet("exec")
	host := fs.String("host", "", "Named host profile from config.json")
	endpoint := fs.String("endpoint", "", "Target host:port override")
	certPath := fs.String("cert", "", "Client certificate PEM path")
	keyPath := fs.String("key", "", "Client private key PEM path")
	caPath := fs.String("ca", "", "Root CA certificate PEM path")
	cfgFile := fs.String("config", "", "Optional client config.json path override")
	timeout := fs.String("timeout", "", "Execution timeout (e.g. 60s, 2m; max 600s)")

	if code, handled := parseFlags(fs, args, stdout, stderr, printExecUsage); handled {
		return code
	}

	command := strings.TrimSpace(strings.Join(fs.Args(), " "))
	if command == "" {
		_, _ = fmt.Fprintln(stderr, "Error: missing <COMMAND> argument")
		printExecUsage(stderr)
		return exitUsage
	}

	var resolveOpts config.ResolveOptions
	if trimmedCfg := strings.TrimSpace(*cfgFile); trimmedCfg != "" {
		homeDir, _ := os.UserHomeDir()
		resolveOpts.GlobalConfigPath = config.ExpandPath(trimmedCfg, homeDir, "")
	}

	resolvedCfg, err := config.ResolveWithOptions(config.FlagOverrides{
		Host:     *host,
		Endpoint: *endpoint,
		CertPath: *certPath,
		KeyPath:  *keyPath,
		CAPath:   *caPath,
		Timeout:  *timeout,
	}, resolveOpts)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		return exitError
	}

	sigCtx, stopSignals := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stopSignals()

	exitCode, err := client.Run(sigCtx, resolvedCfg, command, stdout, stderr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: %v\n", err)
		if exitCode != 0 {
			return exitCode
		}
		return exitError
	}
	return exitCode
}

func readFirstLineTrimmed(r io.Reader) (string, error) {
	if r == nil {
		return "", errors.New("stdin reader is nil")
	}
	br := bufio.NewReader(io.LimitReader(r, 64*1024))
	line, err := br.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func resolveJoinTokenInput(flagToken string, fromStdin bool, stdin io.Reader) (string, error) {
	trimmed := strings.TrimSpace(flagToken)
	if trimmed != "" && fromStdin {
		return "", errors.New("--join-token and --join-token-stdin cannot be combined")
	}
	if fromStdin {
		tok, err := readFirstLineTrimmed(stdin)
		if err != nil {
			return "", fmt.Errorf("failed to read join token from stdin: %w", err)
		}
		if tok == "" {
			return "", errors.New("--join-token-stdin received empty input on stdin")
		}
		return tok, nil
	}
	return trimmed, nil
}

func fileExistsRegular(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func dirExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func sanitizeDirName(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "node-1"
	}
	var sb strings.Builder
	sb.Grow(len(trimmed))
	for i := 0; i < len(trimmed); i++ {
		c := trimmed[i]
		if (c >= 'a' && c <= 'z') ||
			(c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '_' || c == '.' {
			sb.WriteByte(c)
		} else {
			sb.WriteByte('_')
		}
	}
	out := strings.Trim(sb.String(), "._ ")
	if out == "" {
		return "node-1"
	}
	if len(out) > 96 {
		out = out[:96]
	}
	return out
}

func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func parseFlags(
	fs *flag.FlagSet,
	args []string,
	stdout, stderr io.Writer,
	usageFn func(io.Writer),
) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usageFn(stdout)
			return exitOK, true
		}
		_, _ = fmt.Fprintf(stderr, "Error: %v\n\n", err)
		usageFn(stderr)
		return exitUsage, true
	}
	return exitOK, false
}

func visitedFlags(fs *flag.FlagSet) map[string]bool {
	visited := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) {
		visited[f.Name] = true
	})
	return visited
}

func writeIndentedJSON(stdout, stderr io.Writer, v any) int {
	encoded, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "Error: failed to encode JSON output: %v\n", err)
		return exitError
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", encoded)
	return exitOK
}

func isInteractiveStdin(r io.Reader) bool {
	f, ok := r.(*os.File)
	if !ok || f == nil {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return (info.Mode() & os.ModeCharDevice) != 0
}

func printRootUsage(w io.Writer) {
	_, _ = fmt.Fprintf(w, `Usage: agent-bridge <command> [flags]

Commands:
  server        Run mTLS 1.3 WebSocket execution & cluster daemon
  service       Install and manage native OS service (SCM, systemd, launchd)
  doctor        Run pre-flight routing, hairpin, bind, SAN, CRL, and ACL diagnostics
  ca            Initialize Root CA, issue certs/bundles, and revoke certificates
  client        Provision client from .abbundle and verify mTLS host connectivity
  cluster       Join, rejoin/rotate certs, mint tokens, and inspect/sync cluster state
  exec          Execute synchronous command on remote host over TLS 1.3 WebSocket
  health        Verify mTLS 1.3 connectivity and CRL/ACL health against target host(s)
  host          Manage named remote host profiles in client config.json
  selfupgrade   Verify Ed25519 + SHA-256 release manifests and upgrade binary in place
  version       Print binary version (%s)

Run 'agent-bridge <command> --help' for subcommands and flags.
`, version)
}

func printVersionUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge version [--json]

Flags:
  --json    Print version and platform build metadata as indented JSON
`)
}

func printExecUsage(w io.Writer) {
	_, _ = fmt.Fprint(w, `Usage: agent-bridge exec [flags] "<COMMAND>"

Flags:
  --host <name>            Named host profile from config.json
  --endpoint <ip:port>     Target host:port override
  --config <path>          Client config.json path override
  --cert <path>            Client certificate PEM path
  --key <path>             Client private key PEM path
  --ca <path>              Root CA certificate PEM path
  --timeout <duration>     Execution timeout, e.g. 60s or 2m (default 60s, max 600s)
`)
}
