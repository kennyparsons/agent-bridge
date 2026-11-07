package main

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/pki"
)

func TestCLIVersionAndHelp(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-v"} {
		var out, errBuf bytes.Buffer
		code := run([]string{arg}, &out, &errBuf)
		if code != exitOK {
			t.Fatalf("run(%q) exit code = %d, want %d (stderr=%q)", arg, code, exitOK, errBuf.String())
		}
		if !strings.Contains(out.String(), "agent-bridge "+version) {
			t.Fatalf("run(%q) stdout = %q, want version %q", arg, out.String(), version)
		}
		if errBuf.Len() != 0 {
			t.Fatalf("run(%q) unexpected stderr = %q", arg, errBuf.String())
		}
	}

	helpCases := [][]string{
		{"--help"},
		{"help"},
		{"ca", "--help"},
		{"ca", "init", "--help"},
		{"ca", "issue", "--help"},
		{"ca", "revoke", "--help"},
		{"cluster", "--help"},
		{"cluster", "token-create", "--help"},
		{"cluster", "status", "--help"},
		{"cluster", "peers", "--help"},
		{"cluster", "sync", "--help"},
		{"server", "--help"},
		{"exec", "--help"},
	}
	for _, args := range helpCases {
		var out, errBuf bytes.Buffer
		code := run(args, &out, &errBuf)
		if code != exitOK {
			t.Fatalf("run(%v) exit code = %d, want 0 (stderr=%q)", args, code, errBuf.String())
		}
		if !strings.Contains(out.String(), "Usage: agent-bridge") {
			t.Fatalf("run(%v) stdout missing Usage header: %q", args, out.String())
		}
		if errBuf.Len() != 0 {
			t.Fatalf("run(%v) unexpected stderr: %q", args, errBuf.String())
		}
	}

	invalidCases := [][]string{
		{},
		{"unknown-cmd"},
		{"ca"},
		{"ca", "unknown"},
		{"ca", "init"},
		{"ca", "issue", "--ca-dir", "/tmp/x"},
		{"ca", "revoke", "--ca-dir", "/tmp/x"},
		{"cluster"},
		{"cluster", "unknown"},
		{"cluster", "token-create", "--quiet", "--json"},
		{"cluster", "token-create", "--ttl", "0s"},
		{"cluster", "status", "unexpected-arg"},
		{"cluster", "peers", "unexpected-arg"},
		{"cluster", "sync", "--enforce-client-acl", "--disable-client-acl"},
		{"server", "--bind", "127.0.0.1"},
		{"server", "--bind", "127.0.0.1", "--join", "127.0.0.1:8444"},
		{"server", "--bind", "127.0.0.1", "--join-token", "abjt1.x.y.z"},
		{"exec"},
		{"exec", "--unknown-flag", "whoami"},
	}
	for _, args := range invalidCases {
		var out, errBuf bytes.Buffer
		code := run(args, &out, &errBuf)
		if code != exitUsage {
			t.Fatalf("run(%v) exit code = %d, want %d", args, code, exitUsage)
		}
		if out.Len() != 0 {
			t.Fatalf("run(%v) wrote to stdout on usage error: %q", args, out.String())
		}
		if errBuf.Len() == 0 {
			t.Fatalf("run(%v) wrote nothing to stderr on usage error", args)
		}
	}
}

func TestCLIPKIServerFailFastAndEndToEndExec(t *testing.T) {
	tmp := t.TempDir()
	caDir := filepath.Join(tmp, "pki")
	srvDir := filepath.Join(tmp, "certs", "server")
	cliDir := filepath.Join(tmp, "certs", "client")

	// 1. agent-bridge ca init
	var out, errBuf bytes.Buffer
	code := run([]string{
		"ca", "init",
		"--out-dir", caDir,
		"--common-name", "Test-Root-CA",
		"--org", "Test Org",
		"--years", "5",
	}, &out, &errBuf)
	if code != exitOK {
		t.Fatalf("ca init failed (code=%d): stderr=%s", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "CA Certificate:") || !strings.Contains(out.String(), "Serial:") {
		t.Fatalf("unexpected ca init output: %s", out.String())
	}

	// 2. agent-bridge ca issue --type server (repeatable --ip & --dns + comma-separated)
	out.Reset()
	errBuf.Reset()
	code = run([]string{
		"ca", "issue",
		"--ca-dir", caDir,
		"--type", "server",
		"--name", "win-dc-01",
		"--ip", "127.0.0.1",
		"--ip", "100.64.0.10,::1",
		"--dns", "localhost",
		"--dns", "win-dc-01,win-dc-01.tailnet-example.ts.net",
		"--out-dir", srvDir,
	}, &out, &errBuf)
	if code != exitOK {
		t.Fatalf("ca issue (server) failed (code=%d): stderr=%s", code, errBuf.String())
	}
	srvCert, err := pki.LoadCertificate(filepath.Join(srvDir, pki.ServerCertFilename))
	if err != nil {
		t.Fatalf("LoadCertificate(server) failed: %v", err)
	}
	if len(srvCert.IPAddresses) != 3 {
		t.Fatalf("server IPAddresses count = %d, want 3 (%v)", len(srvCert.IPAddresses), srvCert.IPAddresses)
	}
	if len(srvCert.DNSNames) != 3 {
		t.Fatalf("server DNSNames count = %d, want 3 (%v)", len(srvCert.DNSNames), srvCert.DNSNames)
	}

	// 3. agent-bridge ca issue --type client
	out.Reset()
	errBuf.Reset()
	code = run([]string{
		"ca", "issue",
		"--ca-dir", caDir,
		"--type", "client",
		"--name", "ops-agent",
		"--out-dir", cliDir,
	}, &out, &errBuf)
	if code != exitOK {
		t.Fatalf("ca issue (client) failed (code=%d): stderr=%s", code, errBuf.String())
	}
	clientSerial := extractField(t, out.String(), "Serial:")

	// 4. agent-bridge server fail-fast on missing CRL and rogue-CA CRL.
	out.Reset()
	errBuf.Reset()
	code = run([]string{
		"server",
		"--bind", "127.0.0.1",
		"--port", "8443",
		"--cert", filepath.Join(srvDir, pki.ServerCertFilename),
		"--key", filepath.Join(srvDir, pki.ServerKeyFilename),
		"--ca", filepath.Join(caDir, pki.CACertFilename),
		"--crl", filepath.Join(tmp, "missing-crl.pem"),
	}, &out, &errBuf)
	if code == exitOK {
		t.Fatal("expected server to fail fast when --crl file does not exist")
	}
	if out.Len() != 0 {
		t.Fatalf("expected empty stdout on server startup failure, got %q", out.String())
	}

	rogueCADir := filepath.Join(tmp, "rogue-pki")
	var rogueOut, rogueErr bytes.Buffer
	if rc := run([]string{"ca", "init", "--out-dir", rogueCADir}, &rogueOut, &rogueErr); rc != exitOK {
		t.Fatalf("rogue ca init failed: %s", rogueErr.String())
	}
	errBuf.Reset()
	code = run([]string{
		"server",
		"--bind", "127.0.0.1",
		"--port", "8443",
		"--cert", filepath.Join(srvDir, pki.ServerCertFilename),
		"--key", filepath.Join(srvDir, pki.ServerKeyFilename),
		"--ca", filepath.Join(caDir, pki.CACertFilename),
		"--crl", filepath.Join(rogueCADir, pki.CRLFilename),
	}, &out, &errBuf)
	if code == exitOK || !strings.Contains(errBuf.String(), "CRL") {
		t.Fatalf("expected server to reject rogue CRL at startup, code=%d stderr=%q", code, errBuf.String())
	}

	// Unassignable bind IP (TEST-NET-2 198.51.100.42) must fail fast without logging "listening on".
	out.Reset()
	errBuf.Reset()
	code = run([]string{
		"server",
		"--bind", "198.51.100.42",
		"--port", "18443",
		"--cert", filepath.Join(srvDir, pki.ServerCertFilename),
		"--key", filepath.Join(srvDir, pki.ServerKeyFilename),
		"--ca", filepath.Join(caDir, pki.CACertFilename),
		"--crl", filepath.Join(caDir, pki.CRLFilename),
	}, &out, &errBuf)
	if code == exitOK {
		t.Fatal("expected server to fail when binding unassignable IP 198.51.100.42")
	}
	if strings.Contains(errBuf.String(), "listening on") {
		t.Fatalf("server logged 'listening on' despite bind failure: %q", errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "failed to bind TCP listener") {
		t.Fatalf("expected bind failure error on stderr, got %q", errBuf.String())
	}

	// 5. Start live server via runContext and exercise exec + live ca revoke.
	port := freeLoopbackPort(t)
	endpoint := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))

	srvCtx, cancelSrv := context.WithCancel(context.Background())
	defer cancelSrv()

	srvDone := make(chan int, 1)
	var srvStdout, srvStderr syncBuffer
	go func() {
		srvDone <- runContext(srvCtx, []string{
			"server",
			"--bind", "127.0.0.1",
			"--port", strconv.Itoa(port),
			"--cert", filepath.Join(srvDir, pki.ServerCertFilename),
			"--key", filepath.Join(srvDir, pki.ServerKeyFilename),
			"--ca", filepath.Join(caDir, pki.CACertFilename),
			"--crl", filepath.Join(caDir, pki.CRLFilename),
		}, &srvStdout, &srvStderr)
	}()

	waitForTCPPort(t, endpoint, 3*time.Second)

	okCmd := "printf 'hello-cli'"
	failCmd := "printf 'bad-input' >&2; exit 42"
	if runtime.GOOS == "windows" {
		okCmd = "Write-Output 'hello-cli'"
		failCmd = "[Console]::Error.WriteLine('bad-input'); exit 42"
	}

	// Zero-exit remote execution.
	out.Reset()
	errBuf.Reset()
	code = run([]string{
		"exec",
		"--endpoint", endpoint,
		"--cert", filepath.Join(cliDir, pki.ClientCertFilename),
		"--key", filepath.Join(cliDir, pki.ClientKeyFilename),
		"--ca", filepath.Join(caDir, pki.CACertFilename),
		"--timeout", "15s",
		okCmd,
	}, &out, &errBuf)
	if code != 0 {
		t.Fatalf("exec okCmd exit code = %d, want 0 (stderr=%q)", code, errBuf.String())
	}
	if out.String() != "hello-cli\n" {
		t.Fatalf("exec okCmd stdout = %q, want %q", out.String(), "hello-cli\n")
	}
	if errBuf.Len() != 0 {
		t.Fatalf("exec okCmd stderr = %q, want empty", errBuf.String())
	}

	// Non-zero exit code mirroring (42) and isolated stderr.
	out.Reset()
	errBuf.Reset()
	code = run([]string{
		"exec",
		"--endpoint", endpoint,
		"--cert", filepath.Join(cliDir, pki.ClientCertFilename),
		"--key", filepath.Join(cliDir, pki.ClientKeyFilename),
		"--ca", filepath.Join(caDir, pki.CACertFilename),
		failCmd,
	}, &out, &errBuf)
	if code != 42 {
		t.Fatalf("exec failCmd exit code = %d, want 42 (stderr=%q)", code, errBuf.String())
	}
	if out.Len() != 0 {
		t.Fatalf("exec failCmd stdout = %q, want empty", out.String())
	}
	if errBuf.String() != "bad-input\n" {
		t.Fatalf("exec failCmd stderr = %q, want %q", errBuf.String(), "bad-input\n")
	}

	// Local config/flag error must keep stdout pure.
	out.Reset()
	errBuf.Reset()
	code = run([]string{
		"exec",
		"--endpoint", endpoint,
		"--cert", filepath.Join(tmp, "missing-client.crt"),
		"--key", filepath.Join(cliDir, pki.ClientKeyFilename),
		"--ca", filepath.Join(caDir, pki.CACertFilename),
		okCmd,
	}, &out, &errBuf)
	if code == 0 {
		t.Fatal("expected exec to fail when client cert does not exist")
	}
	if out.Len() != 0 {
		t.Fatalf("expected empty stdout on client TLS load failure, got %q", out.String())
	}

	// 6. Revoke client certificate via CLI while server is running and assert live rejection + pure stdout.
	var revOut, revErr bytes.Buffer
	if rc := run([]string{
		"ca", "revoke",
		"--ca-dir", caDir,
		"--serial", clientSerial,
	}, &revOut, &revErr); rc != exitOK {
		t.Fatalf("ca revoke failed (code=%d): %s", rc, revErr.String())
	}
	if !strings.Contains(revOut.String(), "CRL Number:     2") || !strings.Contains(revOut.String(), clientSerial) {
		t.Fatalf("unexpected ca revoke output: %s", revOut.String())
	}

	deadline := time.Now().Add(950 * time.Millisecond)
	revokedRejected := false
	for time.Now().Before(deadline) {
		out.Reset()
		errBuf.Reset()
		rc := run([]string{
			"exec",
			"--endpoint", endpoint,
			"--cert", filepath.Join(cliDir, pki.ClientCertFilename),
			"--key", filepath.Join(cliDir, pki.ClientKeyFilename),
			"--ca", filepath.Join(caDir, pki.CACertFilename),
			okCmd,
		}, &out, &errBuf)
		if out.Len() != 0 {
			if rc != 0 {
				t.Fatalf("exec wrote to stdout (%q) despite error exit code %d", out.String(), rc)
			}
			time.Sleep(25 * time.Millisecond)
			continue
		}
		if rc != 0 && strings.Contains(errBuf.String(), "mTLS handshake rejected") {
			revokedRejected = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !revokedRejected {
		t.Fatalf("expected exec to be rejected by live CRL hot-reload within < 1s; last stderr=%q", errBuf.String())
	}

	// 7. Graceful shutdown via context cancellation.
	cancelSrv()
	select {
	case srvExit := <-srvDone:
		if srvExit != exitOK {
			t.Fatalf("server exited with code %d on graceful shutdown; stderr=%s", srvExit, srvStderr.String())
		}
		if !strings.Contains(srvStderr.String(), "listening on "+endpoint) {
			t.Fatalf("expected server stderr to log 'listening on %s' after successful bind, got %q", endpoint, srvStderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down within 5s after context cancellation")
	}
}

func TestNormalizeProcessExitCode(t *testing.T) {
	posixCases := []struct {
		in   int
		want int
	}{
		{in: 0, want: 0},
		{in: 1, want: 1},
		{in: 42, want: 42},
		{in: 255, want: 255},
		{in: 256, want: 1},
		{in: 512, want: 1},
		{in: -1, want: 255},
		{in: -256, want: 1},
		{in: int(int32(-1073741824)), want: 1}, // 0xC0000000 (low byte 0x00)
		{in: 0xC0000000, want: 1},
		{in: 0xC0000005, want: 5},
	}

	for _, goos := range []string{"linux", "darwin"} {
		for _, tc := range posixCases {
			got := normalizeProcessExitCode(tc.in, goos)
			if got != tc.want {
				t.Errorf("normalizeProcessExitCode(%d, %q) = %d, want %d", tc.in, goos, got, tc.want)
			}
			if tc.in != 0 && (got < 1 || got > 255) {
				t.Errorf("normalizeProcessExitCode(%d, %q) = %d, expected non-zero in [1..255]", tc.in, goos, got)
			}
		}
	}

	for _, code := range []int{0, 1, 42, 256, -1, 0xC0000000, 0xC0000005} {
		if got := normalizeProcessExitCode(code, "windows"); got != code {
			t.Errorf("normalizeProcessExitCode(%d, \"windows\") = %d, want %d", code, got, code)
		}
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func extractField(t *testing.T, output, prefix string) string {
	t.Helper()
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			val := strings.TrimSpace(strings.TrimPrefix(line, prefix))
			if val != "" {
				return val
			}
		}
	}
	t.Fatalf("field %q not found in output:\n%s", prefix, output)
	return ""
}

func freeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen(127.0.0.1:0) failed: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func waitForTCPPort(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for TCP listener at %s", addr)
}
