package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kennyparsons/agent-bridge/cluster"
	"github.com/kennyparsons/agent-bridge/internal/pki"
)

func TestCLIClusterTwoNodeCSRJoinRevokePolicyAndGracefulDegradation(t *testing.T) {
	tmp := t.TempDir()
	caDir := filepath.Join(tmp, "pki")
	node1CertDir := filepath.Join(tmp, "certs", "node-1")
	node2DataDir := filepath.Join(tmp, "node2-data")
	revokedCliDir := filepath.Join(tmp, "certs", "agent-revokeme")
	allowedCliDir := filepath.Join(tmp, "certs", "agent-allowed")
	unlistedCliDir := filepath.Join(tmp, "certs", "agent-unlisted")

	// 1. Initialize Root CA and issue Node 1 + 3 client certificates via CLI.
	mustRunCLI(t, []string{"ca", "init", "--out-dir", caDir})

	mustRunCLI(t, []string{
		"ca", "issue",
		"--ca-dir", caDir,
		"--type", "server",
		"--name", "node-1",
		"--ip", "127.0.0.1",
		"--dns", "localhost",
		"--out-dir", node1CertDir,
	})

	revokedOut := mustRunCLI(t, []string{
		"ca", "issue",
		"--ca-dir", caDir,
		"--type", "client",
		"--name", "agent-revokeme",
		"--out-dir", revokedCliDir,
	})
	revokedSerial := extractField(t, revokedOut, "Serial:")

	mustRunCLI(t, []string{
		"ca", "issue",
		"--ca-dir", caDir,
		"--type", "client",
		"--name", "agent-allowed",
		"--out-dir", allowedCliDir,
	})

	mustRunCLI(t, []string{
		"ca", "issue",
		"--ca-dir", caDir,
		"--type", "client",
		"--name", "agent-unlisted",
		"--out-dir", unlistedCliDir,
	})

	caCertPath := filepath.Join(caDir, pki.CACertFilename)
	crlPath := filepath.Join(caDir, pki.CRLFilename)
	adminCertPath := filepath.Join(allowedCliDir, pki.ClientCertFilename)
	adminKeyPath := filepath.Join(allowedCliDir, pki.ClientKeyFilename)

	// 2. Start Node 1 with --cluster-bind (omitting --ca-key to verify automatic ca.key discovery beside --ca).
	execPort1 := freeLoopbackPort(t)
	clusterPort1 := freeLoopbackPort(t)
	execAddr1 := net.JoinHostPort("127.0.0.1", strconv.Itoa(execPort1))
	clusterAddr1 := net.JoinHostPort("127.0.0.1", strconv.Itoa(clusterPort1))

	node1Ctx, cancelNode1 := context.WithCancel(context.Background())
	defer cancelNode1()

	node1Done := make(chan int, 1)
	var node1Stdout, node1Stderr syncBuffer
	go func() {
		node1Done <- runContext(node1Ctx, []string{
			"server",
			"--bind", "127.0.0.1",
			"--port", strconv.Itoa(execPort1),
			"--cluster-bind", clusterAddr1,
			"--node-id", "node-1",
			"--cert", filepath.Join(node1CertDir, pki.ServerCertFilename),
			"--key", filepath.Join(node1CertDir, pki.ServerKeyFilename),
			"--ca", caCertPath,
			"--crl", crlPath,
		}, &node1Stdout, &node1Stderr)
	}()

	waitForTCPPort(t, clusterAddr1, 5*time.Second)
	waitForTCPPort(t, execAddr1, 5*time.Second)

	// Mint single-use join token via `cluster token-create --ttl 1h -q`.
	rawTokenOut := mustRunCLI(t, []string{
		"cluster", "token-create",
		"--cluster-addr", clusterAddr1,
		"--cert", adminCertPath,
		"--key", adminKeyPath,
		"--ca", caCertPath,
		"--ttl", "1h",
		"-q",
	})
	joinToken := strings.TrimSpace(rawTokenOut)
	if !strings.HasPrefix(joinToken, cluster.JoinTokenVersionPrefix+".") || strings.Contains(joinToken, "\n") {
		t.Fatalf("expected bare join token from -q flag, got %q", rawTokenOut)
	}

	// Verify `cluster token-create --json` also emits structured metadata cleanly.
	jsonTokenOut := mustRunCLI(t, []string{
		"cluster", "token-create",
		"--cluster-addr", clusterAddr1,
		"--cert", adminCertPath,
		"--key", adminKeyPath,
		"--ca", caCertPath,
		"--ttl", "30m",
		"--node-id", "unused-node",
		"--json",
	})
	var parsedTokResp cluster.TokenCreateResponse
	if err := json.Unmarshal([]byte(jsonTokenOut), &parsedTokResp); err != nil {
		t.Fatalf("failed to parse token-create --json output: %v\nraw=%s", err, jsonTokenOut)
	}
	if parsedTokResp.BoundNodeID != "unused-node" || parsedTokResp.CreatedByNode != "node-1" {
		t.Fatalf("unexpected token-create --json response: %+v", parsedTokResp)
	}

	// 3. Start Node 2 with --join and --join-token and ZERO pre-existing files in node2DataDir!
	execPort2 := freeLoopbackPort(t)
	clusterPort2 := freeLoopbackPort(t)
	execAddr2 := net.JoinHostPort("127.0.0.1", strconv.Itoa(execPort2))
	clusterAddr2 := net.JoinHostPort("127.0.0.1", strconv.Itoa(clusterPort2))

	node2Ctx, cancelNode2 := context.WithCancel(context.Background())
	defer cancelNode2()

	node2Done := make(chan int, 1)
	var node2Stdout, node2Stderr syncBuffer
	go func() {
		node2Done <- runContext(node2Ctx, []string{
			"server",
			"--bind", "127.0.0.1",
			"--port", strconv.Itoa(execPort2),
			"--cluster-bind", clusterAddr2,
			"--node-id", "node-2",
			"--join", clusterAddr1,
			"--join-token", joinToken,
			"--data-dir", node2DataDir,
		}, &node2Stdout, &node2Stderr)
	}()

	waitForTCPPort(t, clusterAddr2, 5*time.Second)
	waitForTCPPort(t, execAddr2, 5*time.Second)

	// Wait until both nodes converge on `two-node` / `healthy` / `2` alive members.
	var status2 cluster.ClusterStatus
	waitDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(waitDeadline) {
		statusJSON := mustRunCLI(t, []string{
			"cluster", "status",
			"--cluster-addr", clusterAddr2,
			"--cert", adminCertPath,
			"--key", adminKeyPath,
			"--ca", caCertPath,
			"--json",
		})
		if err := json.Unmarshal([]byte(statusJSON), &status2); err != nil {
			t.Fatalf("invalid cluster status JSON: %v", err)
		}
		if status2.Topology == cluster.TopologyTwoNode &&
			status2.QuorumState == cluster.QuorumHealthy &&
			status2.AliveNodes == 2 &&
			status2.TotalNodes == 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if status2.Topology != cluster.TopologyTwoNode || status2.QuorumState != cluster.QuorumHealthy || status2.AliveNodes != 2 {
		t.Fatalf("Node 2 did not reach healthy two-node state: %+v", status2)
	}
	if !status2.HasQuorum || status2.LeaderID != "node-1" || status2.HasCAKey {
		t.Fatalf("unexpected Node 2 leadership/CA flags: %+v", status2)
	}

	// Verify human-readable `cluster status` and `cluster peers` + `cluster peers --json`.
	humanStatus := mustRunCLI(t, []string{
		"cluster", "status",
		"--cluster-addr", clusterAddr1,
		"--cert", adminCertPath,
		"--key", adminKeyPath,
		"--ca", caCertPath,
	})
	if !strings.Contains(humanStatus, "Topology:       two-node") || !strings.Contains(humanStatus, "Quorum State:   healthy") {
		t.Fatalf("unexpected human cluster status output:\n%s", humanStatus)
	}

	peersTable := mustRunCLI(t, []string{
		"cluster", "peers",
		"--cluster-addr", clusterAddr2,
		"--cert", adminCertPath,
		"--key", adminKeyPath,
		"--ca", caCertPath,
	})
	if !strings.Contains(peersTable, "NODE_ID") || !strings.Contains(peersTable, "node-1") || !strings.Contains(peersTable, "node-2") {
		t.Fatalf("unexpected cluster peers table output:\n%s", peersTable)
	}

	peersJSON := mustRunCLI(t, []string{
		"cluster", "peers",
		"--cluster-addr", clusterAddr2,
		"--cert", adminCertPath,
		"--key", adminKeyPath,
		"--ca", caCertPath,
		"--json",
	})
	var peersList []cluster.PeerInfo
	if err := json.Unmarshal([]byte(peersJSON), &peersList); err != nil {
		t.Fatalf("invalid cluster peers JSON: %v", err)
	}
	if len(peersList) != 2 {
		t.Fatalf("len(peersList) = %d, want 2", len(peersList))
	}

	// 4. Execute `agent-bridge exec` against Node 2's /ws/exec using valid client certs.
	okCmd := "printf 'node2-exec-ok'"
	if runtime.GOOS == "windows" {
		okCmd = "Write-Output 'node2-exec-ok'"
	}
	const wantStdout = "node2-exec-ok\n"

	for _, cDir := range []string{revokedCliDir, allowedCliDir, unlistedCliDir} {
		var out, errBuf bytes.Buffer
		rc := run([]string{
			"exec",
			"--endpoint", execAddr2,
			"--cert", filepath.Join(cDir, pki.ClientCertFilename),
			"--key", filepath.Join(cDir, pki.ClientKeyFilename),
			"--ca", caCertPath,
			okCmd,
		}, &out, &errBuf)
		if rc != 0 {
			t.Fatalf("exec against Node 2 failed (dir=%s, rc=%d): stderr=%q", cDir, rc, errBuf.String())
		}
		if out.String() != wantStdout {
			t.Fatalf("exec stdout = %q, want %q", out.String(), wantStdout)
		}
		if errBuf.Len() != 0 {
			t.Fatalf("exec unexpected stderr = %q", errBuf.String())
		}
	}

	// 5. Revoke `agent-revokeme` on Node 1 (`ca revoke`) and verify automatic gossip CRL propagation to Node 2!
	revOut := mustRunCLI(t, []string{
		"ca", "revoke",
		"--ca-dir", caDir,
		"--serial", revokedSerial,
	})
	if !strings.Contains(revOut, "CRL Number:     2") {
		t.Fatalf("unexpected ca revoke output:\n%s", revOut)
	}

	revDeadline := time.Now().Add(3 * time.Second)
	node2RejectedRevoked := false
	var lastRevErr string
	for time.Now().Before(revDeadline) {
		var out, errBuf bytes.Buffer
		rc := run([]string{
			"exec",
			"--endpoint", execAddr2,
			"--cert", filepath.Join(revokedCliDir, pki.ClientCertFilename),
			"--key", filepath.Join(revokedCliDir, pki.ClientKeyFilename),
			"--ca", caCertPath,
			okCmd,
		}, &out, &errBuf)
		if rc != 0 {
			if out.Len() != 0 {
				t.Fatalf("revoked exec wrote to stdout (%q) despite error exit %d", out.String(), rc)
			}
			lastRevErr = errBuf.String()
			if strings.Contains(lastRevErr, "mTLS handshake rejected") {
				node2RejectedRevoked = true
				break
			}
		}
		time.Sleep(35 * time.Millisecond)
	}
	if !node2RejectedRevoked {
		t.Fatalf("expected Node 2 to automatically receive revoked CRL and reject handshake; last stderr=%q", lastRevErr)
	}

	// 6. Push a cluster-wide ExecutionPolicy via `agent-bridge cluster sync` on Node 1 and verify Node 2 enforces 403 ACL.
	syncOut1 := mustRunCLI(t, []string{
		"cluster", "sync",
		"--cluster-addr", clusterAddr1,
		"--cert", adminCertPath,
		"--key", adminKeyPath,
		"--ca", caCertPath,
		"--enforce-client-acl",
		"--allow-client", "agent-allowed",
		"--default-timeout", "45s",
		"--max-timeout", "120s",
	})
	if !strings.Contains(syncOut1, "Policy Version: 1") {
		t.Fatalf("expected Policy Version: 1 in sync output:\n%s", syncOut1)
	}

	// Unlisted client must immediately be denied (403 Forbidden) on Node 2 with pure empty stdout.
	{
		var out, errBuf bytes.Buffer
		rc := run([]string{
			"exec",
			"--endpoint", execAddr2,
			"--cert", filepath.Join(unlistedCliDir, pki.ClientCertFilename),
			"--key", filepath.Join(unlistedCliDir, pki.ClientKeyFilename),
			"--ca", caCertPath,
			okCmd,
		}, &out, &errBuf)
		if rc == 0 {
			t.Fatal("expected Node 2 to deny unlisted client agent-unlisted under cluster ExecutionPolicy ACL")
		}
		if out.Len() != 0 {
			t.Fatalf("expected empty stdout on ACL rejection, got %q", out.String())
		}
		if !strings.Contains(errBuf.String(), "403") {
			t.Fatalf("expected HTTP 403 error on stderr for ACL rejection, got %q", errBuf.String())
		}
	}

	// Allowed client must continue to succeed on Node 2.
	{
		var out, errBuf bytes.Buffer
		rc := run([]string{
			"exec",
			"--endpoint", execAddr2,
			"--cert", adminCertPath,
			"--key", adminKeyPath,
			"--ca", caCertPath,
			okCmd,
		}, &out, &errBuf)
		if rc != 0 || out.String() != wantStdout || errBuf.Len() != 0 {
			t.Fatalf("expected allowed client to succeed on Node 2 (rc=%d, stdout=%q, stderr=%q)", rc, out.String(), errBuf.String())
		}
	}

	// Verify incremental `cluster sync` preserves unspecified policy fields and increments Version to 2.
	syncJSON2 := mustRunCLI(t, []string{
		"cluster", "sync",
		"--cluster-addr", clusterAddr1,
		"--cert", adminCertPath,
		"--key", adminKeyPath,
		"--ca", caCertPath,
		"--max-timeout", "90s",
		"--json",
	})
	var syncRes2 cluster.SyncResult
	if err := json.Unmarshal([]byte(syncJSON2), &syncRes2); err != nil {
		t.Fatalf("invalid cluster sync --json output: %v", err)
	}
	if syncRes2.PolicyVersion != 2 ||
		!syncRes2.Policy.EnforceClientACL ||
		syncRes2.Policy.DefaultTimeoutSeconds != 45 ||
		syncRes2.Policy.MaxTimeoutSeconds != 90 ||
		len(syncRes2.Policy.AllowedClients) != 1 ||
		syncRes2.Policy.AllowedClients[0] != "agent-allowed" {
		t.Fatalf("incremental cluster sync did not preserve policy fields cleanly: %+v", syncRes2.Policy)
	}

	// 7. Stop Node 1 (partition / peer loss) -> verify Node 2 continues servicing `agent-bridge exec` (Graceful Degradation).
	cancelNode1()
	select {
	case exit1 := <-node1Done:
		if exit1 != exitOK {
			t.Fatalf("Node 1 exited with %d on graceful shutdown; stderr=%s", exit1, node1Stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Node 1 did not shut down within 5s")
	}

	{
		var out, errBuf bytes.Buffer
		rc := run([]string{
			"exec",
			"--endpoint", execAddr2,
			"--cert", adminCertPath,
			"--key", adminKeyPath,
			"--ca", caCertPath,
			okCmd,
		}, &out, &errBuf)
		if rc != 0 || out.String() != wantStdout || errBuf.Len() != 0 {
			t.Fatalf("Graceful Degradation failed on Node 2 after Node 1 stopped (rc=%d, stdout=%q, stderr=%q)",
				rc, out.String(), errBuf.String())
		}
	}

	// 8. Restart Node 2 from persisted state while Node 1 remains offline (and WITHOUT --join-token!).
	cancelNode2()
	select {
	case exit2 := <-node2Done:
		if exit2 != exitOK {
			t.Fatalf("Node 2 exited with %d on graceful shutdown; stderr=%s", exit2, node2Stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Node 2 did not shut down within 5s")
	}

	execPort2Restart := freeLoopbackPort(t)
	clusterPort2Restart := freeLoopbackPort(t)
	execAddr2Restart := net.JoinHostPort("127.0.0.1", strconv.Itoa(execPort2Restart))
	clusterAddr2Restart := net.JoinHostPort("127.0.0.1", strconv.Itoa(clusterPort2Restart))

	node2RestartCtx, cancelNode2Restart := context.WithCancel(context.Background())
	defer cancelNode2Restart()

	node2RestartDone := make(chan int, 1)
	var node2RestartStdout, node2RestartStderr syncBuffer
	go func() {
		node2RestartDone <- runContext(node2RestartCtx, []string{
			"server",
			"--bind", "127.0.0.1",
			"--port", strconv.Itoa(execPort2Restart),
			"--cluster-bind", clusterAddr2Restart,
			"--node-id", "node-2",
			"--join", clusterAddr1, // Seed Node 1 is completely offline!
			"--data-dir", node2DataDir,
		}, &node2RestartStdout, &node2RestartStderr)
	}()

	waitForTCPPort(t, clusterAddr2Restart, 5*time.Second)
	waitForTCPPort(t, execAddr2Restart, 5*time.Second)

	// Allowed client succeeds against restarted Node 2 despite offline seed Node 1.
	{
		var out, errBuf bytes.Buffer
		rc := run([]string{
			"exec",
			"--endpoint", execAddr2Restart,
			"--cert", adminCertPath,
			"--key", adminKeyPath,
			"--ca", caCertPath,
			okCmd,
		}, &out, &errBuf)
		if rc != 0 || out.String() != wantStdout || errBuf.Len() != 0 {
			t.Fatalf("restarted Node 2 failed exec while seed Node 1 was down (rc=%d, stdout=%q, stderr=%q)",
				rc, out.String(), errBuf.String())
		}
	}

	// Persisted ExecutionPolicy ACL and persisted CRL are BOTH still enforced after offline restart!
	{
		var out, errBuf bytes.Buffer
		rc := run([]string{
			"exec",
			"--endpoint", execAddr2Restart,
			"--cert", filepath.Join(unlistedCliDir, pki.ClientCertFilename),
			"--key", filepath.Join(unlistedCliDir, pki.ClientKeyFilename),
			"--ca", caCertPath,
			okCmd,
		}, &out, &errBuf)
		if rc == 0 || out.Len() != 0 || !strings.Contains(errBuf.String(), "403") {
			t.Fatalf("restarted Node 2 did not enforce persisted ExecutionPolicy ACL (rc=%d, stdout=%q, stderr=%q)",
				rc, out.String(), errBuf.String())
		}
	}
	{
		var out, errBuf bytes.Buffer
		rc := run([]string{
			"exec",
			"--endpoint", execAddr2Restart,
			"--cert", filepath.Join(revokedCliDir, pki.ClientCertFilename),
			"--key", filepath.Join(revokedCliDir, pki.ClientKeyFilename),
			"--ca", caCertPath,
			okCmd,
		}, &out, &errBuf)
		if rc == 0 || out.Len() != 0 || !strings.Contains(errBuf.String(), "mTLS handshake rejected") {
			t.Fatalf("restarted Node 2 did not enforce persisted revoked CRL (rc=%d, stdout=%q, stderr=%q)",
				rc, out.String(), errBuf.String())
		}
	}

	cancelNode2Restart()
	select {
	case exitRestart := <-node2RestartDone:
		if exitRestart != exitOK {
			t.Fatalf("restarted Node 2 exited with %d; stderr=%s", exitRestart, node2RestartStderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("restarted Node 2 did not shut down within 5s")
	}
}

func TestCLIClusterZeroFlagDataDirAndBindFailFast(t *testing.T) {
	tmp := t.TempDir()
	origWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("os.Chdir(%s): %v", tmp, err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(origWD)
	})

	caDir := filepath.Join(tmp, "pki")
	srv1Dir := filepath.Join(tmp, "srv1")
	cliDir := filepath.Join(tmp, "cli")

	mustRunCLI(t, []string{"ca", "init", "--out-dir", caDir})
	mustRunCLI(t, []string{
		"ca", "issue",
		"--ca-dir", caDir,
		"--type", "server",
		"--name", "seed-1",
		"--ip", "127.0.0.1",
		"--out-dir", srv1Dir,
	})
	mustRunCLI(t, []string{
		"ca", "issue",
		"--ca-dir", caDir,
		"--type", "client",
		"--name", "operator",
		"--out-dir", cliDir,
	})

	// Verify cluster-enabled server bind failure on unassignable IP 198.51.100.42 never logs "listening on".
	{
		var out, errBuf bytes.Buffer
		rc := run([]string{
			"server",
			"--bind", "198.51.100.42",
			"--port", "18443",
			"--cluster-bind", "127.0.0.1:18444",
			"--cert", filepath.Join(srv1Dir, pki.ServerCertFilename),
			"--key", filepath.Join(srv1Dir, pki.ServerKeyFilename),
			"--ca", filepath.Join(caDir, pki.CACertFilename),
			"--crl", filepath.Join(caDir, pki.CRLFilename),
		}, &out, &errBuf)
		if rc == exitOK {
			t.Fatal("expected cluster server to fail fast on unassignable --bind 198.51.100.42")
		}
		if strings.Contains(errBuf.String(), "listening on") {
			t.Fatalf("cluster server logged 'listening on' despite bind failure: %q", errBuf.String())
		}
	}

	execPort1 := freeLoopbackPort(t)
	clusterPort1 := freeLoopbackPort(t)
	clusterAddr1 := net.JoinHostPort("127.0.0.1", strconv.Itoa(clusterPort1))

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()
	done1 := make(chan int, 1)
	var out1, err1 syncBuffer
	go func() {
		done1 <- runContext(ctx1, []string{
			"server",
			"--bind", "127.0.0.1",
			"--port", strconv.Itoa(execPort1),
			"--cluster-bind", clusterAddr1,
			"--cert", filepath.Join(srv1Dir, pki.ServerCertFilename),
			"--key", filepath.Join(srv1Dir, pki.ServerKeyFilename),
			"--ca", filepath.Join(caDir, pki.CACertFilename),
			"--crl", filepath.Join(caDir, pki.CRLFilename),
		}, &out1, &err1)
	}()
	waitForTCPPort(t, clusterAddr1, 5*time.Second)

	tok := strings.TrimSpace(mustRunCLI(t, []string{
		"cluster", "token-create",
		"--cluster-addr", clusterAddr1,
		"--cert", filepath.Join(cliDir, pki.ClientCertFilename),
		"--key", filepath.Join(cliDir, pki.ClientKeyFilename),
		"--ca", filepath.Join(caDir, pki.CACertFilename),
		"-q",
	}))

	// Start joining node WITHOUT --data-dir, --cert, --key, --ca, or --crl (verifies ./agent-bridge-data/<node-id>).
	execPort2 := freeLoopbackPort(t)
	clusterPort2 := freeLoopbackPort(t)
	execAddr2 := net.JoinHostPort("127.0.0.1", strconv.Itoa(execPort2))
	clusterAddr2 := net.JoinHostPort("127.0.0.1", strconv.Itoa(clusterPort2))

	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	done2 := make(chan int, 1)
	var out2, err2 syncBuffer
	go func() {
		done2 <- runContext(ctx2, []string{
			"server",
			"--bind", "127.0.0.1",
			"--port", strconv.Itoa(execPort2),
			"--cluster-bind", clusterAddr2,
			"--node-id", "auto-dir-node",
			"--join", clusterAddr1,
			"--join-token", tok,
		}, &out2, &err2)
	}()
	waitForTCPPort(t, execAddr2, 5*time.Second)

	expectedAutoCert := filepath.Join(tmp, "agent-bridge-data", "auto-dir-node", pki.ServerCertFilename)
	if !fileExistsRegular(expectedAutoCert) {
		t.Fatalf("expected auto-provisioned certificate at %s", expectedAutoCert)
	}

	cancel2()
	<-done2
	cancel1()
	<-done1
}

func mustRunCLI(t *testing.T, args []string) string {
	t.Helper()
	var out, errBuf bytes.Buffer
	rc := run(args, &out, &errBuf)
	if rc != exitOK {
		t.Fatalf("run(%v) failed with exit code %d:\nstdout=%s\nstderr=%s", args, rc, out.String(), errBuf.String())
	}
	return out.String()
}
