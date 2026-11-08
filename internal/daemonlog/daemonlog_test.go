package daemonlog

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/kennyparsons/agent-bridge/internal/acl"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestRotatingWriterDefaultsAndBackupRetention(t *testing.T) {
	t.Parallel()

	if DefaultMaxBytes != 10<<20 {
		t.Fatalf("DefaultMaxBytes = %d, want %d", DefaultMaxBytes, 10<<20)
	}
	if DefaultMaxBackups != 5 {
		t.Fatalf("DefaultMaxBackups = %d, want 5", DefaultMaxBackups)
	}

	dir := filepath.Join(t.TempDir(), "logs")
	logPath := filepath.Join(dir, "daemon.log")

	w, err := NewRotatingWriter(Options{
		Path:       logPath,
		MaxBytes:   120,
		MaxBackups: 3,
	})
	if err != nil {
		t.Fatalf("NewRotatingWriter failed: %v", err)
	}
	defer func() {
		_ = w.Close()
	}()

	// Write 12 lines (~480 bytes) so multiple rotations occur and backups cap at .3.
	for i := 1; i <= 12; i++ {
		line := fmt.Sprintf("2026-11-08T00:00:%02dZ event-%02d-payload\n", i, i)
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatalf("Write(%d) failed: %v", i, err)
		}
	}
	if err := w.Sync(); err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	for idx := 1; idx <= 3; idx++ {
		if _, err := os.Stat(fmt.Sprintf("%s.%d", logPath, idx)); err != nil {
			t.Fatalf("expected backup %s.%d to exist: %v", logPath, idx, err)
		}
	}
	if _, err := os.Stat(fmt.Sprintf("%s.4", logPath)); !os.IsNotExist(err) {
		t.Fatalf("expected backup .4 not to exist when MaxBackups=3, stat err=%v", err)
	}

	// Verify log directory and active log file pass ACL lockdown audit.
	if stDir, err := acl.AuditPathACL(dir, false); err != nil || !stDir.Secure {
		t.Fatalf("expected log directory ACL secure, got st=%+v err=%v", stDir, err)
	}
	if stFile, err := acl.AuditPathACL(logPath, false); err != nil || !stFile.Secure {
		t.Fatalf("expected active log file ACL secure, got st=%+v err=%v", stFile, err)
	}
}

func TestTailLinesMultiChunkCRLFAndConcurrentSharedReads(t *testing.T) {
	t.Parallel()

	logPath := filepath.Join(t.TempDir(), "daemon.log")
	w, err := Open(logPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer func() {
		_ = w.Close()
	}()

	// Empty file returns empty slice.
	emptyLines, err := TailLines(logPath, 10)
	if err != nil || len(emptyLines) != 0 {
		t.Fatalf("TailLines(empty) = (%v, %v), want ([], nil)", emptyLines, err)
	}

	// Write > 100 KiB with mixed LF and CRLF line endings to exercise multi-chunk backward reading.
	total := 1500
	for i := 1; i <= total; i++ {
		sep := "\n"
		if i%2 == 0 {
			sep = "\r\n"
		}
		entry := fmt.Sprintf("line-%04d-%s%s", i, strings.Repeat("x", 72), sep)
		if _, err := w.Write([]byte(entry)); err != nil {
			t.Fatalf("Write(%d) failed: %v", i, err)
		}
	}

	got, err := TailLines(logPath, 5)
	if err != nil {
		t.Fatalf("TailLines(5) failed: %v", err)
	}
	if len(got) != 5 {
		t.Fatalf("len(TailLines) = %d, want 5", len(got))
	}
	for idx, wantNum := range []int{1496, 1497, 1498, 1499, 1500} {
		wantPrefix := fmt.Sprintf("line-%04d-", wantNum)
		if !strings.HasPrefix(got[idx], wantPrefix) || strings.HasSuffix(got[idx], "\r") {
			t.Fatalf("got[%d] = %q, want prefix %q without trailing CR", idx, got[idx], wantPrefix)
		}
	}

	// Concurrent writers + concurrent TailLines readers while file stays open.
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(2)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 40; j++ {
				_, _ = fmt.Fprintf(w, "concurrent-writer-%d-%d\n", id, j)
			}
		}(g)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				if _, rErr := TailLines(logPath, 15); rErr != nil {
					t.Errorf("concurrent TailLines error: %v", rErr)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestFollowStreamsInitialLinesLiveAppendsAndAcrossLogRotation(t *testing.T) {
	t.Parallel()

	logPath := filepath.Join(t.TempDir(), "daemon.log")
	w, err := NewRotatingWriter(Options{
		Path:       logPath,
		MaxBytes:   180,
		MaxBackups: 3,
	})
	if err != nil {
		t.Fatalf("NewRotatingWriter failed: %v", err)
	}
	defer func() {
		_ = w.Close()
	}()

	for i := 1; i <= 4; i++ {
		if _, err := fmt.Fprintf(w, "seed-line-%d\n", i); err != nil {
			t.Fatalf("seed write failed: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := &syncBuffer{}
	doneCh := make(chan error, 1)
	go func() {
		doneCh <- followWithInterval(ctx, logPath, 2, out, 35*time.Millisecond)
	}()

	// Wait for initial 2 seed lines ("seed-line-3", "seed-line-4").
	waitForSubstring(t, out, "seed-line-4\n", 2*time.Second)
	initialOut := out.String()
	if strings.Contains(initialOut, "seed-line-1\n") || strings.Contains(initialOut, "seed-line-2\n") {
		t.Fatalf("Follow emitted more than initialLines=2: %q", initialOut)
	}
	if !strings.Contains(initialOut, "seed-line-3\n") {
		t.Fatalf("Follow missed seed-line-3: %q", initialOut)
	}

	// Write enough live lines to trigger multiple rotations while Follow has the file open!
	for i := 1; i <= 10; i++ {
		payload := fmt.Sprintf("live-msg-%02d-rotation-probe-padding\n", i)
		if _, err := w.Write([]byte(payload)); err != nil {
			t.Fatalf("live Write(%d) failed: %v", i, err)
		}
		time.Sleep(15 * time.Millisecond)
	}

	waitForSubstring(t, out, "live-msg-10-rotation-probe-padding\n", 3*time.Second)
	cancel()

	select {
	case followErr := <-doneCh:
		if followErr != nil {
			t.Fatalf("Follow returned unexpected error on ctx cancel: %v", followErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Follow did not exit cleanly after context cancellation")
	}

	streamed := out.String()
	for i := 1; i <= 10; i++ {
		want := fmt.Sprintf("live-msg-%02d-rotation-probe-padding\n", i)
		if !strings.Contains(streamed, want) {
			t.Fatalf("Follow lost line %q across log rotation; full output:\n%s", want, streamed)
		}
	}
}

func waitForSubstring(t *testing.T, buf *syncBuffer, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), want) {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timed out after %v waiting for %q in %q", timeout, want, buf.String())
}
