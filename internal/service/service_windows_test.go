//go:build windows

package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows/svc"
)

func TestWindowsLegacyMigrationAndDefenderHelpers(t *testing.T) {
	tmp := t.TempDir()
	exePath := filepath.Join(tmp, "agent-bridge.exe")
	legacyScript := filepath.Join(tmp, LegacyWindowsRunScriptFilename)
	if err := os.WriteFile(exePath, []byte("exe"), 0o755); err != nil {
		t.Fatalf("WriteFile(exePath): %v", err)
	}
	if err := os.WriteFile(legacyScript, []byte("# legacy wrapper"), 0o644); err != nil {
		t.Fatalf("WriteFile(legacyScript): %v", err)
	}

	type recordedCall struct {
		env  []string
		name string
		args []string
	}
	var calls []recordedCall

	wm := &windowsManager{
		runCmd: func(_ context.Context, env []string, name string, args ...string) ([]byte, error) {
			calls = append(calls, recordedCall{env: env, name: name, args: args})
			return nil, nil
		},
	}

	migrated, warnings := wm.migrateLegacyScheduledTask(context.Background(), exePath)
	if !migrated || len(warnings) != 0 {
		t.Fatalf("migrateLegacyScheduledTask = (%v, %v)", migrated, warnings)
	}
	if _, err := os.Stat(legacyScript); !os.IsNotExist(err) {
		t.Fatalf("expected legacy %s to be deleted", legacyScript)
	}
	if len(calls) < 4 {
		t.Fatalf("expected schtasks Query/End/Delete + powershell cleanup calls, got %d", len(calls))
	}

	// Verify Defender exclusion passes path via env var AB_EXE_PATH rather than interpolating into -Command.
	calls = nil
	evilLookingPath := `C:\Program Files\Agent'Bridge$(calc)\agent-bridge.exe`
	if err := wm.addDefenderExclusion(context.Background(), evilLookingPath); err != nil {
		t.Fatalf("addDefenderExclusion: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 powershell call, got %d", len(calls))
	}
	cmdStr := strings.Join(calls[0].args, " ")
	if strings.Contains(cmdStr, "calc") {
		t.Fatalf("Defender exclusion interpolated path directly into command args: %s", cmdStr)
	}
	foundEnv := false
	for _, kv := range calls[0].env {
		if kv == "AB_EXE_PATH="+evilLookingPath {
			foundEnv = true
		}
	}
	if !foundEnv {
		t.Fatalf("expected AB_EXE_PATH env var to carry executable path")
	}
}

func TestWinSvcHandlerStateMachine(t *testing.T) {
	reqCh := make(chan svc.ChangeRequest, 4)
	statusCh := make(chan svc.Status, 16)

	started := make(chan struct{})
	h := &winSvcHandler{
		name: "agent-bridge",
		runFn: func(ctx context.Context) int {
			close(started)
			<-ctx.Done()
			return 0
		},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		svcSpec, code := h.Execute([]string{"agent-bridge"}, reqCh, statusCh)
		if svcSpec || code != 0 {
			t.Errorf("unexpected Execute exit: svcSpec=%v code=%d", svcSpec, code)
		}
	}()

	<-started
	reqCh <- svc.ChangeRequest{Cmd: svc.Stop}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for winSvcHandler.Execute to stop")
	}

	close(statusCh)
	var states []svc.State
	for st := range statusCh {
		states = append(states, st.State)
	}
	if len(states) < 4 || states[0] != svc.StartPending || states[1] != svc.Running || states[len(states)-1] != svc.Stopped {
		t.Fatalf("unexpected SCM state transitions: %v", states)
	}
}
