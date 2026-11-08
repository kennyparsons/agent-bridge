//go:build linux

package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLinuxManagerLifecycle(t *testing.T) {
	tmp := t.TempDir()
	unitDir := filepath.Join(tmp, "systemd")
	dataDir := filepath.Join(tmp, "var-lib-node")
	cfgPath := filepath.Join(tmp, "etc", "server.json")
	logPath := filepath.Join(tmp, "var-log", "daemon.log")
	exePath := filepath.Join(tmp, "bin", "agent-bridge")
	if err := os.MkdirAll(filepath.Dir(exePath), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(exePath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(exePath): %v", err)
	}

	var calls []string
	activeState := "inactive"
	subState := "dead"
	mainPID := "0"

	mgr := &linuxManager{
		unitDir: unitDir,
		runCmd: func(_ context.Context, name string, args ...string) ([]byte, error) {
			cmdStr := name + " " + strings.Join(args, " ")
			calls = append(calls, cmdStr)
			if len(args) >= 1 {
				switch args[0] {
				case "start", "restart":
					activeState = "active"
					subState = "running"
					mainPID = "5150"
				case "stop":
					activeState = "inactive"
					subState = "dead"
					mainPID = "0"
				case "show":
					out := "LoadState=loaded\nActiveState=" + activeState + "\nSubState=" + subState + "\nMainPID=" + mainPID + "\n"
					return []byte(out), nil
				}
			}
			return nil, nil
		},
	}

	res, err := mgr.Install(context.Background(), InstallOptions{
		Name:              "agent-bridge",
		BinaryPath:        exePath,
		ConfigPath:        cfgPath,
		StartNow:          true,
		ConfigureFirewall: true,
		Config: &ServerDaemonConfig{
			NodeID:  "linux-node-01",
			DataDir: dataDir,
			LogPath: logPath,
			Port:    8765,
		},
	})
	if err != nil {
		t.Fatalf("Install failed: %v", err)
	}
	if !res.Started || res.ServiceType != "systemd" {
		t.Fatalf("unexpected InstallResult: %+v", res)
	}
	if len(res.Warnings) == 0 {
		t.Fatalf("expected non-fatal warning when ConfigureFirewall=true on linux")
	}

	info, err := os.Stat(res.UnitPath)
	if err != nil {
		t.Fatalf("Stat(UnitPath): %v", err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("expected systemd unit mode 0644, got %04o", info.Mode().Perm())
	}

	st, err := mgr.Status(context.Background(), "agent-bridge")
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if !st.Installed || !st.Running || st.PID != 5150 || st.BinaryPath != exePath || st.ConfigPath != cfgPath || st.LogPath != logPath {
		t.Fatalf("unexpected running Status: %+v", st)
	}

	if err := mgr.Stop(context.Background(), "agent-bridge"); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	stStopped, err := mgr.Status(context.Background(), "agent-bridge")
	if err != nil {
		t.Fatalf("Status after Stop failed: %v", err)
	}
	if !stStopped.Installed || stStopped.Running || stStopped.State != "stopped" {
		t.Fatalf("unexpected stopped Status: %+v", stStopped)
	}

	if err := mgr.Uninstall(context.Background(), "agent-bridge"); err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}
	if _, err := os.Stat(res.UnitPath); !os.IsNotExist(err) {
		t.Fatalf("expected unit file to be deleted after Uninstall, err=%v", err)
	}
}

func TestSpawnDetachedServiceRestartUnixHelper(t *testing.T) {
	if os.Getenv("AB_TEST_DETACHED_HELPER") == "1" {
		marker := os.Getenv("AB_TEST_MARKER_FILE")
		inExec := os.Getenv(EnvInExec)
		payload := strings.Join(os.Args[1:], " ") + "|IN_EXEC=" + inExec
		_ = os.WriteFile(marker, []byte(payload), 0o600)
		os.Exit(0)
	}

	markerFile := filepath.Join(t.TempDir(), "detached.marker")
	t.Setenv("AB_TEST_DETACHED_HELPER", "1")
	t.Setenv("AB_TEST_MARKER_FILE", markerFile)
	t.Setenv(EnvInExec, "1")

	testBin, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	if err := SpawnDetachedServiceRestart(testBin, "agent-bridge", "/tmp/rb.bin", 250*time.Millisecond); err != nil {
		t.Fatalf("SpawnDetachedServiceRestart failed: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, readErr := os.ReadFile(markerFile); readErr == nil {
			got := string(data)
			if !strings.Contains(got, "service _detached-restart --name agent-bridge --delay 250ms --rollback-bin /tmp/rb.bin") {
				t.Fatalf("unexpected child args: %q", got)
			}
			if !strings.HasSuffix(got, "|IN_EXEC=") {
				t.Fatalf("expected %s env var to be stripped in detached child, got %q", EnvInExec, got)
			}
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for detached child helper to write %s", markerFile)
}
