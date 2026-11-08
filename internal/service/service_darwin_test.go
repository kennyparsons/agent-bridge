//go:build darwin

package service

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDarwinManagerLifecycle(t *testing.T) {
	tmp := t.TempDir()
	plistDir := filepath.Join(tmp, "LaunchDaemons")
	dataDir := filepath.Join(tmp, "node")
	cfgPath := filepath.Join(tmp, "server.json")
	logPath := filepath.Join(tmp, "logs", "daemon.log")
	exePath := filepath.Join(tmp, "agent-bridge")
	if err := os.WriteFile(exePath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("WriteFile(exePath): %v", err)
	}

	loaded := false
	dm := &darwinManager{
		plistDir: plistDir,
		runCmd: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if len(args) > 0 {
				switch args[0] {
				case "bootstrap", "kickstart":
					loaded = true
				case "bootout":
					loaded = false
				case "print":
					if !loaded {
						return []byte("Could not find service"), os.ErrNotExist
					}
					return []byte("\tstate = running\n\tpid = 777\n"), nil
				}
			}
			return nil, nil
		},
	}

	res, err := dm.Install(context.Background(), InstallOptions{
		Name:       "agent-bridge",
		BinaryPath: exePath,
		ConfigPath: cfgPath,
		StartNow:   true,
		Config: &ServerDaemonConfig{
			NodeID:  "mac-node-01",
			DataDir: dataDir,
			LogPath: logPath,
		},
	})
	if err != nil {
		t.Fatalf("Install failed: %v", err)
	}
	if !res.Started || !strings.HasSuffix(res.UnitPath, "io.agent-bridge.agent-bridge.plist") {
		t.Fatalf("unexpected InstallResult: %+v", res)
	}

	st, err := dm.Status(context.Background(), "agent-bridge")
	if err != nil {
		t.Fatalf("Status failed: %v", err)
	}
	if !st.Installed || !st.Running || st.PID != 777 || st.BinaryPath != exePath || st.ConfigPath != cfgPath {
		t.Fatalf("unexpected Status: %+v", st)
	}

	if err := dm.Uninstall(context.Background(), "agent-bridge"); err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}
	if _, err := os.Stat(res.UnitPath); !os.IsNotExist(err) {
		t.Fatalf("expected plist to be deleted")
	}
}
