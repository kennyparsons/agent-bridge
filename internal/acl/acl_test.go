package acl

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSDDLBuildersAndSIDValidation(t *testing.T) {
	t.Parallel()

	if ServerDirSDDL != "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)" {
		t.Fatalf("unexpected ServerDirSDDL: %q", ServerDirSDDL)
	}
	if PrivateFileSDDL != "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)" {
		t.Fatalf("unexpected PrivateFileSDDL: %q", PrivateFileSDDL)
	}

	userSID := "S-1-5-21-1000000001-2000000002-3000000003-1001"
	dirSDDL, err := ClientDirSDDL(userSID)
	if err != nil {
		t.Fatalf("ClientDirSDDL failed: %v", err)
	}
	wantDir := "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-21-1000000001-2000000002-3000000003-1001)"
	if dirSDDL != wantDir {
		t.Fatalf("ClientDirSDDL = %q, want %q", dirSDDL, wantDir)
	}

	fileSDDL, err := ClientFileSDDL(userSID)
	if err != nil {
		t.Fatalf("ClientFileSDDL failed: %v", err)
	}
	wantFile := "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;S-1-5-21-1000000001-2000000002-3000000003-1001)"
	if fileSDDL != wantFile {
		t.Fatalf("ClientFileSDDL = %q, want %q", fileSDDL, wantFile)
	}

	// Deduplication when process runs directly as SYSTEM or BUILTIN\Administrators.
	for _, sysSID := range []string{SIDLocalSystem, SIDBuiltinAdmins, "s-1-5-18"} {
		d, err := ClientDirSDDL(sysSID)
		if err != nil || d != ServerDirSDDL {
			t.Fatalf("ClientDirSDDL(%q) = (%q, %v), want (%q, nil)", sysSID, d, err, ServerDirSDDL)
		}
		f, err := ClientFileSDDL(sysSID)
		if err != nil || f != PrivateFileSDDL {
			t.Fatalf("ClientFileSDDL(%q) = (%q, %v), want (%q, nil)", sysSID, f, err, PrivateFileSDDL)
		}
	}

	invalidSIDs := []string{
		"",
		"   ",
		"WD",
		"S-2-5-18",
		"S-1-",
		"S-1-5-18-",
		"S-1-5--18",
		"S-1-5-18)(A;;FA;;;WD",
	}
	for _, bad := range invalidSIDs {
		if _, err := ClientDirSDDL(bad); err == nil {
			t.Errorf("ClientDirSDDL(%q) unexpectedly succeeded", bad)
		}
		if _, err := ClientFileSDDL(bad); err == nil {
			t.Errorf("ClientFileSDDL(%q) unexpectedly succeeded", bad)
		}
	}
}

func TestLockdownAndAuditPathACL(t *testing.T) {
	t.Parallel()

	base := t.TempDir()
	srvDir := filepath.Join(base, "server-node")
	cliDir := filepath.Join(base, "client-cfg")

	// Pre-create over-permissive directory to verify LockdownServerDir tightens existing modes/DACLs.
	if err := os.MkdirAll(srvDir, 0o777); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(srvDir, 0o755)
		stBefore, err := AuditPathACL(srvDir, false)
		if err != nil {
			t.Fatalf("AuditPathACL(0755 dir) error: %v", err)
		}
		if stBefore.Secure || !stBefore.UsersAllowed || !stBefore.EveryoneAllowed {
			t.Fatalf("expected 0755 dir to fail audit, got %+v", stBefore)
		}
	}

	if err := LockdownServerDir(srvDir); err != nil {
		t.Fatalf("LockdownServerDir failed: %v", err)
	}
	stSrvDir, err := AuditPathACL(srvDir, false)
	if err != nil {
		t.Fatalf("AuditPathACL(srvDir) failed: %v", err)
	}
	if !stSrvDir.Secure || !stSrvDir.ProtectedDACL || stSrvDir.EveryoneAllowed || stSrvDir.UsersAllowed {
		t.Fatalf("expected locked-down server dir to pass audit, got %+v", stSrvDir)
	}

	if err := LockdownClientDir(cliDir); err != nil {
		t.Fatalf("LockdownClientDir failed: %v", err)
	}
	stCliDir, err := AuditPathACL(cliDir, true)
	if err != nil {
		t.Fatalf("AuditPathACL(cliDir) failed: %v", err)
	}
	if !stCliDir.Secure || !stCliDir.ProtectedDACL || stCliDir.EveryoneAllowed || stCliDir.UsersAllowed {
		t.Fatalf("expected locked-down client dir to pass audit, got %+v", stCliDir)
	}

	// Test private file lockdown from initial 0644 permissions.
	srvKeyPath := filepath.Join(srvDir, "server.key")
	if err := os.WriteFile(srvKeyPath, []byte("secret-key"), 0o644); err != nil {
		t.Fatalf("WriteFile(srvKeyPath): %v", err)
	}
	if runtime.GOOS != "windows" {
		_ = os.Chmod(srvKeyPath, 0o640)
		stGroup, err := AuditPathACL(srvKeyPath, false)
		if err != nil {
			t.Fatalf("AuditPathACL(0640) failed: %v", err)
		}
		if stGroup.Secure || !stGroup.UsersAllowed || stGroup.EveryoneAllowed {
			t.Fatalf("expected 0640 file to flag UsersAllowed=true, EveryoneAllowed=false, got %+v", stGroup)
		}

		_ = os.Chmod(srvKeyPath, 0o604)
		stWorld, err := AuditPathACL(srvKeyPath, false)
		if err != nil {
			t.Fatalf("AuditPathACL(0604) failed: %v", err)
		}
		if stWorld.Secure || stWorld.UsersAllowed || !stWorld.EveryoneAllowed {
			t.Fatalf("expected 0604 file to flag UsersAllowed=false, EveryoneAllowed=true, got %+v", stWorld)
		}
	}

	if err := LockdownPrivateFile(srvKeyPath); err != nil {
		t.Fatalf("LockdownPrivateFile failed: %v", err)
	}
	stKey, err := AuditPathACL(srvKeyPath, false)
	if err != nil {
		t.Fatalf("AuditPathACL(srvKeyPath) failed: %v", err)
	}
	if !stKey.Secure || stKey.EveryoneAllowed || stKey.UsersAllowed {
		t.Fatalf("expected locked-down private file to pass audit, got %+v", stKey)
	}

	cliKeyPath := filepath.Join(cliDir, "client.key")
	if err := os.WriteFile(cliKeyPath, []byte("client-secret"), 0o644); err != nil {
		t.Fatalf("WriteFile(cliKeyPath): %v", err)
	}
	if err := LockdownClientFile(cliKeyPath); err != nil {
		t.Fatalf("LockdownClientFile failed: %v", err)
	}
	stCliKey, err := AuditPathACL(cliKeyPath, true)
	if err != nil {
		t.Fatalf("AuditPathACL(cliKeyPath) failed: %v", err)
	}
	if !stCliKey.Secure || stCliKey.EveryoneAllowed || stCliKey.UsersAllowed {
		t.Fatalf("expected locked-down client file to pass audit, got %+v", stCliKey)
	}

	// Verify empty and missing path error handling.
	if err := LockdownServerDir("   "); err == nil {
		t.Fatal("expected error on empty LockdownServerDir path")
	}
	if err := LockdownPrivateFile("   "); err == nil {
		t.Fatal("expected error on empty LockdownPrivateFile path")
	}
	if _, err := AuditPathACL(filepath.Join(base, "does-not-exist"), false); err == nil {
		t.Fatal("expected error auditing nonexistent path")
	}
}
