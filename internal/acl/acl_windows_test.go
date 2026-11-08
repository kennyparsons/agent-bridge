//go:build windows

package acl

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsNTFSDACLViolationsAndRemediation(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "test-secret.key")
	if err := os.WriteFile(target, []byte("key-material"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	userSID, err := currentProcessUserSID()
	if err != nil {
		t.Fatalf("currentProcessUserSID failed: %v", err)
	}

	// Apply an intentionally over-permissive DACL granting BUILTIN\Users (BU) and Everyone (WD) read access.
	insecureSDDL := "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)(A;;FR;;;WD)(A;;FA;;;" + userSID + ")"
	sd, err := windows.SecurityDescriptorFromString(insecureSDDL)
	if err != nil {
		t.Fatalf("SecurityDescriptorFromString failed: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("sd.DACL() failed: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		target,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	); err != nil {
		t.Fatalf("SetNamedSecurityInfo(insecure) failed: %v", err)
	}

	stBad, err := AuditPathACL(target, true)
	if err != nil {
		t.Fatalf("AuditPathACL(insecure) failed: %v", err)
	}
	if stBad.Secure || !stBad.EveryoneAllowed || !stBad.UsersAllowed {
		t.Fatalf("expected EveryoneAllowed=true and UsersAllowed=true on insecure DACL, got %+v", stBad)
	}

	// Remediate with LockdownClientFile and re-audit.
	if err := LockdownClientFile(target); err != nil {
		t.Fatalf("LockdownClientFile failed: %v", err)
	}
	stFixed, err := AuditPathACL(target, true)
	if err != nil {
		t.Fatalf("AuditPathACL(fixed) failed: %v", err)
	}
	if !stFixed.Secure || !stFixed.ProtectedDACL || stFixed.EveryoneAllowed || stFixed.UsersAllowed {
		t.Fatalf("expected secure protected DACL after LockdownClientFile, got %+v", stFixed)
	}
}
