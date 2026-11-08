//go:build windows

package acl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// LockdownServerDir creates path (if absent) and applies a protected NTFS DACL
// D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA) stripping inherited BUILTIN\Users and Everyone access.
// When invoked from an unprivileged non-admin user token (e.g. non-elevated developer shells or CI),
// the current user SID is also retained so the caller does not lock itself out of its own directory.
func LockdownServerDir(path string) error {
	clean, err := cleanRequiredPath(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return fmt.Errorf("failed to create directory %q: %w", clean, err)
	}
	sddl := ServerDirSDDL
	if !isCurrentProcessSystemOrAdmin() {
		if userSID, sidErr := currentProcessUserSID(); sidErr == nil {
			if candidate, buildErr := ClientDirSDDL(userSID); buildErr == nil {
				sddl = candidate
			}
		}
	}
	return applySDDL(clean, sddl)
}

// LockdownPrivateFile applies a protected NTFS DACL D:PAI(A;;FA;;;SY)(A;;FA;;;BA) on path,
// stripping inherited BUILTIN\Users and Everyone access.
func LockdownPrivateFile(path string) error {
	clean, err := cleanRequiredPath(path)
	if err != nil {
		return err
	}
	if _, err := os.Stat(clean); err != nil {
		return fmt.Errorf("failed to stat file %q: %w", clean, err)
	}
	sddl := PrivateFileSDDL
	if !isCurrentProcessSystemOrAdmin() {
		if userSID, sidErr := currentProcessUserSID(); sidErr == nil {
			if candidate, buildErr := ClientFileSDDL(userSID); buildErr == nil {
				sddl = candidate
			}
		}
	}
	return applySDDL(clean, sddl)
}

// LockdownClientDir creates path (if absent) and applies a protected NTFS DACL granting access
// exclusively to NT AUTHORITY\SYSTEM, BUILTIN\Administrators, and the current process user SID.
func LockdownClientDir(path string) error {
	clean, err := cleanRequiredPath(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return fmt.Errorf("failed to create client directory %q: %w", clean, err)
	}
	userSID, err := currentProcessUserSID()
	if err != nil {
		return err
	}
	sddl, err := ClientDirSDDL(userSID)
	if err != nil {
		return err
	}
	return applySDDL(clean, sddl)
}

// LockdownClientFile applies a protected NTFS DACL on path granting access exclusively to
// NT AUTHORITY\SYSTEM, BUILTIN\Administrators, and the current process user SID.
func LockdownClientFile(path string) error {
	clean, err := cleanRequiredPath(path)
	if err != nil {
		return err
	}
	if _, err := os.Stat(clean); err != nil {
		return fmt.Errorf("failed to stat client file %q: %w", clean, err)
	}
	userSID, err := currentProcessUserSID()
	if err != nil {
		return err
	}
	sddl, err := ClientFileSDDL(userSID)
	if err != nil {
		return err
	}
	return applySDDL(clean, sddl)
}

// AuditPathACL inspects the NTFS DACL and SE_DACL_PROTECTED control flag on path via Win32 APIs,
// verifying that Everyone (S-1-1-0) and BUILTIN\Users (S-1-5-32-545) have zero allow ACEs.
func AuditPathACL(path string, allowCurrentUser bool) (ACLStatus, error) {
	clean, err := cleanRequiredPath(path)
	if err != nil {
		return ACLStatus{}, err
	}
	if _, err := os.Stat(clean); err != nil {
		return ACLStatus{Path: clean}, fmt.Errorf("failed to stat %q: %w", clean, err)
	}

	sd, err := windows.GetNamedSecurityInfo(
		clean,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return ACLStatus{Path: clean}, fmt.Errorf("GetNamedSecurityInfo failed for %q: %w", clean, err)
	}
	if sd == nil {
		return ACLStatus{
			Path:            clean,
			Secure:          false,
			EveryoneAllowed: true,
			UsersAllowed:    true,
			Summary:         "missing security descriptor on NTFS object",
			Violations:      []string{"security descriptor is nil"},
		}, nil
	}

	control, _, err := sd.Control()
	if err != nil {
		return ACLStatus{Path: clean}, fmt.Errorf("failed to read security descriptor control flags for %q: %w", clean, err)
	}
	protected := (control & windows.SE_DACL_PROTECTED) != 0

	status := ACLStatus{
		Path:          clean,
		ProtectedDACL: protected,
	}
	if !protected {
		status.Violations = append(status.Violations, "DACL is not protected (SE_DACL_PROTECTED unset; inherited ACEs permitted)")
	}

	dacl, _, daclErr := sd.DACL()
	if daclErr != nil {
		if errors.Is(daclErr, windows.ERROR_OBJECT_NOT_FOUND) {
			status.EveryoneAllowed = true
			status.UsersAllowed = true
			status.Violations = append(status.Violations, "no DACL present on object (unrestricted access)")
			status.Summary = "unrestricted null DACL"
			return status, nil
		}
		return status, fmt.Errorf("failed to inspect DACL for %q: %w", clean, daclErr)
	}
	if dacl == nil {
		status.EveryoneAllowed = true
		status.UsersAllowed = true
		status.Violations = append(status.Violations, "NULL DACL grants unrestricted access to Everyone")
		status.Summary = "unrestricted NULL DACL"
		return status, nil
	}

	currentUserSID, _ := currentProcessUserSID()
	elevatedOrSystem := isCurrentProcessSystemOrAdmin()
	seenSIDs := make(map[string]struct{})

	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return status, fmt.Errorf("GetAce(%d) failed for %q: %w", i, clean, err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE || ace.Mask == 0 {
			continue
		}

		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		sidStr := strings.ToUpper(strings.TrimSpace(sid.String()))
		if _, exists := seenSIDs[sidStr]; !exists {
			seenSIDs[sidStr] = struct{}{}
			status.AllowedSIDs = append(status.AllowedSIDs, sidStr)
		}

		switch sidStr {
		case SIDEveryone:
			status.EveryoneAllowed = true
			status.Violations = append(status.Violations, "Everyone (S-1-1-0) has an allow ACE")
		case SIDBuiltinUsers:
			status.UsersAllowed = true
			status.Violations = append(status.Violations, `BUILTIN\Users (S-1-5-32-545) has an allow ACE`)
		case SIDAuthenticatedUsers:
			status.UsersAllowed = true
			status.Violations = append(status.Violations, "Authenticated Users (S-1-5-11) has an allow ACE")
		case SIDLocalSystem, SIDBuiltinAdmins:
			// Expected privileged system/admin principals.
		default:
			canAllowCurrentUser := allowCurrentUser || !elevatedOrSystem
			if canAllowCurrentUser && currentUserSID != "" && strings.EqualFold(sidStr, currentUserSID) {
				continue
			}
			status.Violations = append(status.Violations, fmt.Sprintf("unexpected principal %s has an allow ACE", sidStr))
		}
	}

	status.Secure = len(status.Violations) == 0
	if status.Secure {
		status.Summary = fmt.Sprintf("protected NTFS DACL (%s)", strings.Join(status.AllowedSIDs, ", "))
	} else {
		status.Summary = strings.Join(status.Violations, "; ")
	}
	return status, nil
}

func applySDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return fmt.Errorf("SecurityDescriptorFromString(%q) failed: %w", sddl, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("failed to extract DACL from SDDL %q: %w", sddl, err)
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("SetNamedSecurityInfo failed on %q: %w", path, err)
	}
	return nil
}

func currentProcessUserSID() (string, error) {
	tok := windows.GetCurrentProcessToken()
	tu, err := tok.GetTokenUser()
	if err != nil {
		return "", fmt.Errorf("GetTokenUser failed: %w", err)
	}
	if tu == nil || tu.User.Sid == nil {
		return "", errors.New("GetTokenUser returned nil SID")
	}
	return strings.ToUpper(strings.TrimSpace(tu.User.Sid.String())), nil
}

func isCurrentProcessSystemOrAdmin() bool {
	tok := windows.GetCurrentProcessToken()
	if tu, err := tok.GetTokenUser(); err == nil && tu != nil && tu.User.Sid != nil {
		if strings.EqualFold(tu.User.Sid.String(), SIDLocalSystem) {
			return true
		}
	}
	if tok.IsElevated() {
		return true
	}
	adminSID, err := windows.StringToSid(SIDBuiltinAdmins)
	if err != nil {
		return false
	}
	isMember, err := tok.IsMember(adminSID)
	return err == nil && isMember
}

func cleanRequiredPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", errors.New("path cannot be empty")
	}
	return filepath.Clean(trimmed), nil
}
