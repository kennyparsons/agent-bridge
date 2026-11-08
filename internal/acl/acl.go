package acl

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// Well-known Windows security identifiers used for NTFS SDDL lockdown and ACL auditing.
	SIDEveryone           = "S-1-1-0"
	SIDAuthenticatedUsers = "S-1-5-11"
	SIDLocalSystem        = "S-1-5-18"
	SIDBuiltinAdmins      = "S-1-5-32-544"
	SIDBuiltinUsers       = "S-1-5-32-545"

	// ServerDirSDDL sets SE_DACL_PROTECTED (P) + auto-inherit request (AI) and restricts directory
	// access (with OI+CI inheritance) strictly to NT AUTHORITY\SYSTEM (SY) and BUILTIN\Administrators (BA).
	ServerDirSDDL = "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

	// PrivateFileSDDL sets SE_DACL_PROTECTED (P) + auto-inherit request (AI) and restricts file
	// access strictly to NT AUTHORITY\SYSTEM (SY) and BUILTIN\Administrators (BA).
	PrivateFileSDDL = "D:PAI(A;;FA;;;SY)(A;;FA;;;BA)"
)

// ACLStatus reports the security posture of a filesystem path on NTFS (Windows) or POSIX (Unix).
type ACLStatus struct {
	Path            string   `json:"path"`
	Secure          bool     `json:"secure"`
	ProtectedDACL   bool     `json:"protected_dacl"`
	EveryoneAllowed bool     `json:"everyone_allowed"`
	UsersAllowed    bool     `json:"users_allowed"`
	ModePerm        uint32   `json:"mode_perm,omitempty"`
	AllowedSIDs     []string `json:"allowed_sids,omitempty"`
	Summary         string   `json:"summary"`
	Violations      []string `json:"violations,omitempty"`
}

// ClientDirSDDL constructs a protected NTFS directory SDDL granting Full Access (OICI) to
// NT AUTHORITY\SYSTEM (SY), BUILTIN\Administrators (BA), and the specified user SID.
func ClientDirSDDL(userSID string) (string, error) {
	sid, err := normalizeSID(userSID)
	if err != nil {
		return "", err
	}
	if sid == SIDLocalSystem || sid == SIDBuiltinAdmins {
		return ServerDirSDDL, nil
	}
	return fmt.Sprintf("%s(A;OICI;FA;;;%s)", ServerDirSDDL, sid), nil
}

// ClientFileSDDL constructs a protected NTFS file SDDL granting Full Access to
// NT AUTHORITY\SYSTEM (SY), BUILTIN\Administrators (BA), and the specified user SID.
func ClientFileSDDL(userSID string) (string, error) {
	sid, err := normalizeSID(userSID)
	if err != nil {
		return "", err
	}
	if sid == SIDLocalSystem || sid == SIDBuiltinAdmins {
		return PrivateFileSDDL, nil
	}
	return fmt.Sprintf("%s(A;;FA;;;%s)", PrivateFileSDDL, sid), nil
}

func normalizeSID(raw string) (string, error) {
	trimmed := strings.ToUpper(strings.TrimSpace(raw))
	if trimmed == "" {
		return "", errors.New("SID cannot be empty")
	}
	if !strings.HasPrefix(trimmed, "S-1-") || len(trimmed) < 5 {
		return "", fmt.Errorf("invalid Windows SID format %q", raw)
	}
	for i := 4; i < len(trimmed); i++ {
		ch := trimmed[i]
		if (ch < '0' || ch > '9') && ch != '-' {
			return "", fmt.Errorf("invalid character %q in Windows SID %q", ch, raw)
		}
	}
	if strings.HasSuffix(trimmed, "-") || strings.Contains(trimmed, "--") {
		return "", fmt.Errorf("malformed sub-authority in Windows SID %q", raw)
	}
	return trimmed, nil
}
