//go:build !windows

package acl

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LockdownServerDir creates path (if absent) and enforces strict 0700 POSIX directory permissions.
func LockdownServerDir(path string) error {
	clean, err := cleanRequiredPath(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(clean, 0o700); err != nil {
		return fmt.Errorf("failed to create directory %q: %w", clean, err)
	}
	if err := os.Chmod(clean, 0o700); err != nil {
		return fmt.Errorf("failed to enforce 0700 permissions on directory %q: %w", clean, err)
	}
	return nil
}

// LockdownClientDir creates path (if absent) and enforces strict 0700 POSIX directory permissions.
func LockdownClientDir(path string) error {
	return LockdownServerDir(path)
}

// LockdownPrivateFile enforces strict 0600 POSIX file permissions on path.
func LockdownPrivateFile(path string) error {
	clean, err := cleanRequiredPath(path)
	if err != nil {
		return err
	}
	if err := os.Chmod(clean, 0o600); err != nil {
		return fmt.Errorf("failed to enforce 0600 permissions on file %q: %w", clean, err)
	}
	return nil
}

// LockdownClientFile enforces strict 0600 POSIX file permissions on path.
func LockdownClientFile(path string) error {
	return LockdownPrivateFile(path)
}

// AuditPathACL inspects POSIX permissions on path and verifies zero group or world permission bits (mode & 0077 == 0).
func AuditPathACL(path string, _ bool) (ACLStatus, error) {
	clean, err := cleanRequiredPath(path)
	if err != nil {
		return ACLStatus{}, err
	}
	info, err := os.Stat(clean)
	if err != nil {
		return ACLStatus{Path: clean}, fmt.Errorf("failed to stat %q: %w", clean, err)
	}

	perm := info.Mode().Perm()
	groupAllowed := (perm & 0o070) != 0
	otherAllowed := (perm & 0o007) != 0

	status := ACLStatus{
		Path:            clean,
		ProtectedDACL:   true,
		EveryoneAllowed: otherAllowed,
		UsersAllowed:    groupAllowed,
		ModePerm:        uint32(perm),
	}

	if perm&0o077 != 0 {
		expected := "0600"
		if info.IsDir() {
			expected = "0700"
		}
		if groupAllowed {
			status.Violations = append(status.Violations, fmt.Sprintf("mode %04o grants group access (expected %s)", perm, expected))
		}
		if otherAllowed {
			status.Violations = append(status.Violations, fmt.Sprintf("mode %04o grants world/other access (expected %s)", perm, expected))
		}
		status.Secure = false
		status.Summary = fmt.Sprintf("insecure POSIX mode %04o (expected %s)", perm, expected)
		return status, nil
	}

	status.Secure = true
	status.Summary = fmt.Sprintf("mode %04o (owner-only)", perm)
	return status, nil
}

func cleanRequiredPath(path string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", errors.New("path cannot be empty")
	}
	return filepath.Clean(trimmed), nil
}
