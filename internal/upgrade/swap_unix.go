//go:build !windows

package upgrade

import (
	"fmt"
	"io"
	"os"
)

func atomicSwapExecutable(exePath, stagedPath string) (string, error) {
	oldPath := exePath + ".old"
	_ = os.Remove(oldPath)

	if info, err := os.Stat(exePath); err == nil {
		perm := info.Mode().Perm() | 0o111
		_ = os.Chmod(stagedPath, perm)
	}

	if linkErr := os.Link(exePath, oldPath); linkErr != nil {
		if copyErr := copyExecutableBackup(exePath, oldPath); copyErr != nil {
			return "", fmt.Errorf("failed creating backup executable %q (link: %v; copy: %w)", oldPath, linkErr, copyErr)
		}
	}

	if err := os.Rename(stagedPath, exePath); err != nil {
		_ = os.Remove(oldPath)
		return "", fmt.Errorf("failed atomically replacing executable %q: %w", exePath, err)
	}

	return oldPath, nil
}

func restoreBackupExecutable(exePath, backupPath string) error {
	if err := os.Rename(backupPath, exePath); err != nil {
		return fmt.Errorf("failed restoring backup executable %q to %q: %w", backupPath, exePath, err)
	}
	return nil
}

func cleanupBackupExecutable(backupPath string) {
	if backupPath != "" {
		_ = os.Remove(backupPath)
	}
}

func copyExecutableBackup(srcPath, dstPath string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()

	perm := os.FileMode(0o755)
	if info, statErr := src.Stat(); statErr == nil {
		perm = info.Mode().Perm() | 0o111
	}

	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, perm)
	if err != nil {
		return err
	}

	success := false
	defer func() {
		_ = dst.Close()
		if !success {
			_ = os.Remove(dstPath)
		}
	}()

	if err := dst.Chmod(perm); err != nil {
		return err
	}
	if _, err := io.Copy(dst, src); err != nil {
		return err
	}
	if err := dst.Sync(); err != nil {
		return err
	}
	if err := dst.Close(); err != nil {
		return err
	}
	success = true
	return nil
}
