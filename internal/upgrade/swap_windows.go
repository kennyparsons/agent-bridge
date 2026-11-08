//go:build windows

package upgrade

import (
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
)

const winReplaceFlags = windows.MOVEFILE_REPLACE_EXISTING | windows.MOVEFILE_WRITE_THROUGH

func atomicSwapExecutable(exePath, stagedPath string) (string, error) {
	oldPath := exePath + ".old"
	if rmErr := os.Remove(oldPath); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
		rotatedPath := fmt.Sprintf("%s.old.%d", exePath, time.Now().UnixNano())
		if rotErr := moveFileReplace(oldPath, rotatedPath); rotErr != nil {
			return "", fmt.Errorf("failed rotating locked backup %q to %q: %w", oldPath, rotatedPath, rotErr)
		}
		scheduleDeleteOnReboot(rotatedPath)
	}

	if err := moveFileReplace(exePath, oldPath); err != nil {
		return "", fmt.Errorf("failed moving current executable %q to %q: %w", exePath, oldPath, err)
	}

	if err := moveFileReplace(stagedPath, exePath); err != nil {
		if rbErr := moveFileReplace(oldPath, exePath); rbErr != nil {
			return "", fmt.Errorf(
				"failed installing staged executable to %q (%v) and failed restoring %q (%v)",
				exePath, err, oldPath, rbErr,
			)
		}
		return "", fmt.Errorf("failed installing staged executable to %q (restored previous executable): %w", exePath, err)
	}

	return oldPath, nil
}

func restoreBackupExecutable(exePath, backupPath string) error {
	var movedAside string
	if _, statErr := os.Stat(exePath); statErr == nil {
		aside := fmt.Sprintf("%s.old.%d", exePath, time.Now().UnixNano())
		if err := moveFileReplace(exePath, aside); err == nil {
			movedAside = aside
		}
	}

	if err := moveFileReplace(backupPath, exePath); err != nil {
		if movedAside != "" {
			_ = moveFileReplace(movedAside, exePath)
		}
		return fmt.Errorf("failed restoring backup executable %q to %q: %w", backupPath, exePath, err)
	}

	if movedAside != "" {
		if rmErr := os.Remove(movedAside); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			scheduleDeleteOnReboot(movedAside)
		}
	}
	return nil
}

func cleanupBackupExecutable(backupPath string) {
	if backupPath == "" {
		return
	}
	if err := os.Remove(backupPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		scheduleDeleteOnReboot(backupPath)
	}
}

func moveFileReplace(src, dst string) error {
	fromPtr, err := windows.UTF16PtrFromString(src)
	if err != nil {
		return fmt.Errorf("invalid source path %q: %w", src, err)
	}
	toPtr, err := windows.UTF16PtrFromString(dst)
	if err != nil {
		return fmt.Errorf("invalid destination path %q: %w", dst, err)
	}
	return windows.MoveFileEx(fromPtr, toPtr, winReplaceFlags)
}

func scheduleDeleteOnReboot(path string) {
	if ptr, err := windows.UTF16PtrFromString(path); err == nil {
		_ = windows.MoveFileEx(ptr, nil, windows.MOVEFILE_DELAY_UNTIL_REBOOT)
	}
}
