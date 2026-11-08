//go:build windows

package daemonlog

import (
	"os"

	"golang.org/x/sys/windows"
)

func openAppendShared(path string) (*os.File, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// Omit FILE_WRITE_DATA so Win32 atomically appends every write to EOF, and grant
	// FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE so concurrent log readers and
	// rotation renames never fail with ERROR_SHARING_VIOLATION.
	access := uint32(windows.FILE_APPEND_DATA | windows.FILE_WRITE_ATTRIBUTES | windows.STANDARD_RIGHTS_WRITE | windows.SYNCHRONIZE)
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	handle, err := windows.CreateFile(
		pathPtr,
		access,
		share,
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}

func openReadShared(path string) (*os.File, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	share := uint32(windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE)
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		share,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), path), nil
}
