//go:build !windows

package daemonlog

import "os"

func openAppendShared(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
}

func openReadShared(path string) (*os.File, error) {
	return os.Open(path)
}
