//go:build !windows

package netbind

import (
	"errors"
	"syscall"
)

func platformIsAddrNotAvail(err error) bool {
	return errors.Is(err, syscall.EADDRNOTAVAIL)
}

func platformIsIPv6Unsupported(err error) bool {
	return errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT)
}
