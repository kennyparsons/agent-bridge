//go:build windows

package netbind

import (
	"errors"

	"golang.org/x/sys/windows"
)

func platformIsAddrNotAvail(err error) bool {
	return errors.Is(err, windows.WSAEADDRNOTAVAIL)
}

func platformIsIPv6Unsupported(err error) bool {
	return errors.Is(err, windows.WSAEAFNOSUPPORT) || errors.Is(err, windows.WSAEPROTONOSUPPORT)
}
