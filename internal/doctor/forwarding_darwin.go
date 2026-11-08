//go:build darwin

package doctor

import (
	"fmt"

	"golang.org/x/sys/unix"

	"github.com/kennyparsons/agent-bridge/internal/netbind"
)

const darwinIPv4ForwardSysctl = "net.inet.ip.forwarding"

func detectPlatformIPv4Forwarding(_ []netbind.InterfaceInfo) (enabled bool, detail string, err error) {
	val, err := unix.SysctlUint32(darwinIPv4ForwardSysctl)
	if err != nil {
		return false, "", fmt.Errorf("sysctl %s failed: %w", darwinIPv4ForwardSysctl, err)
	}
	if val != 0 {
		return true, fmt.Sprintf("sysctl %s=%d", darwinIPv4ForwardSysctl, val), nil
	}
	return false, fmt.Sprintf("sysctl %s=0", darwinIPv4ForwardSysctl), nil
}
