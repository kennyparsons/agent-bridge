//go:build !linux && !darwin && !windows

package doctor

import "github.com/kennyparsons/agent-bridge/internal/netbind"

func detectPlatformIPv4Forwarding(_ []netbind.InterfaceInfo) (enabled bool, detail string, err error) {
	return false, "IPv4 forwarding inspection not supported on this platform", nil
}
