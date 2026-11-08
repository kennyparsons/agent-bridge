//go:build linux

package doctor

import (
	"fmt"
	"os"
	"strings"

	"github.com/kennyparsons/agent-bridge/internal/netbind"
)

const linuxIPv4ForwardProcPath = "/proc/sys/net/ipv4/ip_forward"

func detectPlatformIPv4Forwarding(_ []netbind.InterfaceInfo) (enabled bool, detail string, err error) {
	raw, err := os.ReadFile(linuxIPv4ForwardProcPath)
	if err != nil {
		return false, "", fmt.Errorf("failed to read %s: %w", linuxIPv4ForwardProcPath, err)
	}
	val := strings.TrimSpace(string(raw))
	if val != "0" && val != "" {
		return true, fmt.Sprintf("%s=%s", linuxIPv4ForwardProcPath, val), nil
	}
	return false, fmt.Sprintf("%s=0", linuxIPv4ForwardProcPath), nil
}
