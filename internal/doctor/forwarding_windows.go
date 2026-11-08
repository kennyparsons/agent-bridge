//go:build windows

package doctor

import (
	"fmt"
	"net"
	"strings"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/kennyparsons/agent-bridge/internal/netbind"
)

const tcpipParamsRegKey = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters`

func detectPlatformIPv4Forwarding(ifaces []netbind.InterfaceInfo) (enabled bool, detail string, err error) {
	var forwardingIfaces []string
	var probed int

	for _, iface := range ifaces {
		if iface.Index <= 0 || iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if netbind.IsEphemeralBridgeInterface(iface.Name) {
			continue
		}
		row := windows.MibIpInterfaceRow{
			Family:         windows.AF_INET,
			InterfaceIndex: uint32(iface.Index),
		}
		if callErr := windows.GetIpInterfaceEntry(&row); callErr != nil {
			continue
		}
		probed++
		if row.ForwardingEnabled != 0 {
			forwardingIfaces = append(forwardingIfaces, iface.Name)
		}
	}

	if len(forwardingIfaces) > 0 {
		return true, fmt.Sprintf("iphlpapi GetIpInterfaceEntry ForwardingEnabled=1 on [%s]", strings.Join(forwardingIfaces, ", ")), nil
	}

	// Fallback / secondary check against HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\IPEnableRouter.
	key, regErr := registry.OpenKey(registry.LOCAL_MACHINE, tcpipParamsRegKey, registry.QUERY_VALUE)
	if regErr == nil {
		defer func() {
			_ = key.Close()
		}()
		val, _, valErr := key.GetIntegerValue("IPEnableRouter")
		if valErr == nil && val != 0 {
			return true, fmt.Sprintf(`HKLM\%s\IPEnableRouter=%d`, tcpipParamsRegKey, val), nil
		}
		if valErr == nil {
			return false, fmt.Sprintf(`HKLM\%s\IPEnableRouter=0`, tcpipParamsRegKey), nil
		}
	}

	if probed > 0 {
		return false, "iphlpapi GetIpInterfaceEntry ForwardingEnabled=0 on active interfaces", nil
	}
	if regErr != nil {
		return false, "", fmt.Errorf("unable to query Windows IPv4 forwarding via iphlpapi or registry: %w", regErr)
	}
	return false, "Windows IPv4 forwarding disabled", nil
}
