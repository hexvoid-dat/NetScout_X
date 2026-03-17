package scanner

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

var ignoredInterfacePrefixes = []string{
	"docker", "br-", "veth", "tailscale", "utun", "wg", "vmnet",
}

// DetectLocalSubnet attempts to find a usable IPv4 subnet on the host machine.
func DetectLocalSubnet() (string, error) {
	// Wykrywanie interfejsu to zawsze ból głowy, zwłaszcza jak ktoś ma nawalone 
	// wirtualnych mostków z Dockera. Lecimy po kolei i szukamy czegoś sensownego.
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("unable to list interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if (iface.Flags&net.FlagLoopback) != 0 || (iface.Flags&net.FlagUp) == 0 {
			continue
		}
		if shouldIgnoreInterface(iface.Name) {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ipv4 := ipNet.IP.To4()
			if ipv4 == nil {
				continue
			}

			networkIP := ipv4.Mask(ipNet.Mask)
			return (&net.IPNet{
				IP:   networkIP,
				Mask: ipNet.Mask,
			}).String(), nil
		}
	}

	return "", errors.New("unable to detect a local IPv4 subnet")
}

func shouldIgnoreInterface(name string) bool {
	lowered := strings.ToLower(name)
	for _, prefix := range ignoredInterfacePrefixes {
		if strings.HasPrefix(lowered, prefix) {
			return true
		}
	}
	return false
}
