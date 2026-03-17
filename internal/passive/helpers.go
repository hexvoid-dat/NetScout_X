package passive

import (
	"strings"
	"time"
)

const zeroMAC = "00:00:00:00:00:00"

// ensureHostLocked retrieves or creates a passive host record.
// Callers must hold resultMutex.
func (e *Engine) ensureHostLocked(mac string) (*Host, bool) {
	mac = normalizeMAC(mac)
	if mac == "" || mac == zeroMAC {
		return nil, false
	}

	host, exists := e.Result.Hosts[mac]
	if !exists {
		host = NewHost(mac)
		host.Vendor = GetVendorFromMAC(mac)
		e.Result.Hosts[mac] = host
	}
	host.LastSeen = time.Now()
	return host, !exists
}

func normalizeMAC(mac string) string {
	return strings.ToLower(mac)
}
