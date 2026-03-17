package passive

import (
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
)

var (
	// Use a mutex to protect access to the shared AnalysisResult.
	resultMutex = &sync.Mutex{}
)

// parseARP processes an ARP packet and updates the analysis result.
func (e *Engine) parseARP(arp *layers.ARP) {
	srcMAC := net.HardwareAddr(arp.SourceHwAddress).String()
	srcIP := net.IP(arp.SourceProtAddress).String()

	if srcMAC == "00:00:00:00:00:00" || srcIP == "0.0.0.0" {
		return
	}

	resultMutex.Lock()
	defer resultMutex.Unlock()

	host, created := e.ensureHostLocked(srcMAC)
	if created {
		log.Printf("Passive ARP: discovered new host %s (%s) [%s]", srcMAC, srcIP, host.Vendor)
	}
	if _, ipExists := host.IPs[srcIP]; !ipExists {
		host.IPs[srcIP] = time.Now()
	}
}
