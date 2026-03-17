package passive

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseDNS processes a DNS packet and updates the analysis result.
func (e *Engine) parseDNS(packet gopacket.Packet) {
	udpLayer, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok {
		return
	}

	dns := &layers.DNS{}
	if err := dns.DecodeFromBytes(udpLayer.Payload, gopacket.NilDecodeFeedback); err != nil {
		return
	}

	// We only care about questions, not responses from servers.
	if len(dns.Questions) == 0 {
		return
	}

	// Get the source IP from the IP layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}
	ip, _ := ipLayer.(*layers.IPv4)
	srcIP := ip.SrcIP.String()

	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	var mac string
	if ethernetLayer != nil {
		if eth, ok := ethernetLayer.(*layers.Ethernet); ok {
			mac = eth.SrcMAC.String()
		}
	}

	// Find the host by IP in our results
	resultMutex.Lock()
	defer resultMutex.Unlock()

	var host *Host
	for _, h := range e.Result.Hosts {
		if _, ok := h.IPs[srcIP]; ok {
			host = h
			break
		}
	}

	// If we don't know this host yet, create it based on the MAC.
	if host == nil && mac != "" {
		var created bool
		host, created = e.ensureHostLocked(mac)
		if host != nil {
			if created {
				log.Printf("Passive DNS: discovered new host %s via DNS query", mac)
			}
			host.IPs[srcIP] = time.Now()
		}
	}

	if host == nil {
		return // Can't attribute fingerprint to a known host
	}

	for _, q := range dns.Questions {
		query := string(q.Name)
		// Avoid flooding with duplicate queries in the log
		isNewQuery := true
		for _, existingQuery := range host.DNSQueries {
			if existingQuery == query {
				isNewQuery = false
				break
			}
		}
		if isNewQuery {
			host.DNSQueries = append(host.DNSQueries, query)
			log.Printf("Passive DNS: host %s (%s) queried for %s", host.MAC, srcIP, query)
			if suspicious, reason := classifyDNSQuery(query); suspicious {
				addUniqueString(&host.SuspiciousDNSQueries, fmt.Sprintf("%s (%s)", query, reason))
			}
		}
	}
}
