package passive

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseMDNS processes an mDNS packet and updates the analysis result.
func (e *Engine) parseMDNS(packet gopacket.Packet) {
	udpLayer, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok {
		return
	}

	mdns := &layers.DNS{}
	// mDNS is just DNS on a different port. We can use the DNS decoder.
	if err := mdns.DecodeFromBytes(udpLayer.Payload, gopacket.NilDecodeFeedback); err != nil {
		return
	}

	// We need the source MAC address from the Ethernet layer.
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer == nil {
		return
	}
	eth, _ := ethernetLayer.(*layers.Ethernet)
	mac := eth.SrcMAC.String()

	var services []string
	for _, ans := range mdns.Answers {
		if ans.Type != layers.DNSTypePTR {
			continue
		}
		service := string(ans.PTR)
		if service == "" && len(ans.Data) > 0 {
			service = string(ans.Data)
		}
		if service != "" {
			services = append(services, service)
		}
	}

	if len(services) == 0 {
		return
	}

	resultMutex.Lock()
	defer resultMutex.Unlock()

	host, created := e.ensureHostLocked(mac)
	if host == nil {
		return
	}
	if created {
		log.Printf("Passive mDNS: discovered new host %s via mDNS", mac)
	}
	for _, service := range services {
		if _, serviceExists := host.Services[service]; !serviceExists {
			host.Services[service] = struct{}{}
			log.Printf("Passive mDNS: host %s (%s) announced service: %s", mac, host.Vendor, service)
		}
		if isSensitiveMDNSService(service) {
			addUniqueString(&host.LeakedMDNSServices, service)
		}
	}
}
