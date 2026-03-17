package passive

import (
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseDHCP processes a DHCP packet and updates the analysis result.
func (e *Engine) parseDHCP(packet gopacket.Packet) {
	udpLayer, ok := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
	if !ok {
		return
	}

	payload := udpLayer.Payload
	dhcp := &layers.DHCPv4{}
	err := dhcp.DecodeFromBytes(payload, gopacket.NilDecodeFeedback)
	if err != nil {
		// Not a valid DHCP packet, ignore.
		return
	}

	var leaseInfo DHCPLeaseInfo
	var msgType layers.DHCPMsgType

	for _, opt := range dhcp.Options {
		switch opt.Type {
		case layers.DHCPOptMessageType:
			if len(opt.Data) == 1 {
				msgType = layers.DHCPMsgType(opt.Data[0])
			}
		case layers.DHCPOptHostname:
			leaseInfo.Hostname = string(opt.Data)
		case layers.DHCPOptServerID:
			leaseInfo.ServerIP = net.IP(opt.Data).String()
		}
	}

	// We only care about Offers and ACKs from a server
	if msgType != layers.DHCPMsgTypeOffer && msgType != layers.DHCPMsgTypeAck {
		return
	}

	leaseInfo.IP = dhcp.YourClientIP.String()
	leaseInfo.MAC = dhcp.ClientHWAddr.String()
	leaseInfo.IsOffer = (msgType == layers.DHCPMsgTypeOffer)

	if leaseInfo.ServerIP == "" || leaseInfo.MAC == "" {
		return
	}

	if ethernetLayer := packet.Layer(layers.LayerTypeEthernet); ethernetLayer != nil {
		if eth, ok := ethernetLayer.(*layers.Ethernet); ok {
			leaseInfo.ServerMAC = eth.SrcMAC.String()
		}
	}

	serverVendor := GetVendorFromMAC(leaseInfo.ServerMAC)

	resultMutex.Lock()
	defer resultMutex.Unlock()

	// Track the DHCP server
	serverInfo, exists := e.Result.DHCPServers[leaseInfo.ServerIP]
	if !exists {
		serverInfo = &DHCPServer{
			IP:     leaseInfo.ServerIP,
			MAC:    leaseInfo.ServerMAC,
			Vendor: serverVendor,
		}
		e.Result.DHCPServers[leaseInfo.ServerIP] = serverInfo
	} else {
		if leaseInfo.ServerMAC != "" {
			serverInfo.MAC = leaseInfo.ServerMAC
		}
		if serverVendor != "" {
			serverInfo.Vendor = serverVendor
		}
	}
	serverInfo.LastSeen = time.Now()

	if serverVendor == "" {
		serverVendor = "unknown"
	}

	// Update the host record
	host, created := e.ensureHostLocked(leaseInfo.MAC)
	if host == nil {
		return
	}
	if created {
		log.Printf("Passive DHCP: discovered new host %s via DHCP", leaseInfo.MAC)
	}

	if _, ipExists := host.IPs[leaseInfo.IP]; !ipExists {
		host.IPs[leaseInfo.IP] = time.Now()
	}
	if leaseInfo.Hostname != "" {
		host.DHCPHostname = leaseInfo.Hostname
	}

	// Flag rogue DHCP if vendor looks suspicious or there are too many servers
	suspectVendor := leaseInfo.ServerMAC != "" && !isLikelyInfrastructureVendor(serverVendor)
	if suspectVendor || len(e.Result.DHCPServers) > maxTrustedDHCPServers {
		serverInfo.Suspect = true
		host.PotentialRogueDHCP = true
	}
}
