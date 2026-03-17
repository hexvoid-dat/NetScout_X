package scanner

import (
	"context"
	"errors"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ARPResult holds the mapping discovered via ARP.
type ARPResult struct {
	IPToMAC  map[string]string
	MACToIPs map[string][]string
}

// EnrichHostsWithARP merges ARP results into the existing host list.
// It returns the updated hosts slice (including any ARP-only hosts)
// and the ARPResult (for downstream analysis).
func EnrichHostsWithARP(hosts []Host, subnet string) ([]Host, ARPResult, bool) {
	ips, err := GetIPsInSubnet(subnet)
	if err != nil {
		log.Printf("ARP: could not parse subnet %s for enrichment: %v", subnet, err)
		return hosts, ARPResult{}, false
	}

	arpResult, arpActive := CollectARP(ips, subnet)
	if !arpActive {
		return hosts, arpResult, false
	}

	hostMap := make(map[string]*Host)
	for i := range hosts {
		hostMap[hosts[i].IP] = &hosts[i]
	}

	for ip, mac := range arpResult.IPToMAC {
		if host, found := hostMap[ip]; found {
			host.MAC = mac
		} else {
			newHost := Host{
				IP:  ip,
				MAC: mac,
			}
			hosts = append(hosts, newHost)
		}
	}

	return hosts, arpResult, true
}

// CollectARP tries to collect ARP information for all IPs in the given subnet.
// It returns best-effort mappings and a boolean flag indicating whether ARP
// collection was actually active (true) or skipped/fell back (false).
func CollectARP(ips []net.IP, subnet string) (ARPResult, bool) {
	iface, localIP, err := findInterfaceForSubnet(subnet)
	if err != nil {
		log.Printf("ARP: no matching interface for subnet %s, skipping ARP collection", subnet)
		return ARPResult{}, false
	}

	handle, err := pcap.OpenLive(iface.Name, 65536, false, pcap.BlockForever)
	if err != nil {
		log.Printf("ARP: could not open pcap on %s: %v (falling back to TCP-only discovery)", iface.Name, err)
		return ARPResult{}, false
	}
	defer handle.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ipToMAC := make(map[string]string)
	macToIPs := make(map[string][]string)
	var mu sync.Mutex

	// Start listening for ARP replies
	go listenARP(ctx, handle, &mu, ipToMAC, macToIPs)

	// Send ARP requests
	for _, ip := range ips {
		if ip.Equal(localIP) {
			continue
		}
		sendARPRequest(handle, iface, localIP, ip)
		// Mały sleep, żeby nie zafloodować sieci i nie pogubić odpowiedzi.
		time.Sleep(10 * time.Millisecond)
	}

	<-ctx.Done() // Wait for collection to finish

	return ARPResult{
		IPToMAC:  ipToMAC,
		MACToIPs: macToIPs,
	}, true
}

func findInterfaceForSubnet(subnetStr string) (*net.Interface, net.IP, error) {
	// Szukanie właściwego interfejsu to zawsze loteria, jak ktoś ma 
	// odpalone VPN-y i inne wynalazki. Lecimy po masce i sprawdzamy co pasuje.
	_, subnet, err := net.ParseCIDR(subnetStr)
	if err != nil {
		return nil, nil, err
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil && subnet.Contains(ipnet.IP) {
					return &iface, ipnet.IP, nil
				}
			}
		}
	}
	return nil, nil, errors.New("no suitable interface found")
}

func sendARPRequest(handle *pcap.Handle, iface *net.Interface, srcIP, dstIP net.IP) {
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(srcIP.To4()),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(dstIP.To4()),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	if err := handle.WritePacketData(buf.Bytes()); err != nil {
		log.Printf("ARP: failed to send request: %v", err)
	}
}

func listenARP(ctx context.Context, handle *pcap.Handle, mu *sync.Mutex, ipToMAC map[string]string, macToIPs map[string][]string) {
	src := gopacket.NewPacketSource(handle, handle.LinkType())
	in := src.Packets()

	for {
		select {
		case <-ctx.Done():
			return
		case packet, ok := <-in:
			if !ok {
				return
			}
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}
			arp, _ := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply {
				continue
			}

			srcIP := net.IP(arp.SourceProtAddress).String()
			srcMAC := net.HardwareAddr(arp.SourceHwAddress).String()

			mu.Lock()
			if _, ok := ipToMAC[srcIP]; !ok {
				ipToMAC[srcIP] = srcMAC
				macToIPs[srcMAC] = append(macToIPs[srcMAC], srcIP)
			}
			mu.Unlock()
		}
	}
}
