package passive

import (
	"context"
	"log"
	"net"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Engine is the core of the passive analysis system.
type Engine struct {
	Interfaces []string
	Result     *AnalysisResult
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// NewEngine creates a new passive analysis engine.
func NewEngine(interfaces ...string) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
	return &Engine{
		Interfaces: interfaces,
		Result:     NewAnalysisResult(),
		ctx:        ctx,
		cancel:     cancel,
	}
}

// Start begins the passive packet capture and analysis.
func (e *Engine) Start() {
	if len(e.Interfaces) == 0 {
		ifaces, err := net.Interfaces()
		if err != nil {
			log.Printf("Passive: could not list interfaces: %v", err)
			return
		}
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
				e.Interfaces = append(e.Interfaces, iface.Name)
			}
		}
	}

	log.Printf("Passive: starting capture on interfaces: %v", e.Interfaces)
	for _, ifaceName := range e.Interfaces {
		e.wg.Add(1)
		go e.sniffInterface(ifaceName)
	}
}

// Stop halts the packet capture and waits for all processing to finish.
func (e *Engine) Stop() {
	log.Println("Passive: stopping capture...")
	e.cancel()
	e.wg.Wait()
	log.Println("Passive: capture stopped.")
}

// sniffInterface opens a pcap handle on a single interface and starts the packet processing loop.
// Gopacket to potężna kobyła, ale potrafi zjeść sporo RAM-u przy dużym ruchu. 
// Trzeba uważać na bufory przy setkach tysięcy pakietów na sekundę.
func (e *Engine) sniffInterface(ifaceName string) {
	defer e.wg.Done()

	handle, err := pcap.OpenLive(ifaceName, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Passive: could not open pcap on %s: %v. (Try running with sudo)", ifaceName, err)
		return
	}
	defer handle.Close()

	// Set a BPF filter to capture only the traffic we care about.
	filter := "arp or (udp and (port 67 or port 68 or port 53 or port 5353)) or (tcp and port 443)"
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Printf("Passive: could not set BPF filter on %s: %v", ifaceName, err)
		// Continue without filter, but it will be less efficient.
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packets := packetSource.Packets()

	for {
		select {
		case <-e.ctx.Done():
			return
		case packet, ok := <-packets:
			if !ok {
				return
			}
			e.dispatchPacket(packet)
		}
	}
}

// dispatchPacket inspects a packet and sends it to the appropriate parser.
func (e *Engine) dispatchPacket(packet gopacket.Packet) {
	// ARP Parser
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		e.parseARP(arpLayer.(*layers.ARP))
	}

	// Check for UDP protocols
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		srcPort, dstPort := udp.SrcPort, udp.DstPort

		// DHCP Parser
		if (srcPort == 67 && dstPort == 68) || (srcPort == 68 && dstPort == 67) {
			e.parseDHCP(packet)
		}

		// mDNS Parser
		if dstPort == 5353 || srcPort == 5353 {
			e.parseMDNS(packet)
		}

		// DNS Parser
		if dstPort == 53 || srcPort == 53 {
			e.parseDNS(packet)
		}
	}

	// TLS/JA3 Parser
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcp, ok := tcpLayer.(*layers.TCP); ok {
			payload := tcp.Payload
			if len(payload) > 5 && payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01 {
				e.parseJA3(packet)
			}
		}
	}
}
