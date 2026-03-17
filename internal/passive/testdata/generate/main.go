package main

import (
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func main() {
	base := filepath.Join("internal", "passive", "testdata")

	samples := map[string][][]byte{
		"arp.pcap":  {buildARPPacket()},
		"dhcp.pcap": {buildDHCPPacket()},
		"mdns.pcap": {buildMDNSPacket()},
		"dns.pcap":  {buildDNSPacket()},
		"ja3.pcap":  {buildTLSPacket()},
	}

	for name, packets := range samples {
		if err := writePcap(filepath.Join(base, name), packets); err != nil {
			log.Fatalf("writing %s: %v", name, err)
		}
	}
}

func writePcap(path string, packets [][]byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := pcapgo.NewWriter(f)
	if err := writer.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return err
	}

	for _, pkt := range packets {
		capture := gopacket.CaptureInfo{
			Timestamp:     time.Unix(0, 0),
			CaptureLength: len(pkt),
			Length:        len(pkt),
		}
		if err := writer.WritePacket(capture, pkt); err != nil {
			return err
		}
	}
	return nil
}

func buildARPPacket() []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		SourceProtAddress: []byte{192, 168, 1, 50},
		DstHwAddress:      []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    []byte{192, 168, 1, 1},
	}

	return serializePacket(eth, arp)
}

func buildDHCPPacket() []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee},
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.IP{255, 255, 255, 255},
		Protocol: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: 67,
		DstPort: 68,
	}
	udp.SetNetworkLayerForChecksum(ip)

	clientMAC := net.HardwareAddr{0x00, 0x24, 0xd7, 0x12, 0x34, 0x56}
	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		Xid:          0x3903f326,
		YourClientIP: net.IP{192, 168, 1, 60},
		ClientHWAddr: clientMAC,
	}

	dhcp.Options = []layers.DHCPOption{
		{Type: layers.DHCPOptMessageType, Length: 1, Data: []byte{byte(layers.DHCPMsgTypeOffer)}},
		{Type: layers.DHCPOptHostname, Length: uint8(len("lab-ap")), Data: []byte("lab-ap")},
		{Type: layers.DHCPOptServerID, Length: 4, Data: []byte{192, 168, 1, 1}},
	}

	return serializePacket(eth, ip, udp, dhcp)
}

func buildMDNSPacket() []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x24, 0xd7, 0x12, 0x34, 0x56},
		DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      255,
		SrcIP:    net.IP{192, 168, 1, 60},
		DstIP:    net.IP{224, 0, 0, 251},
		Protocol: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: 5353,
		DstPort: 5353,
	}
	udp.SetNetworkLayerForChecksum(ip)

	header := []byte{
		0x00, 0x00, // ID
		0x84, 0x00, // Flags: response + AA
		0x00, 0x00, // QDCOUNT
		0x00, 0x01, // ANCOUNT
		0x00, 0x00, // NSCOUNT
		0x00, 0x00, // ARCOUNT
	}

	name := encodeDomainName("_services._dns-sd._udp.local.")
	target := encodeDomainName("macbook._workstation._tcp.local.")

	answer := append([]byte{}, name...)
	answer = append(answer, 0x00, 0x0c)             // PTR
	answer = append(answer, 0x00, 0x01)             // Class IN
	answer = append(answer, 0x00, 0x00, 0x00, 0x78) // TTL 120
	answer = append(answer, byte(len(target)>>8), byte(len(target)&0xff))
	answer = append(answer, target...)

	payload := append(header, answer...)

	return serializePacket(eth, ip, udp, gopacket.Payload(payload))
}

func buildDNSPacket() []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x24, 0xd7, 0x12, 0x34, 0x56},
		DstMAC:       net.HardwareAddr{0x30, 0x9c, 0x23, 0xaa, 0xbb, 0xcc},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 1, 60},
		DstIP:    net.IP{8, 8, 8, 8},
		Protocol: layers.IPProtocolUDP,
	}

	udp := &layers.UDP{
		SrcPort: 51000,
		DstPort: 53,
	}
	udp.SetNetworkLayerForChecksum(ip)

	dns := &layers.DNS{
		ID:      0x2042,
		QR:      false,
		OpCode:  layers.DNSOpCodeQuery,
		RD:      true,
		QDCount: 1,
	}
	domain := []byte("zz0sd92las9d0asdj123.malicious-example.xyz.")
	dns.Questions = append(dns.Questions, layers.DNSQuestion{
		Name:  domain,
		Type:  layers.DNSTypeA,
		Class: layers.DNSClassIN,
	})

	return serializePacket(eth, ip, udp, dns)
}

func buildTLSPacket() []byte {
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x24, 0xd7, 0x12, 0x34, 0x56},
		DstMAC:       net.HardwareAddr{0x34, 0x29, 0xea, 0xff, 0xee, 0xdd},
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    net.IP{192, 168, 1, 60},
		DstIP:    net.IP{93, 184, 216, 34},
		Protocol: layers.IPProtocolTCP,
	}

	tcp := &layers.TCP{
		SrcPort: 52345,
		DstPort: 443,
		Seq:     1,
		Ack:     1,
		ACK:     true,
		PSH:     true,
		Window:  64240,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	payload := buildTLSClientHello()
	tcp.Payload = payload

	return serializePacket(eth, ip, tcp, gopacket.Payload(payload))
}

func buildTLSClientHello() []byte {
	hello := []byte{
		0x16, 0x03, 0x03, 0x00, 0x4d, // TLS record header
		0x01, 0x00, 0x00, 0x49, // Handshake header
		0x03, 0x03, // Client version
	}

	// Random bytes (32)
	random := []byte{
		0x5e, 0x7f, 0x3a, 0x61, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
		0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14,
		0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
	}
	hello = append(hello, random...)

	// Session ID length
	hello = append(hello, 0x00)

	// Cipher suites
	ciphers := []byte{
		0x00, 0x08,
		0x00, 0x2f, 0x00, 0x35, 0x00, 0x3c, 0x00, 0x9c,
	}
	hello = append(hello, ciphers...)

	// Compression methods
	hello = append(hello, 0x01, 0x00)

	// Extensions length
	hello = append(hello, 0x00, 0x18)

	// SNI extension
	hello = append(hello,
		0x00, 0x00, // type
		0x00, 0x06, // length
		0x00, 0x04, // list length
		0x00,             // name type
		0x00, 0x01, 0x61, // host "a"
	)

	// Supported groups extension
	hello = append(hello,
		0x00, 0x0a,
		0x00, 0x04,
		0x00, 0x02,
		0x00, 0x1d,
	)

	// EC point formats
	hello = append(hello,
		0x00, 0x0b,
		0x00, 0x02,
		0x01, 0x00,
	)

	return hello
}

func encodeDomainName(name string) []byte {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0x00}
	}
	labels := strings.Split(name, ".")
	var encoded []byte
	for _, label := range labels {
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, []byte(label)...)
	}
	return append(encoded, 0x00)
}

func serializePacket(layersList ...gopacket.SerializableLayer) []byte {
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	if err := gopacket.SerializeLayers(buffer, opts, layersList...); err != nil {
		panic(err)
	}
	return buffer.Bytes()
}
