package passive

import (
	"crypto/md5"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func TestParseARP(t *testing.T) {
	engine := newTestEngine()
	packet := loadPacket(t, "arp.pcap")

	arpLayer, ok := packet.Layer(layers.LayerTypeARP).(*layers.ARP)
	if !ok {
		t.Fatalf("expected ARP layer in fixture")
	}

	engine.parseARP(arpLayer)

	host := engine.Result.Hosts["00:11:22:33:44:55"]
	if host == nil {
		t.Fatalf("expected host to be tracked")
	}
	if _, ok := host.IPs["192.168.1.50"]; !ok {
		t.Fatalf("expected IP 192.168.1.50 to be recorded; got %+v", host.IPs)
	}
}

func TestParseDHCP(t *testing.T) {
	engine := newTestEngine()
	packet := loadPacket(t, "dhcp.pcap")
	engine.parseDHCP(packet)

	mac := "00:24:d7:12:34:56"
	host := engine.Result.Hosts[mac]
	if host == nil {
		t.Fatalf("expected DHCP client %s to exist", mac)
	}
	if host.DHCPHostname != "lab-ap" {
		t.Fatalf("expected DHCP hostname lab-ap, got %s", host.DHCPHostname)
	}
	if !host.PotentialRogueDHCP {
		t.Fatalf("expected rogue DHCP flag to be raised")
	}

	server := engine.Result.DHCPServers["192.168.1.1"]
	if server == nil {
		t.Fatalf("expected DHCP server record")
	}
	if !server.Suspect {
		t.Fatalf("expected DHCP server to be flagged suspicious")
	}
}

func TestParseMDNS(t *testing.T) {
	engine := newTestEngine()
	packet := loadPacket(t, "mdns.pcap")
	engine.parseMDNS(packet)

	host := engine.Result.Hosts["00:24:d7:12:34:56"]
	if host == nil {
		t.Fatalf("expected mDNS speaker to exist")
	}
	if len(host.LeakedMDNSServices) == 0 {
		t.Fatalf("expected mDNS leak to be recorded")
	}
	found := false
	for _, service := range host.LeakedMDNSServices {
		if service == "macbook._workstation._tcp.local" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected workstation advertisement to be marked as leak, got %v", host.LeakedMDNSServices)
	}
}

func TestParseDNS(t *testing.T) {
	engine := newTestEngine()
	packet := loadPacket(t, "dns.pcap")
	engine.parseDNS(packet)

	host := engine.Result.Hosts["00:24:d7:12:34:56"]
	if host == nil {
		t.Fatalf("expected DNS client to exist")
	}
	if len(host.SuspiciousDNSQueries) != 1 {
		t.Fatalf("expected exactly one suspicious DNS query, got %v", host.SuspiciousDNSQueries)
	}
	if host.SuspiciousDNSQueries[0][:5] != "zz0sd" {
		t.Fatalf("unexpected suspicious DNS record: %v", host.SuspiciousDNSQueries)
	}
}

func TestParseJA3(t *testing.T) {
	engine := newTestEngine()
	packet := loadPacket(t, "ja3.pcap")
	tcpLayer, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		t.Fatalf("fixture missing TCP layer")
	}

	expectedString, err := extractJA3String(tcpLayer.Payload)
	if err != nil {
		t.Fatalf("fixture cannot be parsed: %v", err)
	}
	expectedHash := fmt.Sprintf("%x", md5.Sum([]byte(expectedString)))

	engine.parseJA3(packet)

	host := engine.Result.Hosts["00:24:d7:12:34:56"]
	if host == nil {
		t.Fatalf("expected TLS client host to exist")
	}
	if len(host.JA3Fingerprints) != 1 {
		t.Fatalf("expected JA3 fingerprint to be recorded, got %v", host.JA3Fingerprints)
	}
	if host.JA3Fingerprints[0] != expectedHash {
		t.Fatalf("unexpected JA3 hash, want %s got %s", expectedHash, host.JA3Fingerprints[0])
	}
	if len(host.RareJA3Fingerprints) != 1 {
		t.Fatalf("expected rare JA3 marker")
	}
}

func newTestEngine() *Engine {
	engine := NewEngine()
	engine.Result = NewAnalysisResult()
	return engine
}

func loadPacket(t *testing.T, name string) gopacket.Packet {
	t.Helper()
	path := filepath.Join("testdata", name)
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		t.Fatalf("opening pcap %s: %v", name, err)
	}
	defer handle.Close()

	source := gopacket.NewPacketSource(handle, handle.LinkType())
	packet, err := source.NextPacket()
	if err != nil {
		t.Fatalf("reading packet from %s: %v", name, err)
	}
	return packet
}
