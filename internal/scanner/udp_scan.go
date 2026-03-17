package scanner

import (
	"net"
	"time"
)

var udpWellKnownServices = map[int]string{
	53:   "DNS",
	123:  "NTP",
	161:  "SNMP",
	1900: "SSDP/UPnP",
	5353: "mDNS",
}

var defaultUDPPorts = []int{53, 123, 161, 1900, 5353}

// UdpScanner performs a lightweight UDP probe on a small set of well-known ports
// for each host. Results are appended to Host.OpenPorts with Protocol = "udp".
func UdpScanner(hosts []Host) {
	if len(hosts) == 0 {
		return
	}

	for i := range hosts {
		scanUDPForHost(&hosts[i], defaultUDPPorts)
	}
}

func scanUDPForHost(host *Host, ports []int) {
	ip := net.ParseIP(host.IP)
	if ip == nil {
		return
	}

	timeout := 2 * time.Second

	for _, port := range ports {
		addr := &net.UDPAddr{IP: ip, Port: port}
		conn, err := net.DialUDP("udp", nil, addr)
		if err != nil {
			continue
		}

		_ = conn.SetDeadline(time.Now().Add(timeout))

		// Best-effort probe: tiny payload that many services will ignore or at least not error on immediately.
		_, writeErr := conn.Write([]byte("NSX"))
		if writeErr != nil {
			conn.Close()
			continue
		}

		// Non-blocking read with deadline, just to see if anything comes back.
		buf := make([]byte, 512)
		_, _, _ = conn.ReadFrom(buf) // ignore result; UDP is messy and often silent

		conn.Close()

		// At this point we at least know there was no immediate fatal error on send.
		serviceName := ""
		if name, ok := udpWellKnownServices[port]; ok {
			serviceName = name
		}

		host.OpenPorts = append(host.OpenPorts, Port{
			Number:   port,
			Protocol: "udp",
			State:    StateOpen,
			Service:  serviceName,
			// We intentionally leave Service/Banner empty for now; future versions can decode protocol-specific responses.
		})
	}
}
