package scanner

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

// FingerprintServices attempts to identify service versions for common ports.
func FingerprintServices(hosts []Host) {
	for i := range hosts {
		host := &hosts[i]
		for j := range host.OpenPorts {
			port := &host.OpenPorts[j]
			if port.State != StateOpen {
				continue
			}

			// Skip if we already have version info (e.g., from a banner grab)
			if port.Version != "" {
				continue
			}

			address := net.JoinHostPort(host.IP, fmt.Sprintf("%d", port.Number))
			var version string

			switch port.Number {
			case 22: // SSH
				version = fingerprintSSH(address)
			case 80, 443, 8080: // HTTP/S
				version = fingerprintHTTP(address)
			case 21: // FTP
				version = fingerprintFTP(address)
			case 23: // Telnet
				port.Service = "Telnet" // Just identifying is a risk
			}

			if version != "" {
				port.Version = version
			}
		}
	}
}

func fingerprintSSH(address string) string {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// SSH servers send a banner immediately upon connection.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}

	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "SSH-") {
		return line
	}
	return ""
}

func fingerprintHTTP(address string) string {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// Send a simple HEAD request.
	req := "HEAD / HTTP/1.1\r\nHost: " + address + "\r\nUser-Agent: NetScoutX/1.0\r\n\r\n"
	_, err = conn.Write([]byte(req))
	if err != nil {
		return ""
	}

	// Read the response headers.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(strings.ToLower(line), "server:") {
			return strings.TrimSpace(line[len("server:"):])
		}
		if line == "" { // End of headers
			break
		}
	}
	return ""
}

func fingerprintFTP(address string) string {
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		return ""
	}
	defer conn.Close()

	// FTP servers send a banner immediately.
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}

	line = strings.TrimSpace(line)
	// Example: "220 (vsFTPd 3.0.3)"
	if strings.HasPrefix(line, "220") {
		return line
	}
	return ""
}
