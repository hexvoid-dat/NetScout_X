package scanner

import (
	"fmt"
	"sort"
	"strings"
)

// AnalyzeARP reviews the host list for anomalies that could indicate
// ARP spoofing, misconfigurations, or interesting network topology.
func AnalyzeARP(hosts []Host) []ARPAnomaly {
	if len(hosts) == 0 {
		return nil
	}

	ipToMacs := make(map[string]map[string]struct{})
	macToIPs := make(map[string]map[string]struct{})
	ipToHost := make(map[string]Host)

	for _, host := range hosts {
		if host.IP == "" {
			continue
		}
		ipToHost[host.IP] = host
		mac := normalizeMAC(host.MAC)
		if mac == "" {
			continue
		}

		if _, ok := ipToMacs[host.IP]; !ok {
			ipToMacs[host.IP] = make(map[string]struct{})
		}
		ipToMacs[host.IP][mac] = struct{}{}

		if _, ok := macToIPs[mac]; !ok {
			macToIPs[mac] = make(map[string]struct{})
		}
		macToIPs[mac][host.IP] = struct{}{}
	}

	var anomalies []ARPAnomaly

	// High-severity: IP claimed by multiple MACs (classic spoofing indicator)
	for ip, macSet := range ipToMacs {
		if len(macSet) > 1 {
			macs := sortedKeys(macSet)
			anomalies = append(anomalies, ARPAnomaly{
				Kind:     ARPConflictIP,
				IP:       ip,
				Involved: macs,
				Severity: RiskHigh,
				Message:  fmt.Sprintf("IP %s is claimed by multiple MACs: %v", ip, macs),
			})
		}
	}

	// Medium/Low-severity: MAC claiming multiple IPs (gateway or suspicious)
	for mac, ipSet := range macToIPs {
		if len(ipSet) > 1 {
			ips := sortedKeys(ipSet)
			severity := RiskMedium
			message := fmt.Sprintf("MAC %s is associated with multiple IPs: %v", mac, ips)

			// Downgrade severity if it looks like a gateway
			if isLikelyGateway(ips, ipToHost) {
				severity = RiskLow
				message = fmt.Sprintf("MAC %s acts as a gateway/proxy for %d IPs (e.g., %s)", mac, len(ips), ips[0])
			} else if len(ipSet) > 5 {
				severity = RiskLow // Too many IPs to be a simple MitM, likely infrastructure
			}

			anomalies = append(anomalies, ARPAnomaly{
				Kind:     ARPGreedyMAC,
				MAC:      mac,
				Involved: ips,
				Severity: severity,
				Message:  message,
			})
		}
	}

	return anomalies
}

// isLikelyGateway checks if a set of IPs associated with a single MAC belongs to a gateway device.
func isLikelyGateway(ips []string, ipToHost map[string]Host) bool {
	for _, ip := range ips {
		host, ok := ipToHost[ip]
		if !ok {
			continue
		}
		for _, port := range host.OpenPorts {
			// Common gateway/router service ports
			if (port.Protocol == "udp" && (port.Number == 53 || port.Number == 1900)) ||
				(port.Protocol == "tcp" && (port.Number == 80 || port.Number == 443)) {
				return true
			}
		}
	}
	return false
}

func normalizeMAC(mac string) string {
	normalized := strings.ToLower(strings.TrimSpace(mac))
	if normalized == "" {
		return ""
	}
	replacer := strings.NewReplacer("-", "", ":", "", ".", "")
	stripped := replacer.Replace(normalized)
	if stripped == "" || stripped == "000000000000" || stripped == "ffffffffffff" {
		return ""
	}
	if len(stripped) == 12 {
		var b strings.Builder
		for i := 0; i < len(stripped); i += 2 {
			if b.Len() > 0 {
				b.WriteByte(':')
			}
			b.WriteString(stripped[i : i+2])
		}
		return b.String()
	}
	return stripped
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
