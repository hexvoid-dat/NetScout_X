package scanner

import "strings"

// EvaluateRisk performs a heuristic risk assessment for a given host.
// Ten scoring jest mocno subiektywny, ale daje jako taki pogląd na to, co się dzieje w sieci.
func EvaluateRisk(host *Host) {
	score := 0

	// Base risk for connectivity surface area
	score += len(host.OpenPorts) * 2

	// Risk from detected network anomalies (e.g. ARP spoofing indicators)
	for _, anomaly := range host.Anomalies {
		switch anomaly.Severity {
		case RiskHigh:
			score += 25
		case RiskMedium:
			score += 10
		}
	}

	// Passive observation signals
	if host.PassivelyDiscovered {
		score += 5
	}
	if len(host.RareJA3Fingerprints) > 0 {
		score += 12 + min((len(host.RareJA3Fingerprints)-1)*3, 8)
	} else if len(host.JA3Fingerprints) > 0 {
		score += 3
	}
	if len(host.SuspiciousDNSQueries) > 0 {
		score += 10 + min((len(host.SuspiciousDNSQueries)-1)*2, 10)
	} else if len(host.DNSQueries) > 0 {
		score += 3
	}
	if len(host.LeakedMDNSServices) > 0 {
		score += 8 + min((len(host.LeakedMDNSServices)-1)*2, 10)
	}
	if host.PotentialRogueDHCP {
		score += 20
	}

	var hasHTTP, hasHTTPS bool

	for _, port := range host.OpenPorts {
		// Critical vulnerabilities detected by signature matching
		for _, vuln := range port.Vulnerabilities {
			switch strings.ToUpper(vuln.Severity) {
			case "CRITICAL":
				score += 25
			case "HIGH":
				score += 15
			case "MEDIUM":
				score += 8
			default:
				score += 5
			}
		}

		proto := strings.ToLower(port.Protocol)
		if proto == "" || proto == "tcp" {
			switch port.Number {
			case 21: // FTP (plain text auth)
				score += 8
			case 22: // SSH
				score += 5
			case 23: // Telnet (highly insecure)
				score += 20
			case 445, 139: // SMB (potential lateral movement vector)
				score += 15
			case 3389: // RDP
				score += 15
			case 80:
				hasHTTP = true
			case 443:
				hasHTTPS = true
			}
		}

		if proto == "udp" {
			switch port.Number {
			case 161: // SNMP
				score += 10
			case 1900: // SSDP
				score += 8
			}
		}

		if port.Version != "" {
			score += 2
		}
	}

	// Risk for unencrypted web services exposed
	if hasHTTP && !hasHTTPS {
		score += 10
	}

	// Clamp the score between 0 and 100
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	host.RiskScore = score
	host.RiskLevel = classifyRisk(score)
}

func classifyRisk(score int) RiskLevel {
	if score >= 70 {
		return RiskHigh
	}
	if score >= 30 {
		return RiskMedium
	}
	return RiskLow
}

