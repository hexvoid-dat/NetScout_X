package merge

import (
	"github.com/hexe/net-scout/internal/passive"
	"github.com/hexe/net-scout/internal/scanner"
)

// MergeResults combines the results from the passive analysis engine
// with the results from the active scanner.
func MergeResults(activeHosts []scanner.Host, passiveResult *passive.AnalysisResult) []scanner.Host {
	activeHostMap := make(map[string]*scanner.Host)
	for i := range activeHosts {
		activeHostMap[activeHosts[i].IP] = &activeHosts[i]
	}

	macToActiveHost := make(map[string]*scanner.Host)
	for i, host := range activeHosts {
		if host.MAC != "" && host.MAC != "00:00:00:00:00:00" {
			macToActiveHost[host.MAC] = &activeHosts[i]
		}
	}

	for mac, passiveHost := range passiveResult.Hosts {
		// Find an existing active host by MAC
		activeHost, foundByMac := macToActiveHost[mac]

		// Or find by one of the IPs
		if !foundByMac {
			for ip := range passiveHost.IPs {
				if host, foundByIp := activeHostMap[ip]; foundByIp {
					activeHost = host
					foundByMac = true // Treat as found
					break
				}
			}
		}

		if activeHost != nil {
			// Enrich existing host
			if activeHost.MAC == "" || activeHost.MAC == "00:00:00:00:00:00" {
				activeHost.MAC = passiveHost.MAC
			}
			if activeHost.Hostname == "" {
				activeHost.Hostname = passiveHost.DHCPHostname
			}
			// Add JA3 fingerprints
			activeHost.JA3Fingerprints = mergeStringSlices(activeHost.JA3Fingerprints, passiveHost.JA3Fingerprints)
			activeHost.RareJA3Fingerprints = mergeStringSlices(activeHost.RareJA3Fingerprints, passiveHost.RareJA3Fingerprints)
			// Add DNS queries
			activeHost.DNSQueries = mergeStringSlices(activeHost.DNSQueries, passiveHost.DNSQueries)
			activeHost.SuspiciousDNSQueries = mergeStringSlices(activeHost.SuspiciousDNSQueries, passiveHost.SuspiciousDNSQueries)
			activeHost.LeakedMDNSServices = mergeStringSlices(activeHost.LeakedMDNSServices, passiveHost.LeakedMDNSServices)
			if passiveHost.PotentialRogueDHCP {
				activeHost.PotentialRogueDHCP = true
			}
		} else {
			// Create a new host from passive data
			var primaryIP string
			for ip := range passiveHost.IPs {
				primaryIP = ip // take the first one
				break
			}
			if primaryIP == "" {
				continue
			}

			newHost := scanner.Host{
				IP:                   primaryIP,
				MAC:                  passiveHost.MAC,
				Hostname:             passiveHost.DHCPHostname,
				JA3Fingerprints:      append([]string{}, passiveHost.JA3Fingerprints...),
				RareJA3Fingerprints:  append([]string{}, passiveHost.RareJA3Fingerprints...),
				DNSQueries:           append([]string{}, passiveHost.DNSQueries...),
				SuspiciousDNSQueries: append([]string{}, passiveHost.SuspiciousDNSQueries...),
				LeakedMDNSServices:   append([]string{}, passiveHost.LeakedMDNSServices...),
				PotentialRogueDHCP:   passiveHost.PotentialRogueDHCP,
				PassivelyDiscovered:  true,
			}
			activeHosts = append(activeHosts, newHost)
		}
	}

	return activeHosts
}

func mergeStringSlices(base, additions []string) []string {
	for _, val := range additions {
		exists := false
		for _, existing := range base {
			if existing == val {
				exists = true
				break
			}
		}
		if !exists {
			base = append(base, val)
		}
	}
	return base
}
