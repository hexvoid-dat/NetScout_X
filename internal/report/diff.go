package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hexe/net-scout/internal/scanner"
)

type HostSummary struct {
	IP  string `json:"ip"`
	MAC string `json:"mac,omitempty"`
}

type PortChange struct {
	IP           string   `json:"ip"`
	NewlyOpen    []string `json:"newly_open"`
	NoLongerOpen []string `json:"no_longer_open"`
}

type ScanDiff struct {
	NewHosts     []HostSummary `json:"new_hosts"`
	MissingHosts []HostSummary `json:"missing_hosts"`
	PortChanges  []PortChange  `json:"port_changes"`
}

// ComputeScanDiff compares two scan results and returns a high-level summary of the differences.
func ComputeScanDiff(oldRes, newRes scanner.ScanResult) ScanDiff {
	oldHosts := make(map[string]scanner.Host)
	for _, host := range oldRes.Hosts {
		oldHosts[host.IP] = host
	}

	newHosts := make(map[string]scanner.Host)
	for _, host := range newRes.Hosts {
		newHosts[host.IP] = host
	}

	var diff ScanDiff

	for ip, host := range newHosts {
		if _, found := oldHosts[ip]; !found {
			diff.NewHosts = append(diff.NewHosts, HostSummary{IP: host.IP, MAC: host.MAC})
		}
	}

	for ip, host := range oldHosts {
		if _, found := newHosts[ip]; !found {
			diff.MissingHosts = append(diff.MissingHosts, HostSummary{IP: host.IP, MAC: host.MAC})
		}
	}

	for ip, newHost := range newHosts {
		if oldHost, found := oldHosts[ip]; found {
			newPorts := openPortSet(newHost)
			oldPorts := openPortSet(oldHost)

			newlyOpen := difference(newPorts, oldPorts)
			closed := difference(oldPorts, newPorts)

			if len(newlyOpen) > 0 || len(closed) > 0 {
				sort.Strings(newlyOpen)
				sort.Strings(closed)
				diff.PortChanges = append(diff.PortChanges, PortChange{
					IP:           ip,
					NewlyOpen:    newlyOpen,
					NoLongerOpen: closed,
				})
			}
		}
	}

	sort.Slice(diff.NewHosts, func(i, j int) bool {
		return diff.NewHosts[i].IP < diff.NewHosts[j].IP
	})
	sort.Slice(diff.MissingHosts, func(i, j int) bool {
		return diff.MissingHosts[i].IP < diff.MissingHosts[j].IP
	})
	sort.Slice(diff.PortChanges, func(i, j int) bool {
		return diff.PortChanges[i].IP < diff.PortChanges[j].IP
	})

	return diff
}

func openPortSet(host scanner.Host) map[string]struct{} {
	set := make(map[string]struct{})
	for _, port := range host.OpenPorts {
		if port.State != scanner.StateOpen {
			continue
		}
		proto := port.Protocol
		if proto == "" {
			proto = "tcp"
		}
		key := fmt.Sprintf("%d/%s", port.Number, strings.ToLower(proto))
		set[key] = struct{}{}
	}
	return set
}

func difference(a, b map[string]struct{}) []string {
	var result []string
	for key := range a {
		if _, found := b[key]; !found {
			result = append(result, key)
		}
	}
	return result
}

// RenderDiff prints a concise summary of baseline differences.
func RenderDiff(diff ScanDiff) {
	if len(diff.NewHosts) == 0 && len(diff.MissingHosts) == 0 && len(diff.PortChanges) == 0 {
		fmt.Println("\n=== Baseline diff ===")
		fmt.Println("No differences detected.")
		return
	}

	fmt.Println("\n=== Baseline diff ===")

	if len(diff.NewHosts) > 0 {
		fmt.Println("New hosts:")
		for _, host := range diff.NewHosts {
			if host.MAC != "" {
				fmt.Printf("  - %s (%s)\n", host.IP, host.MAC)
			} else {
				fmt.Printf("  - %s\n", host.IP)
			}
		}
	}

	if len(diff.MissingHosts) > 0 {
		fmt.Println("Missing hosts:")
		for _, host := range diff.MissingHosts {
			if host.MAC != "" {
				fmt.Printf("  - %s (%s)\n", host.IP, host.MAC)
			} else {
				fmt.Printf("  - %s\n", host.IP)
			}
		}
	}

	if len(diff.PortChanges) > 0 {
		fmt.Println("Port changes:")
		for _, change := range diff.PortChanges {
			var details []string
			for _, port := range change.NewlyOpen {
				details = append(details, "+"+port)
			}
			for _, port := range change.NoLongerOpen {
				details = append(details, "-"+port)
			}
			fmt.Printf("  - %s: %s\n", change.IP, strings.Join(details, ", "))
		}
	}
}
