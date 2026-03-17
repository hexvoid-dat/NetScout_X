package report

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/hexe/net-scout/internal/scanner"
)

func RenderConsole(result scanner.ScanResult) {
	fmt.Printf("\n--- Scan Results for subnet %s ---\n", result.Subnet)
	fmt.Printf("Scan finished in %s. Found %d host(s).\n", result.ScanDuration.Round(time.Millisecond), len(result.Hosts))

	if len(result.SecurityWarnings) > 0 {
		fmt.Println("\n!!! SECURITY WARNINGS (ARP) !!!")
		for _, warning := range result.SecurityWarnings {
			fmt.Printf("- %s\n", warning)
		}
	}

	if len(result.Hosts) == 0 {
		return
	}

	fmt.Println("\n--- Detailed Host Report ---")
	for _, host := range result.Hosts {
		fmt.Println("--------------------------------------------------")
		fmt.Printf("HOST: %s (%s)\n", host.IP, host.MAC)
		if host.OSGuess != "" {
			if host.OSConfidence != "" {
				fmt.Printf("  OS (guess): %s [confidence: %s]\n", host.OSGuess, host.OSConfidence)
			} else {
				fmt.Printf("  OS (guess): %s\n", host.OSGuess)
			}
		}

		if host.RiskLevel != "" {
			fmt.Printf("  Risk: %s (%d/100)\n", host.RiskLevel, host.RiskScore)
		}

		if len(host.OpenPorts) == 0 {
			fmt.Println("  Open ports: none detected")
			continue
		}

		fmt.Println("  Open ports:")
		// Tabwriter to zawsze rzeźba w konsoli, żeby kolumny się nie rozjeżdżały.
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

		// Header
		fmt.Fprintln(w, "    PORT\tPROTO\tSERVICE\tDETAILS")

		for _, p := range host.OpenPorts {
			proto := p.Protocol
			if proto == "" {
				proto = "tcp"
			}

			service := p.Service
			if service == "" {
				service = "-"
			}

			details := p.Banner
			if details == "" {
				details = ""
			}

			fmt.Fprintf(w, "    %d\t%s\t%s\t%s\n",
				p.Number,
				strings.ToLower(proto),
				service,
				details,
			)

			if len(p.Vulnerabilities) > 0 {
				for _, v := range p.Vulnerabilities {
					fmt.Fprintf(w, "    \t\t\t[!] VULNERABILITY (%s)\n", v.Severity)
					fmt.Fprintf(w, "    \t\t\t    CVE: %s\n", v.CVE_ID)
					fmt.Fprintf(w, "    \t\t\t    Details: %s\n", v.Description)
				}
			}
		}
		w.Flush()
	}
	fmt.Println("--------------------------------------------------")

	var low, medium, high int
	for _, h := range result.Hosts {
		switch h.RiskLevel {
		case scanner.RiskHigh:
			high++
		case scanner.RiskMedium:
			medium++
		case scanner.RiskLow:
			low++
		}
	}

	fmt.Println("\n=== Security summary ===")
	fmt.Printf("  Hosts scanned: %d\n", len(result.Hosts))
	fmt.Printf("  High risk:   %d\n", high)
	fmt.Printf("  Medium risk: %d\n", medium)
	fmt.Printf("  Low risk:    %d\n", low)

	top := topRiskyHosts(result.Hosts, 3)
	if len(top) > 0 {
		fmt.Println("\n  Top risky hosts:")
		for _, host := range top {
			fmt.Printf("    - %s (risk %d/100, %d open port(s))\n", host.IP, host.RiskScore, len(host.OpenPorts))
		}
	}
}

func SaveJSON(result scanner.ScanResult, filePath string) {
	data, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal JSON: %v", err)
	}

	err = ioutil.WriteFile(filePath, data, 0644)
	if err != nil {
		log.Fatalf("Failed to write JSON file %s: %v", filePath, err)
	}

	log.Printf("Results saved to %s", filePath)
}

// LoadJSON loads a previously saved scan result from disk.
func LoadJSON(filePath string) (scanner.ScanResult, error) {
	var result scanner.ScanResult
	data, err := os.ReadFile(filePath)
	if err != nil {
		return result, err
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return result, err
	}
	return result, nil
}

func topRiskyHosts(hosts []scanner.Host, n int) []scanner.Host {
	if n <= 0 || len(hosts) == 0 {
		return nil
	}

	copyHosts := make([]scanner.Host, len(hosts))
	copy(copyHosts, hosts)

	sort.Slice(copyHosts, func(i, j int) bool {
		return copyHosts[i].RiskScore > copyHosts[j].RiskScore
	})

	if n > len(copyHosts) {
		n = len(copyHosts)
	}

	return copyHosts[:n]
}
