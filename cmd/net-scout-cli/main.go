package main

import (
	"bufio"
	"context" // Added context import
	"fmt"
	"os"
	"os/exec"
	"os/signal" // Import for handling Ctrl+C
	"strconv"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/hexe/net-scout/internal/merge"
	"github.com/hexe/net-scout/internal/passive"
	"github.com/hexe/net-scout/internal/report"
	"github.com/hexe/net-scout/internal/scanner"
)

var (
	enableUDPScan bool
	skipPause     bool
)

func main() {
	// Default fingerprint configuration for interactive mode
	scanner.ConfigureFingerprint(scanner.FingerprintOptions{
		DisableTTL:      false,
		TTLOnlyWithSudo: false,
	})

	enableUDPScan = false

	showLogo()
	showWelcome()

	for {
		showMainMenu()
		choice := getUserChoice()

		switch choice {
		case 1:
			runActiveScan(true)
		case 2:
			runActiveScan(false)
		case 3:
			runTests()
		case 4:
			showHelp()
		case 5:
			showAbout()
		case 6:
			fmt.Println("\nThanks for using NetScoutX!")
			os.Exit(0)
		case 7:
			showSettings()
		case 8:
			runPassiveScan()
		default:
			fmt.Println("Invalid option. Please try again.")
		}

		fmt.Println("\n" + strings.Repeat("=", 60))
		if skipPause {
			skipPause = false
		} else {
			pressEnterToContinue()
		}
	}
}

func showLogo() {
	logo := `
_   _      _   ____                  _  __  __
 | \ | | ___| |_/ ___|  ___ ___  _   _| |_ \ \/ /
 |  \| |/ _ \ __\___ \ / __/ _ \| | | | __| \  / 
 | |\  |  __/ |_ ___) | (_| (_) | |_| | |_ /  \ 
 |_| \_|\___|\__|____/ \___\___/ \__,_|\__/_/\_\
`
	fmt.Println(logo)
}

func showWelcome() {
	fmt.Println("Welcome to NetScoutX!")
	fmt.Println("   Scan your network, enumerate hosts, and highlight security risks.")
	fmt.Println("   Choose an option from the menu below:")
	fmt.Println()
}

func showMainMenu() {
	fmt.Println("MAIN MENU")
	fmt.Println("  1) Quick scan (auto-detect subnet, includes passive analysis)")
	fmt.Println("  2) Custom scan (enter CIDR, includes passive analysis)")
	fmt.Println("  3) Run tests (Docker required)")
	fmt.Println("  4) Help")
	fmt.Println("  5) About")
	fmt.Println("  6) Exit")
	fmt.Println("  7) Settings (TTL / OS fingerprint / UDP)")
	fmt.Println("  8) Passive scan (listen only, no packets sent)")
}

func getUserChoice() int {
	fmt.Print("Choose an option (1-8): ")
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)

	choice, err := strconv.Atoi(input)
	if err != nil {
		return -1
	}
	return choice
}

func quickScan() {
	runActiveScan(true)
}

func customScan() {
	runActiveScan(false)
}

func runTests() {
	fmt.Println("\nRUNNING TESTS")
	fmt.Println("Checking if Docker is available...")

	if !isDockerAvailable() {
		fmt.Println("Docker is not available!")
		fmt.Println("   Install and start Docker to run the E2E tests.")
		return
	}

	fmt.Println("Docker detected")
	fmt.Println("Launching E2E test suite...")
	fmt.Println("   This might take a few minutes.")

	cmd := exec.Command("./run_e2e_tests.sh")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		fmt.Println("Tests failed. Verify Docker is running and you have permissions.")
	} else {
		fmt.Println("All tests passed!")
	}
}

func showHelp() {
	fmt.Println("\nHELP")
	fmt.Println("  Quick scan  - auto-detects your local subnet and performs a fast sweep, including passive analysis.")
	fmt.Println("  Custom scan - lets you provide any subnet in CIDR notation and optional JSON export, including passive analysis.")
	fmt.Println("  Passive scan - listens for network traffic without sending any packets, ideal for stealthy monitoring.")
	fmt.Println("  Features    - host discovery, port scanning, banner grabbing, CVE lookups, ARP anomaly checks, DHCP/DNS/mDNS/TLS passive analysis.")
	fmt.Println("  Reminder    - only scan networks you own or have permission to assess. Passive mode may still require elevated privileges to capture traffic.")
}

func showAbout() {
	fmt.Println("\nABOUT")
	fmt.Println("  NetScoutX - advanced network scanner and passive analysis tool written in Go.")
	fmt.Println("  Highlights: active host discovery, port scanning with banners, CVE hints, ARP spoofing checks, OS guessing, DHCP/DNS/mDNS/TLS passive analysis, JA3 fingerprinting, JSON/console reports.")
	fmt.Println("  Author: h.exe | Version: 3.0 | License: MIT")
	fmt.Println("  Docs: README.md (quick start), howtouse.md (walkthrough), INSTALL.md (requirements).")
}

func runPassiveScan() {
	fmt.Println("\nPASSIVE SCAN")
	fmt.Println("Starting passive network analysis. This will run until you stop it (Ctrl+C).")
	fmt.Println("Listening for ARP, DHCP, mDNS, DNS, and TLS fingerprints...")

	passiveEngine := passive.NewEngine() // Sniff on all available interfaces
	passiveEngine.Start()

	fmt.Println("Capture started. Press Ctrl+C to stop and see results.")
	// Wait for interrupt signal
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c
	signal.Stop(c)
	passiveEngine.Stop()

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("PASSIVE SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 60))
	printPassiveSummary(passiveEngine.Result)
	printHostOverviewTable(passiveHostsAsScannerHosts(passiveEngine.Result))
	pressEnterToContinue()
	skipPause = true
}

func runActiveScan(isQuick bool) {
	var subnet, outputFile, baselineFile string
	if isQuick {
		fmt.Println("\nQUICK SCAN")
		fmt.Println("Attempting to detect your local subnet...")
		s, err := scanner.DetectLocalSubnet()
		if err != nil {
			fmt.Printf("Warning: Could not auto-detect a subnet: %v\n", err)
			s = promptForSubnet()
			if s == "" {
				fmt.Println("Scan cancelled.")
				return
			}
		}
		subnet = s
		outputFile = fmt.Sprintf("quick_scan_%s.json", time.Now().Format("20060102_150405"))
		fmt.Printf("Using detected subnet: %s\n", subnet)
		fmt.Printf("Results will be saved to %s\n", outputFile)
		baselineFile = promptForBaseline()
	} else {
		fmt.Println("\nCUSTOM SCAN")
		fmt.Println("Examples of networks to scan:")
		fmt.Println("  - 192.168.1.0/24  (home network)")
		fmt.Println("  - 192.168.0.0/24  (alternate home network)")
		fmt.Println("  - 10.0.0.0/24     (corporate network)")
		fmt.Println("  - 172.16.0.0/24   (lab/VPN network)")
		fmt.Println()

		subnet = promptForSubnet()
		if subnet == "" {
			fmt.Println("No subnet provided. Scan cancelled.")
			return
		}

		outputFile = promptForOutputFile()
		baselineFile = promptForBaseline()
	}

	fmt.Printf("\nStarting scan for subnet: %s\n", subnet)
	fmt.Println("Passive analysis will run in parallel for 10 seconds...")
	startTime := time.Now()

	// 1. Start passive engine in the background
	passiveEngine := passive.NewEngine()
	passiveEngine.Start()
	// Give passive engine some time to collect data
	passiveCollectionDuration := 10 * time.Second
	passiveCollectionCtx, passiveCollectionCancel := context.WithTimeout(context.Background(), passiveCollectionDuration)
	defer passiveCollectionCancel()

	// Use a channel to signal when active scan is done
	activeScanDone := make(chan struct{})

	var activeHosts []scanner.Host
	var activeScanErr error

	go func() {
		defer close(activeScanDone)
		ctx := context.Background()

		// Host discovery phase
		log.Printf("Starting active host discovery on %s", subnet)
		activeHosts, activeScanErr = scanner.DiscoverHosts(subnet)
		if activeScanErr != nil {
			log.Printf("Error: Host discovery failed: %v", activeScanErr)
			return
		}

		// Active scanning pipeline
		log.Printf("Discovered %d hosts. Enriching with ARP data...", len(activeHosts))
		activeHosts, _, _ = scanner.EnrichHostsWithARP(activeHosts, subnet)

		log.Println("Scanning ports and services...")
		scanner.PortScanner(ctx, activeHosts)
		if enableUDPScan {
			log.Println("Executing UDP service discovery...")
			scanner.UdpScanner(activeHosts)
		}
		
		log.Println("Fingerprinting services and OS...")
		scanner.FingerprintServices(activeHosts)
		runOSFingerprinting(activeHosts)
	}()

	// Wait for either passive collection timeout or active scan completion
	select {
	case <-passiveCollectionCtx.Done():
		log.Println("Passive collection window closed.")
	case <-activeScanDone:
		log.Println("Active scan phase completed.")
	}

	// Ensure passive engine is stopped after active scan or timeout
	passiveEngine.Stop()

	if activeScanErr != nil {
		return 
	}

	// Data normalization and merging
	log.Println("Merging active and passive results...")
	mergedHosts := merge.MergeResults(activeHosts, passiveEngine.Result)

	// Final risk evaluation and anomaly detection
	log.Println("Analyzing network security state...")
	anomalies := scanner.AnalyzeARP(mergedHosts)
	hostMap := make(map[string]*scanner.Host)
	for i := range mergedHosts {
		hostMap[mergedHosts[i].IP] = &mergedHosts[i]
	}
	var warnings []string
	for _, anomaly := range anomalies {
		warnings = append(warnings, anomaly.Message)
		if anomaly.IP != "" {
			if host, ok := hostMap[anomaly.IP]; ok {
				host.Anomalies = append(host.Anomalies, anomaly)
				host.ARPFlags = append(host.ARPFlags, string(anomaly.Kind))
			}
		}
	}
	for i := range mergedHosts {
		scanner.EvaluateRisk(&mergedHosts[i])
	}

	scanDuration := time.Since(startTime)
	result := scanner.ScanResult{
		Timestamp:        startTime,
		Subnet:           subnet,
		Hosts:            mergedHosts,
		ScanDuration:     scanDuration,
		SecurityWarnings: warnings,
	}

	// --- Reporting ---
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("SCAN RESULTS")
	fmt.Println(strings.Repeat("=", 60))

	if len(warnings) > 0 {
		fmt.Println("\nGENERAL WARNINGS:")
		for _, warning := range warnings {
			fmt.Printf("   - %s\n", warning)
		}
	}

	fmt.Printf("\nACTIVE SCAN SUMMARY:\n")
	fmt.Printf("   - Actively probed hosts: %d\n", len(activeHosts))
	fmt.Printf("   - Scan duration: %s\n", scanDuration.Round(time.Millisecond))

	printPassiveSummary(passiveEngine.Result)
	printHostOverviewTable(mergedHosts)

	if outputFile != "" {
		report.SaveJSON(result, outputFile)
	} else {
		report.RenderConsole(result)
	}
	if baselineFile != "" {
		baseline, err := report.LoadJSON(baselineFile)
		if err != nil {
			fmt.Printf("Could not load baseline report (%v). Continuing without diff.\n", err)
		} else {
			diff := report.ComputeScanDiff(baseline, result)
			report.RenderDiff(diff)
		}
	}
}

func promptForSubnet() string {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter subnet in CIDR format (e.g. 192.168.1.0/24): ")
	subnet, _ := reader.ReadString('\n')
	return strings.TrimSpace(subnet)
}

func promptForBaseline() string {
	fmt.Print("Compare with previous JSON report? (y/N): ")
	response := ""
	fmt.Scanln(&response) // Use Scanln for simplicity in CLI
	response = strings.TrimSpace(strings.ToLower(response))
	if response != "y" && response != "yes" {
		return ""
	}
	fmt.Print("Path to baseline JSON file: ")
	path := ""
	fmt.Scanln(&path) // Use Scanln for simplicity in CLI
	return strings.TrimSpace(path)
}

func promptForOutputFile() string {
	fmt.Print("Save results to a JSON file? (y/n): ")
	saveChoice := ""
	fmt.Scanln(&saveChoice) // Use Scanln for simplicity in CLI
	saveChoice = strings.TrimSpace(strings.ToLower(saveChoice))

	if saveChoice != "y" && saveChoice != "yes" {
		return ""
	}

	defaultName := "report_" + time.Now().Format("20060102_150405") + ".json"
	fmt.Printf("File name (default %s): ", defaultName)
	fileName := ""
	fmt.Scanln(&fileName) // Use Scanln for simplicity in CLI
	if fileName == "" {
		return defaultName
	}
	return fileName
}

func isDockerAvailable() bool {
	cmd := exec.Command("docker", "--version")
	err := cmd.Run()
	return err == nil
}

func pressEnterToContinue() {
	fmt.Print("Press Enter to continue...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

func runOSFingerprinting(hosts []scanner.Host) {
	var wg sync.WaitGroup
	for i := range hosts {
		wg.Add(1)
		go func(host *scanner.Host) {
			defer wg.Done()
			scanner.GuessOS(host)
		}(&hosts[i])
	}
	wg.Wait()
}

func showSettings() {
	for {
		opts := scanner.GetFingerprintOptions()

		fmt.Println("\nSETTINGS")
		fmt.Println("  1) Toggle TTL fingerprinting (DisableTTL =", opts.DisableTTL, ")")
		fmt.Println("  2) Toggle 'TTL only with sudo' (TTLOnlyWithSudo =", opts.TTLOnlyWithSudo, ")")
		fmt.Println("  3) Toggle UDP scanning (EnableUDP =", enableUDPScan, ")")
		fmt.Println("  4) Reset to defaults")
		fmt.Println("  5) Back")

		choice := getUserChoice()

		switch choice {
		case 1:
			opts.DisableTTL = !opts.DisableTTL
			scanner.ConfigureFingerprint(opts)
			fmt.Println("DisableTTL set to:", opts.DisableTTL)
		case 2:
			opts.TTLOnlyWithSudo = !opts.TTLOnlyWithSudo
			scanner.ConfigureFingerprint(opts)
			fmt.Println("TTLOnlyWithSudo set to:", opts.TTLOnlyWithSudo)
		case 3:
			enableUDPScan = !enableUDPScan
			fmt.Println("EnableUDP set to:", enableUDPScan)
		case 4:
			scanner.ConfigureFingerprint(scanner.FingerprintOptions{
				DisableTTL:      false,
				TTLOnlyWithSudo: false,
			})
			enableUDPScan = false
			fmt.Println("Settings restored to defaults.")
		case 5:
			return
		default:
			fmt.Println("Invalid option. Please try again.")
		}
	}
}

func printPassiveSummary(result *passive.AnalysisResult) {
	stats := summarizePassiveResult(result)
	fmt.Println("\nPASSIVE DISCOVERY SUMMARY:")
	fmt.Printf("   - Passively discovered hosts: %d\n", stats.HostCount)
	fmt.Printf("   - DHCP servers observed: %d (suspect: %d)\n", stats.DHCPServers, stats.SuspectDHCPServers)
	fmt.Printf("   - Suspicious DNS queries: %d across %d host(s)\n", stats.SuspiciousDNSQueries, stats.SuspiciousDNSHosts)
	fmt.Printf("   - mDNS leaks: %d sensitive advert(s) across %d host(s)\n", stats.MDNSLeakCount, stats.MDNSLeakHosts)
	fmt.Printf("   - JA3 fingerprints: %d total (%d flagged rare)\n", stats.JA3Total, stats.JA3Rare)
}

type passiveSummary struct {
	HostCount            int
	DHCPServers          int
	SuspectDHCPServers   int
	SuspiciousDNSQueries int
	SuspiciousDNSHosts   int
	MDNSLeakCount        int
	MDNSLeakHosts        int
	JA3Total             int
	JA3Rare              int
}

func summarizePassiveResult(result *passive.AnalysisResult) passiveSummary {
	stats := passiveSummary{
		HostCount:   len(result.Hosts),
		DHCPServers: len(result.DHCPServers),
	}

	for _, server := range result.DHCPServers {
		if server.Suspect {
			stats.SuspectDHCPServers++
		}
	}

	for _, host := range result.Hosts {
		stats.JA3Total += len(host.JA3Fingerprints)
		stats.JA3Rare += len(host.RareJA3Fingerprints)
		stats.SuspiciousDNSQueries += len(host.SuspiciousDNSQueries)
		stats.MDNSLeakCount += len(host.LeakedMDNSServices)
		if len(host.SuspiciousDNSQueries) > 0 {
			stats.SuspiciousDNSHosts++
		}
		if len(host.LeakedMDNSServices) > 0 {
			stats.MDNSLeakHosts++
		}
	}
	return stats
}

func passiveHostsAsScannerHosts(result *passive.AnalysisResult) []scanner.Host {
	hosts := make([]scanner.Host, 0, len(result.Hosts))
	for _, ph := range result.Hosts {
		var ip string
		for k := range ph.IPs {
			ip = k
			break
		}
		hosts = append(hosts, scanner.Host{
			IP:                   ip,
			MAC:                  ph.MAC,
			Hostname:             ph.DHCPHostname,
			JA3Fingerprints:      append([]string{}, ph.JA3Fingerprints...),
			RareJA3Fingerprints:  append([]string{}, ph.RareJA3Fingerprints...),
			DNSQueries:           append([]string{}, ph.DNSQueries...),
			SuspiciousDNSQueries: append([]string{}, ph.SuspiciousDNSQueries...),
			LeakedMDNSServices:   append([]string{}, ph.LeakedMDNSServices...),
			PotentialRogueDHCP:   ph.PotentialRogueDHCP,
			PassivelyDiscovered:  true,
		})
	}
	return hosts
}

func printHostOverviewTable(hosts []scanner.Host) {
	if len(hosts) == 0 {
		return
	}

	fmt.Println("\nHOST OVERVIEW:")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "IP\tMAC\tVENDOR\tHOSTNAME\tRISK\tJA3s\tOPEN PORTS")

	for _, h := range hosts {
		var ports []string
		for _, p := range h.OpenPorts {
			ports = append(ports, fmt.Sprintf("%d/%s", p.Number, p.Protocol))
		}

		hostname := h.Hostname
		if hostname == "" {
			hostname = "-"
		}
		// Need to get vendor from MAC
		vendor := passive.GetVendorFromMAC(h.MAC)
		if vendor == "" {
			vendor = "-"
		}

		riskText := fmt.Sprintf("%s (%d)", h.RiskLevel, h.RiskScore)

		fmt.Fprintf(
			w,
			"%s\t%s\t%s\t%s\t%s\t%d\t%s\n",
			h.IP,
			h.MAC,
			vendor,
			hostname,
			riskText,
			len(h.JA3Fingerprints),
			strings.Join(ports, ", "),
		)
	}
	w.Flush()
}
