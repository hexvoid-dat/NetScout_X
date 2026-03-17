package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/hexe/net-scout/internal/merge"
	"github.com/hexe/net-scout/internal/passive"
	"github.com/hexe/net-scout/internal/report"
	"github.com/hexe/net-scout/internal/scanner"
)

func main() {
	subnet := flag.String("subnet", "", "Subnet to scan in CIDR notation (e.g. 192.168.1.0/24)")
	outputFile := flag.String("output", "", "Optional path to a JSON report file")
	disableTTL := flag.Bool("disable-ttl", false, "Disable TTL-based OS fingerprinting")
	ttlOnlyWithSudo := flag.Bool("ttl-only-with-sudo", false, "Only run TTL-based OS fingerprinting when running as root")
	baselineFile := flag.String("baseline", "", "Optional path to a previous JSON report to diff against")
	enableUDP := flag.Bool("enable-udp", false, "Enable UDP scanning on a small set of common ports (53, 123, 5353, 1900)")
	passiveDuration := flag.Duration("passive-duration", 0, "Duration for passive collection (e.g., 30s, 1m). Set to 0 to disable.")
	flag.Parse()

	scanner.ConfigureFingerprint(scanner.FingerprintOptions{
		DisableTTL:      *disableTTL,
		TTLOnlyWithSudo: *ttlOnlyWithSudo,
	})

	if *subnet == "" {
		fmt.Println("Error: the -subnet flag is required.")
		flag.Usage()
		os.Exit(1)
	}

	startTime := time.Now()
	log.Printf("Initializing scan at %s", startTime.Format(time.RFC3339))
	ctx := context.Background()

	var passiveEngine *passive.Engine
	if *passiveDuration > 0 {
		log.Printf("Starting passive collection (duration: %s)", *passiveDuration)
		passiveEngine = passive.NewEngine()
		passiveEngine.Start()
		defer passiveEngine.Stop()
	}

	// Discover active hosts
	log.Printf("Scanning subnet: %s", *subnet)
	activeHosts, err := scanner.DiscoverHosts(*subnet)
	if err != nil {
		log.Fatalf("Fatal: host discovery failed: %v", err)
	}

	if len(activeHosts) == 0 {
		log.Println("No active hosts discovered. Terminating.")
		if passiveEngine != nil {
			time.Sleep(*passiveDuration)
		}
		return
	}

	// ARP enrichment if applicable
	log.Printf("Found %d active hosts. Enriching with ARP data...", len(activeHosts))
	arpEnrichedHosts, _, arpActive := scanner.EnrichHostsWithARP(activeHosts, *subnet)
	if arpActive {
		activeHosts = arpEnrichedHosts
		log.Printf("ARP enrichment finished (active hosts: %d)", len(activeHosts))
	}

	// Security heuristic analysis
	log.Println("Executing security analysis...")
	anomalies := scanner.AnalyzeARP(activeHosts)
	hostMap := make(map[string]*scanner.Host)
	for i := range activeHosts {
		hostMap[activeHosts[i].IP] = &activeHosts[i]
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

	// Active scanning (Ports, OS, Services)
	log.Println("Starting active service discovery...")
	scanner.PortScanner(ctx, activeHosts)
	runOSFingerprinting(activeHosts)

	if *enableUDP {
		log.Println("Running UDP scan subset...")
		scanner.UdpScanner(activeHosts)
	}

	log.Println("Performing service fingerprinting...")
	scanner.FingerprintServices(activeHosts)

	// Finalize passive collection
	if passiveEngine != nil {
		remaining := *passiveDuration - time.Since(startTime)
		if remaining > 0 {
			log.Printf("Waiting for passive data collection to complete (%s remaining)...", remaining.Round(time.Second))
			time.Sleep(remaining)
		}
		log.Println("Merging passive and active scan results...")
		activeHosts = merge.MergeResults(activeHosts, passiveEngine.Result)
	}

	// Risk evaluation
	log.Println("Computing risk scores...")
	for i := range activeHosts {
		scanner.EvaluateRisk(&activeHosts[i])
	}

	scanDuration := time.Since(startTime)

	finalResult := scanner.ScanResult{
		Timestamp:        startTime,
		Subnet:           *subnet,
		Hosts:            activeHosts,
		ScanDuration:     scanDuration,
		SecurityWarnings: warnings,
	}

	if *outputFile != "" {
		report.SaveJSON(finalResult, *outputFile)
		log.Printf("Report saved to: %s", *outputFile)
	} else {
		report.RenderConsole(finalResult)
	}

	if *baselineFile != "" {
		baseline, err := report.LoadJSON(*baselineFile)
		if err != nil {
			log.Printf("Warning: baseline report %s skipped: %v", *baselineFile, err)
		} else {
			diff := report.ComputeScanDiff(baseline, finalResult)
			report.RenderDiff(diff)
		}
	}

	log.Printf("Scan completed in %s", scanDuration.Round(time.Second))
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
