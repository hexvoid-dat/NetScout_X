package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// numWorkers defines the number of concurrent port scanning workers.
	// 100 to taki "sweet spot", żeby nie zabić deskryptorów, a szło sprawnie.
	numWorkers = 100
	// connectTimeout is the maximum time allowed for a single port connection attempt.
	connectTimeout = 1 * time.Second
)

// scanTask represents a single unit of work for a port scanner worker.
type scanTask struct {
	host *Host
	port int
}

// scanResult holds the outcome of a single port scan operation.
type scanResult struct {
	port Port
	host *Host
}

// PortScanner performs concurrent port scanning on the provided list of hosts.
// It uses a worker pool pattern for efficiency and respects the provided context for cancellation.
func PortScanner(ctx context.Context, hosts []Host) {
	tasks := make(chan scanTask, numWorkers)
	results := make(chan scanResult)
	var wg sync.WaitGroup

	// Initialize worker pool
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(ctx, &wg, tasks, results)
	}

	// Task producer
	go func() {
		defer close(tasks)
		ports := commonPorts()
		for i := range hosts {
			for _, port := range ports {
				select {
				case <-ctx.Done():
					return
				case tasks <- scanTask{host: &hosts[i], port: port}:
				}
			}
		}
	}()

	// Wait for workers and close results channel
	go func() {
		wg.Wait()
		close(results)
	}()

	// Result collector
	for result := range results {
		if result.port.State == StateOpen {
			result.host.OpenPorts = append(result.host.OpenPorts, result.port)
		}
	}

	// Sort open ports for consistent output
	for i := range hosts {
		sort.Slice(hosts[i].OpenPorts, func(j, k int) bool {
			return hosts[i].OpenPorts[j].Number < hosts[i].OpenPorts[k].Number
		})
	}
}

func worker(ctx context.Context, wg *sync.WaitGroup, tasks <-chan scanTask, results chan<- scanResult) {
	defer wg.Done()
	for task := range tasks {
		select {
		case <-ctx.Done():
			return
		default:
		}

		address := fmt.Sprintf("%s:%d", task.host.IP, task.port)
		
		// Use DialContext for proper cancellation support
		var d net.Dialer
		d.Timeout = connectTimeout
		conn, err := d.DialContext(ctx, "tcp", address)

		portResult := Port{
			Number:   task.port,
			Protocol: "tcp",
		}

		if err != nil {
			portResult.State = StateClosed
		} else {
			conn.Close()
			portResult.State = StateOpen
			// Basic banner grabbing attempt
			portResult.Banner = grabBanner(ctx, address)

			// Perform vulnerability check based on the retrieved banner
			portResult.Vulnerabilities = CheckBannerForVulnerabilities(portResult.Banner)
		}

		select {
		case <-ctx.Done():
			return
		case results <- scanResult{port: portResult, host: task.host}:
		}
	}
}

func grabBanner(ctx context.Context, address string) string {
	var d net.Dialer
	d.Timeout = connectTimeout
	conn, err := d.DialContext(ctx, "tcp", address)
	if err != nil {
		return ""
	}
	defer conn.Close()
	
	_ = conn.SetReadDeadline(time.Now().Add(connectTimeout))
	
	// Special handling for HTTP (port 80) to elicit a banner
	if strings.HasSuffix(address, ":80") {
		hostOnly := strings.Split(address, ":")[0]
		_, err = conn.Write([]byte("HEAD / HTTP/1.1\r\nHost: " + hostOnly + "\r\n\r\n"))
		if err != nil {
			return ""
		}
	}
	
	buffer := make([]byte, 512)
	n, err := conn.Read(buffer)
	if err != nil {
		return ""
	}

	return string(buffer[:n])
}

// commonPorts returns a predefined list of frequently scanned network ports.
func commonPorts() []int {
	return []int{
		20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
		993, 995, 1723, 3306, 3389, 5900, 8080,
	}
}

