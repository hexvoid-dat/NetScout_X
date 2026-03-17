package scanner

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// defaultDiscoveryPorts defines the TCP ports probed to guess whether a host is online.
// This is a best-effort technique that only detects hosts exposing these services,
// so devices without these open ports might be missed entirely.
var defaultDiscoveryPorts = []int{80, 22, 21, 443}

// DiscoverHosts performs a lightweight TCP-based discovery of hosts within the provided subnet.
// To jest taki fallback, jak nie mamy roota na ARP. Wiadomo, że cichych maszyn tak nie złapiemy, 
// ale zawsze to lepsze niż nic.
func DiscoverHosts(subnet string) ([]Host, error) {
	log.Printf("Starting host discovery across subnet %s", subnet)

	ips, err := GetIPsInSubnet(subnet)
	if err != nil {
		return nil, err
	}

	var activeHosts []Host
	var wg sync.WaitGroup
	hostsChan := make(chan Host, 255)

	// Probe each IP concurrently
	for _, ip := range ips {
		wg.Add(1)
		go func(targetIP net.IP) {
			defer wg.Done()
			if pingHost(targetIP) {
				// For now we keep a placeholder MAC until ARP collection is implemented.
				hostsChan <- Host{
					IP:  targetIP.String(),
					MAC: "00:00:00:00:00:00", // Placeholder
				}
			}
		}(ip)
	}

	// Close channel once all probes finish
	go func() {
		wg.Wait()
		close(hostsChan)
	}()

	// Aggregate all responsive hosts.
	for host := range hostsChan {
		activeHosts = append(activeHosts, host)
	}

	log.Printf("Discovery finished: found %d active host(s) in %s", len(activeHosts), subnet)
	return activeHosts, nil
}

// pingHost checks if the target responds on at least one of the discovery ports.
func pingHost(ip net.IP) bool {
	for _, port := range defaultDiscoveryPorts {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 1*time.Second)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

func GetIPsInSubnet(subnetStr string) ([]net.IP, error) {
	ip, ipNet, err := net.ParseCIDR(subnetStr)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		// Copy the IP to avoid data races when goroutines hold onto the slice.
		addr := make(net.IP, len(ip))
		copy(addr, ip)
		ips = append(ips, addr)
	}
	// Remove network and broadcast addresses when possible.
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
