package passive

import "time"

// Host represents a device observed passively on the network.
// It is a separate model from scanner.Host but is designed to be mergeable.
type Host struct {
	IPs       map[string]time.Time // Set of IPs associated with this host, with last seen timestamp
	MAC       string
	Hostname  string
	Vendor    string
	Services  map[string]struct{} // Set of services discovered (e.g., "_http._tcp.local")
	FirstSeen time.Time
	LastSeen  time.Time

	// DHCP Info
	DHCPHostname   string
	DHCPVendorCode string

	// DNS Info
	DNSQueries []string
	// Suspicious DNS queries flagged by heuristics.
	SuspiciousDNSQueries []string

	// TLS Info
	JA3Fingerprints []string
	// JA3 fingerprints that look rare/uncommon for alerting.
	RareJA3Fingerprints []string

	// mDNS Info
	LeakedMDNSServices []string

	// DHCP threat intel
	PotentialRogueDHCP bool
}

// NewHost creates a new passive host entry.
func NewHost(mac string) *Host {
	return &Host{
		MAC:                  mac,
		IPs:                  make(map[string]time.Time),
		Services:             make(map[string]struct{}),
		FirstSeen:            time.Now(),
		LastSeen:             time.Now(),
		DNSQueries:           []string{},
		JA3Fingerprints:      []string{},
		SuspiciousDNSQueries: []string{},
		RareJA3Fingerprints:  []string{},
		LeakedMDNSServices:   []string{},
	}
}

// AnalysisResult holds the complete state of the passive analysis.
type AnalysisResult struct {
	Hosts          map[string]*Host // Keyed by MAC address
	DHCPServers    map[string]*DHCPServer
	JA3Observatory map[string]*JA3Observation
}

func NewAnalysisResult() *AnalysisResult {
	return &AnalysisResult{
		Hosts:          make(map[string]*Host),
		DHCPServers:    make(map[string]*DHCPServer),
		JA3Observatory: make(map[string]*JA3Observation),
	}
}

// DHCPServer captures metadata about DHCP servers seen on the wire.
type DHCPServer struct {
	IP       string
	MAC      string
	Vendor   string
	LastSeen time.Time
	Suspect  bool
}

// DHCPLeaseInfo holds information extracted from a DHCP ACK packet.
type DHCPLeaseInfo struct {
	IP        string
	MAC       string
	Hostname  string
	ServerIP  string
	ServerMAC string
	IsOffer   bool // True if DHCP Offer, false if ACK
}

// DNSInfo holds information from a parsed DNS query/response.
type DNSInfo struct {
	QueriedHost string
	Query       string
	Answers     []string
	Type        string // "A", "AAAA", "CNAME", etc.
}

// JA3Info holds a JA3 fingerprint and the source/destination IPs.
type JA3Info struct {
	SourceIP string
	JA3      string
	JA3S     string // Server-side JA3, if available
}

// JA3Observation tracks JA3 usage frequency to detect rare fingerprints.
type JA3Observation struct {
	Fingerprint string
	Count       int
	FirstSeen   time.Time
	LastSeen    time.Time
	LastSource  string // MAC or IP of the last host seen
}
