package scanner

import "time"

// PortState describes the status of a scanned port.
type PortState string

const (
	StateOpen     PortState = "open"
	StateClosed   PortState = "closed"
	StateFiltered PortState = "filtered"
)

// Vulnerability captures a known issue detected for a given service banner.
type Vulnerability struct {
	CVE_ID      string `json:"cve_id"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // e.g. CRITICAL, HIGH, MEDIUM
}

// Port contains information collected for a single port on a host.
type Port struct {
	Number          int             `json:"number"`
	Protocol        string          `json:"protocol"`
	State           PortState       `json:"state"`
	Service         string          `json:"service,omitempty"`         // e.g. "SSH", "HTTP"
	Version         string          `json:"version,omitempty"`         // e.g. "OpenSSH 8.2p1", "nginx/1.18.0"
	Banner          string          `json:"banner,omitempty"`          // Raw server response
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"` // Known issues linked to the banner
}

// ARPAnomalyKind defines the type of an ARP-related anomaly.
type ARPAnomalyKind string

const (
	// ARPConflictIP indicates one IP is claimed by multiple MACs. High-risk indicator.
	ARPConflictIP ARPAnomalyKind = "ip_conflict"
	// ARPGreedyMAC indicates one MAC claims multiple IPs. Often a gateway, but can be suspicious.
	ARPGreedyMAC ARPAnomalyKind = "greedy_mac"
)

// ARPAnomaly represents a single detected ARP anomaly.
type ARPAnomaly struct {
	Kind     ARPAnomalyKind `json:"kind"`
	IP       string         `json:"ip,omitempty"`
	MAC      string         `json:"mac,omitempty"`
	Involved []string       `json:"involved,omitempty"` // Conflicting MACs or IPs
	Severity RiskLevel      `json:"severity"`
	Message  string         `json:"message"`
}

// OSConfidence represents the confidence level of an OS guess.
type OSConfidence string

const (
	ConfidenceLow    OSConfidence = "low"
	ConfidenceMedium OSConfidence = "medium"
	ConfidenceHigh   OSConfidence = "high"
)

// RiskLevel represents the severity of a risk.
type RiskLevel string

const (
	RiskLow    RiskLevel = "low"
	RiskMedium RiskLevel = "medium"
	RiskHigh   RiskLevel = "high"
)

// Host represents a device discovered on the scanned subnet.
type Host struct {
	IP           string       `json:"ip"`
	MAC          string       `json:"mac"`
	Hostname     string       `json:"hostname,omitempty"`
	OSGuess      string       `json:"os_guess,omitempty"`      // Best-effort OS fingerprint
	OSConfidence OSConfidence `json:"os_confidence,omitempty"` // Confidence level for the guess
	OpenPorts    []Port       `json:"open_ports"`
	RiskScore    int          `json:"risk_score,omitempty"` // 0-100 heuristic
	RiskLevel    RiskLevel    `json:"risk_level,omitempty"`
	Anomalies    []ARPAnomaly `json:"-"` // Internal use for risk scoring
	ARPFlags     []string     `json:"arp_flags,omitempty"`

	// Passively discovered data
	JA3Fingerprints      []string `json:"ja3_fingerprints,omitempty"`
	RareJA3Fingerprints  []string `json:"rare_ja3_fingerprints,omitempty"`
	DNSQueries           []string `json:"dns_queries,omitempty"`
	SuspiciousDNSQueries []string `json:"suspicious_dns_queries,omitempty"`
	LeakedMDNSServices   []string `json:"mdns_leaks,omitempty"`
	PotentialRogueDHCP   bool     `json:"rogue_dhcp_suspected,omitempty"`
	PassivelyDiscovered  bool     `json:"passively_discovered,omitempty"`
}

// ScanResult bundles everything collected during a scan.
type ScanResult struct {
	Timestamp        time.Time     `json:"timestamp"`
	Subnet           string        `json:"subnet"`
	Hosts            []Host        `json:"hosts"`
	ScanDuration     time.Duration `json:"scan_duration"`
	SecurityWarnings []string      `json:"security_warnings,omitempty"` // ARP or other warnings
}
