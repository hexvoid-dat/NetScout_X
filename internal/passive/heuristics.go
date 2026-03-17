package passive

import (
	"fmt"
	"math"
	"strings"
)

const (
	maxTrustedDHCPServers       = 2
	ja3RareObservationThreshold = 2
	minEntropyLabelLength       = 12
	highEntropyThreshold        = 4.0
)

var (
	infraVendorKeywords = []string{
		"cisco", "meraki", "juniper", "mikrotik", "ubiquiti",
		"aruba", "hewlett", "hp", "tp-link", "tplink", "netgear",
		"huawei", "zyxel", "fortinet", "palo alto", "checkpoint",
		"dell", "h3c",
	}

	commonTLDs = map[string]struct{}{
		"com": {}, "net": {}, "org": {}, "edu": {}, "gov": {}, "mil": {},
		"local": {}, "lan": {}, "home": {}, "int": {}, "io": {}, "dev": {},
		"app": {}, "co": {}, "us": {}, "uk": {}, "de": {}, "fr": {},
	}

	sensitiveMDNSServices = []string{
		"_workstation", "_adisk", "_afpovertcp", "_smb", "_nfs",
		"_raop", "_ssh", "_rfb", "_ipp", "_companion-link", "_apple-mobdev2",
	}

	wellKnownJA3Fingerprints = map[string]string{
		"e7d705a3286e19ea42f587b344ee6865": "Chrome",
		"d4d0f4b4a1d7b13f5b0d66fb1b5d19e4": "Firefox",
		"a0e9f5d64349fb13191bc781f81f42e1": "Safari",
		"39e3f4338ff0fc2f9ce4cf8b725c9e4b": "Edge",
		"9a3ba83e0d304a085b2c651b6bf1c3d6": "curl",
	}
)

func isLikelyInfrastructureVendor(vendor string) bool {
	if vendor == "" {
		return false
	}
	vendor = strings.ToLower(vendor)
	for _, keyword := range infraVendorKeywords {
		if strings.Contains(vendor, keyword) {
			return true
		}
	}
	return false
}

func isSensitiveMDNSService(service string) bool {
	service = strings.ToLower(service)
	for _, keyword := range sensitiveMDNSServices {
		if strings.Contains(service, keyword) {
			return true
		}
	}
	return false
}

func classifyDNSQuery(query string) (bool, string) {
	query = strings.TrimSuffix(strings.ToLower(query), ".")
	if query == "" {
		return false, ""
	}

	labels := strings.Split(query, ".")
	if len(labels) == 0 {
		return false, ""
	}

	tld := labels[len(labels)-1]
	if _, ok := commonTLDs[tld]; !ok && len(tld) >= 3 {
		return true, fmt.Sprintf("unusual TLD .%s", tld)
	}

	longest := ""
	for _, label := range labels {
		if len(label) > len(longest) {
			longest = label
		}
	}

	if len(longest) >= minEntropyLabelLength {
		if entropy := shannonEntropy(longest); entropy >= highEntropyThreshold {
			return true, fmt.Sprintf("high entropy label %.2f", entropy)
		}
	}

	return false, ""
}

func shannonEntropy(label string) float64 {
	// Klasyka gatunku przy szukaniu DGA. Na krótkich labelkach potrafi siać 
	// false-positives, ale przy dłuższych ciągach całkiem nieźle wyłapuje syf.
	if label == "" {
		return 0
	}
	freqs := make(map[rune]float64)
	length := float64(len(label))

	for _, r := range label {
		freqs[r]++
	}

	var entropy float64
	for _, count := range freqs {
		p := count / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func addUniqueString(target *[]string, value string) {
	if value == "" {
		return
	}
	for _, existing := range *target {
		if existing == value {
			return
		}
	}
	*target = append(*target, value)
}

func isGREASEValue(value uint16) bool {
	low := value & 0x00ff
	high := value >> 8
	return low == high && (value&0x0f0f) == 0x0a0a
}

func isCommonJA3(hash string) bool {
	_, ok := wellKnownJA3Fingerprints[hash]
	return ok
}
