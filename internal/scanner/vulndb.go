package scanner

import (
	"strings"
)

// VulnerabilityRule defines a signature-based detection rule.
type VulnerabilityRule struct {
	Software string
	Versions []string
	Vuln     Vulnerability
}

// Match returns true if the provided banner matches the rule's criteria.
func (r VulnerabilityRule) Match(banner string) bool {
	if !strings.Contains(strings.ToLower(banner), strings.ToLower(r.Software)) {
		return false
	}
	for _, v := range r.Versions {
		if strings.Contains(banner, v) {
			return true
		}
	}
	return false
}

// Built-in signatures for common vulnerable services.
// In a more mature version, these could be loaded from an external JSON/YAML source.
var defaultVulnRules = []VulnerabilityRule{
	{
		Software: "OpenSSH",
		Versions: []string{"7.6", "7.5", "7.2"},
		Vuln: Vulnerability{
			CVE_ID:      "CVE-2018-15473",
			Description: "Username enumeration vulnerability in OpenSSH.",
			Severity:    "MEDIUM",
		},
	},
	{
		Software: "Apache",
		Versions: []string{"2.4.29"},
		Vuln: Vulnerability{
			CVE_ID:      "CVE-2018-1312",
			Description: "Path traversal in Apache HTTPD 2.4.29.",
			Severity:    "HIGH",
		},
	},
	{
		Software: "vsftpd",
		Versions: []string{"2.3.4", "3.0.2"},
		Vuln: Vulnerability{
			CVE_ID:      "CVE-2011-2523",
			Description: "Backdoor command execution risk in vsftpd.",
			Severity:    "CRITICAL",
		},
	},
	{
		Software: "ProFTPD",
		Versions: []string{"1.3.3c"},
		Vuln: Vulnerability{
			CVE_ID:      "CVE-2010-4221",
			Description: "Remote code execution issue impacting ProFTPD 1.3.3c.",
			Severity:    "CRITICAL",
		},
	},
	{
		Software: "Samba",
		Versions: []string{"3.0.20"},
		Vuln: Vulnerability{
			CVE_ID:      "CVE-2007-2446",
			Description: "Samba trans2 stack overflow enabling remote code execution.",
			Severity:    "CRITICAL",
		},
	},
	{
		Software: "MySQL",
		Versions: []string{"5.0.51a"},
		Vuln: Vulnerability{
			CVE_ID:      "CVE-2008-0226",
			Description: "Authentication bypass affecting MySQL 5.0.51a.",
			Severity:    "HIGH",
		},
	},
}

// CheckBannerForVulnerabilities compares the supplied banner against the local database signatures.
func CheckBannerForVulnerabilities(banner string) []Vulnerability {
	var found []Vulnerability
	if banner == "" {
		return found
	}

	for _, rule := range defaultVulnRules {
		if rule.Match(banner) {
			found = append(found, rule.Vuln)
		}
	}
	return found
}
