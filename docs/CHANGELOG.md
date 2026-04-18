# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2025-11-17

### Added

*   **Hybrid Active + Passive Network Reconnaissance Engine:**
    *   Seamless integration of active probing and passive traffic analysis.
    *   New `internal/passive` package for passive collection.
    *   New `internal/merge` package for combining active and passive results.
*   **Active Engine Enhancements:**
    *   **UDP Scanning:** Added support for UDP scanning on common ports (53, 123, 161, 1900, 5353) with service name identification.
    *   **Service Version Fingerprinting:** Implemented active probing for SSH, HTTP, and FTP service versions.
*   **Passive Engine Capabilities:**
    *   **Multi-Interface Capture:** Packet capture using `gopacket/pcap` across multiple network interfaces.
    *   **ARP Passive Discovery:** Monitors ARP traffic for host discovery and MAC vendor identification via OUI lookup.
    *   **DHCP Packet Parsing:** Extracts IP assignments, hostnames, and vendor class from DHCP traffic; tracks DHCP servers and flags potential rogue DHCP.
    *   **mDNS Service Discovery:** Parses mDNS traffic for hostnames and advertised services; detects sensitive mDNS leaks.
    *   **DNS Query Parsing:** Monitors DNS queries for requested domains and applies heuristics to detect high-entropy domains and unusual TLDs.
    *   **TLS JA3 Fingerprinting:** Extracts TLS ClientHello messages to compute JA3 fingerprints for client application identification. *(Note: This feature is currently under development and may not be fully functional.)*
*   **Advanced ARP Analysis:**
    *   **Structured Anomalies:** Detection of `ip_conflict` and `greedy_mac` anomalies with severity classification (High, Medium, Low) and intelligent "likely gateway" recognition.
    *   Contribution of ARP anomalies to host risk scores.
*   **Enhanced Risk Engine:**
    *   Heuristic risk scoring now incorporates passive signals (e.g., passively discovered hosts, JA3 fingerprints, DNS queries, mDNS leaks, rogue DHCP suspicion).
    *   Updated risk contributions for specific services (e.g., Telnet, FTP).
*   **CLI Improvements:**
    *   **Interactive CLI (`netscoutx`):**
        *   New `Passive scan` mode for standalone passive monitoring.
        *   Updated `Quick scan` and `Custom scan` to include parallel passive analysis.
        *   Enhanced `Host Overview` table with MAC, Vendor, Hostname, JA3 count, and Open Ports.
        *   New `Passive Summary` block in scan results.
        *   Updated menus and help texts.
    *   **Flag-based CLI (`net-scout`):**
        *   Added `--passive-duration` flag to enable passive collection during active scans.
    *   **JSON Export:** Updated JSON report structure to include all new passive and anomaly data.
*   **Documentation:**
    *   Comprehensive `README.md` with features, architecture, usage examples, and JSON structure.
    *   Detailed `INSTALL.md` with `libpcap` dependencies and permission notes.
    *   `CONTRIBUTING.md` for development guidelines.
    *   `CODE_OF_CONDUCT.md` for community standards.
    *   `SECURITY.md` for vulnerability reporting.
    *   `ARCHITECTURE.md` detailing the codebase structure and flow.
    *   `ROADMAP.md` outlining future development phases.
*   **Test Framework:**
    *   Created `internal/passive/passive_test.go` with test stubs for passive parsers.
    *   Added `internal/passive/testdata/generate/main.go` for generating `.pcap` test fixtures.

### Changed

*   Refactored `internal/scanner/security.go` to return structured `ARPAnomaly` instead of `[]string`.
*   Updated `internal/scanner/risk.go` to use new `ARPAnomaly` types and passive signals.
*   Modified `internal/report/report.go` for more structured console output of open ports.
*   Modified `cmd/net-scout-cli/main.go` and `cmd/net-scout/main.go` to integrate the new scan pipeline.

### Fixed

*   Corrected `internal/scanner/discover.go` syntax errors introduced during previous refactoring.
*   Resolved various unused import warnings across the codebase.

---
