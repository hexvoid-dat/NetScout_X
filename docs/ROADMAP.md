# NetScoutX Project Roadmap

This document outlines the planned evolution of NetScoutX, a hybrid active and passive network reconnaissance tool. Our roadmap is structured into several phases, each building upon the previous one to deliver increasing value and sophistication.

## Phase 1 — OSS Release (Current State)

This phase represents the current capabilities of NetScoutX as an open-source project.

*   **Hybrid Active + Passive Network Reconnaissance:** Seamless integration of active probing and passive traffic analysis.
*   **Comprehensive Host Discovery:** TCP-based host discovery and active ARP enrichment.
*   **Port Scanning:** Robust TCP and UDP port scanning with service name identification.
*   **Service Fingerprinting:** Active identification of service versions (SSH, HTTP, FTP).
*   **Advanced ARP Anomaly Detection:** Structured analysis of ARP conflicts and "greedy MACs" with severity classification and intelligent gateway recognition.
*   **Passive Collection:**
    *   ARP passive discovery (MAC -> vendor detection).
    *   DHCP packet parsing (IP assignment, hostname, vendor, rogue DHCP detection).
    *   mDNS service discovery (hostnames, service types, mDNS leak detection).
    *   DNS query parsing (requested domains, high-entropy/unusual TLD detection).
    *   TLS JA3 fingerprint extraction (client application identification).
*   **Risk Scoring:** Heuristic risk evaluation per host, incorporating active scan findings, vulnerabilities, ARP anomalies, and passive signals.
*   **Command-Line Interfaces:**
    *   Flag-based CLI (`net-scout`) for scripting.
    *   Interactive TUI-like CLI (`netscoutx`) with menus, quick/custom scans, passive-only mode, merged overview, and settings.
*   **Reporting:** JSON export of detailed scan results and console output.
*   **Baseline Diffing:** Comparison of current scan results against previous reports.

## Phase 2 — Enhancements

This phase focuses on refining existing features and introducing new, high-impact capabilities.

*   **Passive TLS JA3S:** Implement server-side JA3 fingerprinting to provide a more complete picture of TLS communication.
*   **IoT Fingerprinting:** Develop advanced heuristics and pattern matching to classify and identify specific IoT devices based on mDNS/SSDP patterns, OUI, and observed behavior.
*   **Behavior Graphs:** Visualize network communication patterns ("talking hosts graph") to identify unusual connections and potential command-and-control channels.
*   **Threat Intelligence Integration:** Integrate with external threat intelligence feeds (e.g., known malicious IPs, domains, JA3 hashes) to enrich anomaly detection and risk scoring.
*   **Mini Web UI:** Develop a lightweight, embedded web user interface for easier monitoring and interaction.
*   **Plugin System:** Design and implement a modular plugin architecture to allow community-driven extensions, custom parsers, and integration with other tools.

## Phase 3 — Heavyweight Fingerprinting

This phase aims to deepen the analysis capabilities by implementing more sophisticated protocol decoders.

*   **SMB, RDP, SSH Deep Parse:** Implement in-depth protocol parsers for these critical services to extract more detailed information (e.g., SMB shares, RDP versions, SSH key exchange algorithms) and identify specific vulnerabilities or misconfigurations.
*   **TLS Full Parser:** Develop a comprehensive TLS parser capable of analyzing full TLS handshakes, certificate chains, and protocol versions beyond just JA3.
*   **Protocol Decoders:** Expand the library of protocol decoders for additional application-layer protocols relevant to security analysis.



---
