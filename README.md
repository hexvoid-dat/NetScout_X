# NetScoutX

[![Go Reference](https://pkg.go.dev/github.com/hexe/net-scout?tab=doc)](https://pkg.go.dev/github.com/hexe/net-scout)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://github.com/hexe/net-scout/actions/workflows/go.yml/badge.svg)](https://github.com/hexe/net-scout/actions/workflows/go.yml)


```
  _   _      _   ____                  _   __  __
 | \ | | ___| |_/ ___|  ___ ___  _   _| |_ \ \/ /
 |  \| |/ _ \ __\___ \ / __/ _ \| | | | __| \  / 
 | |\  |  __/ |_ ___) | (_| (_) | |_| | |_ /  \ 
 |_| \_|\___|\__|____/ \___\___/ \__,_|\__/_/\_\
```


ENG_version of README.md if u want to read in PL (my native lang) u need to search there ---> /NetScout_X/docs/README_PL.md

## Project Overview

NetScoutX - Network scanner with passive traffic analysis and risk scoring (and much more coming soon)

<p align="center">
  <img src="assets/sscli.png" alt="NetScoutX CLI screenshot" width="700" />
</p>

## Quickstart

If you just want to fire up the tool and see what's happening on your network:

```bash
# Interactive mode (simplest start)
sudo netscoutx

# Quick active scan e.g., home network
sudo net-scout -subnet 192.168.0.0/24 -output scan.json

# Active scan + short passive listen
sudo net-scout -subnet 192.168.0.0/24 -passive-duration 20s -output baseline.json
```

## Features

NetScoutX doesn't try to be everything at once. It focuses on the network and helping you quickly spot which hosts are interesting or suspicious.

### Active Engine

* **Host discovery:** Lightweight TCP discovery across a given range, probing common ports (80, 22, 21, 443).
* **Port scanning:** Parallel TCP scan for a sensible list of services (20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080).
* **UDP scanning:** Poking selected UDP services (DNS 53, NTP 123, SNMP 161, SSDP 1900, mDNS 5353) with service identification.
* **Service fingerprinting:** Banners / service versions for SSH, HTTP (Server), FTP, and a few others.
* **OS guessing:** Best-effort guess based on TTL and banners – not magic, just a solid estimate.
* **Vulnerability lookup:** Simple built-in "vuln DB" based on banners – enough to catch the obvious low-hanging fruit.

### Passive Engine (via `gopacket` / `libpcap`)

* **Multi-interface capture:** Listens on multiple interfaces in parallel.
* **ARP passive discovery:** Tracking ARP traffic, mapping IP ↔ MAC, vendor lookup via OUI.
* **DHCP parsing:** Extracting IP assignments, hostnames, and vendor class. Detects DHCP servers and potential rogue ones.
* **mDNS service discovery:** Reading services like `_http._tcp.local` – perfect for catching IoT devices and their "talents." Flags sensitive advertisements via mDNS.
* **DNS query parsing:** Analyzing DNS queries, detecting high-entropy domains (DGA) and unusual TLDs.
* **TLS JA3 fingerprinting:** Extracting JA3 from ClientHello to distinguish client types (browsers, tools, malware). Note: this feature is still under development.
* **Passive scoring contribution:** Everything observed passively contributes to the host's risk score.

### ARP Analysis

* **Structured anomalies:** Detects `ip_conflict` (one IP, multiple MACs) and `greedy_mac` (one MAC, multiple IPs).
* **Severity classification:** Tagged risk levels (High / Medium / Low), with an attempt to recognize "it's just a gateway, don't panic."
* **Impact on risk score:** ARP findings aren't just logged "for later" – they directly increase the host's score.

### Command-Line Interfaces (CLIs)

You have two approaches to choose from:

1. **`net-scout` (Flag-based CLI):** No frills, ideal for scripting and automation.
2. **`net-scout-cli` (`netscoutx` – interactive TUI):**
   * **Quick scan:** Auto-detects subnet and runs active + passive scanning immediately.
   * **Custom scan:** Manually enter CIDR, followed by the same pipeline.
   * **Passive-only:** Listen only, zero generated traffic.
   * **Merged overview:** A single table view showing IP / MAC / vendor / risk / JA3 / ports.
   * **Passive summary:** Aggregated statistics from passive capture.
   * **Settings:** Toggle TTL OS fingerprinting, UDP, etc.
   * **JSON export:** Full report for further processing.
   * **Result diffing:** Compare the current scan against a baseline JSON (drift, new services, new risks).

## Why NetScoutX vs Nmap?

NetScoutX isn't trying to kill Nmap – it's designed to work alongside it.

- **Active + Passive:** Simultaneously scans and listens, so it catches hosts that might not respond to simple SYN probes.
- **Built-in risk scoring:** No need to stare at a list of ports. You immediately see which hosts are "red."
- **Anomaly detection:** ARP, DHCP, DNS, mDNS – heuristics that surface IP conflicts, suspicious DHCP activity, weird domains, or "chatty" IoT devices.
- **Baseline diffing:** JSON reports can be compared against each other – perfect for detecting changes over time.

The best results come from running NetScoutX alongside Nmap and your other favorite tools. Each does its own job, and you get a fuller picture of what's alive on the network.

## Architecture Overview

Under the hood, NetScoutX looks roughly like this:

```
+-------------------+       +-------------------+
|   Active Engine   |       |   Passive Engine  |
|-------------------|       |-------------------|
| - Host Discovery  |       | - Packet Capture  |
| - Port Scanning   |       |   (libpcap/gopacket)|
| - UDP Scanning    |       | - ARP Parser      |
| - Service Finger. |       | - DHCP Parser     |
| - OS Guessing     |       | - mDNS Parser     |
+-------------------+       | - DNS Parser      |
          |                 | - TLS JA3 Parser  |
          |                 +-------------------+
          |                           |
          |                           |
          v                           v
+-------------------------------------------------+
|             Merge & Analysis Pipeline           |
|-------------------------------------------------|
| 1. Active TCP Discovery                         |
| 2. ARP Enrichment (active ARP requests)         |
| 3. Passive Collection (ARP/DHCP/mDNS/DNS/JA3)   |
| 4. ARP Anomaly Analysis (structured)            |
| 5. Port Scan (TCP/UDP)                          |
| 6. Service Fingerprinting                       |
| 7. OS Guessing                                  |
| 8. Merge Passive & Active Results               |
| 9. Risk Evaluation (incorporating passive data) |
+-------------------------------------------------+
          |
          v
+-------------------+
|    CLI & Reports  |
|-------------------|
| - Interactive TUI |
| - Flag-based CLI  |
| - JSON Export     |
| - Console Output  |
| - Baseline Diff   |
+-------------------+
```

### Key Components

* `internal/scanner` – all active scan logic: discovery, ports, OS guess, risk score.
* `internal/passive` – passive engine: capture, parsing ARP / DHCP / mDNS / DNS / TLS.
* `internal/merge` – where active and passive data are stitched together into a single host representation.
* `internal/report` – generating readable console output and JSON.
* `cmd/net-scout` and `cmd/net-scout-cli` – entrypoints for both CLIs.

## Installation

To build NetScoutX, you need Go 1.22+ and `libpcap`.

### Prerequisites

* **Go 1.22+** – standard Go installation.
* **`libpcap` dev:**
  * Ubuntu/Debian: `sudo apt-get update && sudo apt-get install libpcap-dev`
  * CentOS/RHEL: `sudo yum install libpcap-devel`
  * macOS: `brew install libpcap`

### "Official" Installation (system-wide)

1. Build the interactive CLI:

   ```bash
   go build -o netscoutx ./cmd/net-scout-cli
   ```

2. Move the binary somewhere in your `PATH`:

   ```bash
   sudo mv netscoutx /usr/local/bin/
   ```

   In practice, you'll most often run `netscoutx` with `sudo`. Passive capture / TTL fingerprinting requires access to raw sockets (e.g., `setcap cap_net_raw,cap_net_admin+ep /path/to/netscoutx`).

### Building the Flag-based CLI

```bash
go build -o net-scout ./cmd/net-scout
```

## Usage Examples

### Interactive CLI (`netscoutx`)

The simplest path:

```bash
sudo netscoutx
```

You'll see the main menu:

```text
MAIN MENU
  1) Quick scan (auto-detect subnet, includes passive analysis)
  2) Custom scan (enter CIDR, includes passive analysis)
  3) Run tests (Docker required)
  4) Help
  5) About
  6) Exit
  7) Settings (TTL / OS fingerprint / UDP)
  8) Passive scan (listen only, no packets sent)
```

#### Example: Quick Scan (active + passive)

Option `1` runs the full pipeline on the detected subnet.

```text
$ sudo netscoutx
  _   _      _   ____                  _   __  __
 | \ | | ___| |_/ ___|  ___ ___  _   _| |_ \ \/ /
 |  \| |/ _ \ __\___ \ / __/ _ \| | | | __| \  / 
 | |\  |  __/ |_ ___) | (_| (_) | |_| | |_ /  \ 
 |_| \_|\___|\__|____/ \___\___/ \__,_|\__/_/\_/
Welcome to NetScoutX!
   Scan your network, enumerate hosts, and highlight security risks.
   Choose an option from the menu below:

MAIN MENU
  1) Quick scan (auto-detect subnet, includes passive analysis)
  2) Custom scan (enter CIDR, includes passive analysis)
  3) Run tests (Docker required)
  4) Help
  5) About
  6) Exit
  7) Settings (TTL / OS fingerprint / UDP)
  8) Passive scan (listen only, no packets sent)
Choose an option (1-8): 1

QUICK SCAN
Attempting to detect your local subnet...
Using detected subnet: 192.168.1.0/24
Results will be saved to quick_scan_20251117_123456.json
Compare with previous JSON report? (y/N): n

Starting scan for subnet: 192.168.1.0/24
Passive analysis will run in parallel for 10 seconds...
Initializing active host discovery...
Enriching hosts with ARP data...
Discovered 3 hosts.
Analyzing network anomalies...
Scanning ports and services...
... fingerprinting services and OS...
Active scan completed.
Merging passive and active results...
Performing final risk evaluation...

============================================================
SCAN RESULTS
============================================================

GENERAL WARNINGS:
   - ARP anomaly: MAC 00:11:22:33:44:55 is associated with multiple IP addresses: [192.168.1.1, 192.168.1.100]
   - ARP anomaly: MAC 00:11:22:33:44:55 acts as a gateway/proxy for 2 IPs (e.g., 192.168.1.1)

ACTIVE SCAN SUMMARY:
   - Actively probed hosts: 2
   - Scan duration: 12.543s

PASSIVE DISCOVERY SUMMARY:
   - Passively discovered hosts: 3
   - DHCP servers observed: 1

HOST OVERVIEW:
IP             MAC                VENDOR          HOSTNAME        RISK           JA3s   OPEN PORTS
192.168.1.1    00:11:22:33:44:55  Cisco           router.local    medium (45)    0      80/tcp, 443/tcp, 53/udp
192.168.1.100  00:22:33:44:55:66  Intel           my-pc           medium (30)    1      22/tcp, 8080/tcp
192.168.1.101  00:aa:bb:cc:dd:ee  Raspberry Pi F. raspberrypi     low (10)       0      -

--- Scan Results for subnet 192.168.1.0/24 ---
Scan finished in 12.543s. Found 3 host(s).

--- Detailed Host Report ---
--------------------------------------------------
HOST: 192.168.1.1 (00:11:22:33:44:55)
  OS (guess): Network device (Cisco)
  Risk: Medium (45/100)
  Open ports:
    PORT  PROTO  SERVICE  DETAILS
    80    tcp    HTTP     Server: Apache/2.4.29
    443   tcp    HTTPS    Server: nginx/1.18.0
    53    udp    DNS      
--------------------------------------------------
HOST: 192.168.1.100 (00:22:33:44:55:66)
  OS (guess): Linux (OpenSSH)
  Risk: Medium (30/100)
  Open ports:
    PORT  PROTO  SERVICE  DETAILS
    22    tcp    SSH      SSH-2.0-OpenSSH_8.2p1
    8080  tcp    HTTP     Server: Caddy/2.4.5
--------------------------------------------------
HOST: 192.168.1.101 (00:aa:bb:cc:dd:ee)
  OS (guess): Unknown
  Risk: Low (10/100)
  Open ports: none detected
--------------------------------------------------

=== Security summary ===
  Hosts scanned: 3
  High risk:   0
  Medium risk: 2
  Low risk:    1
```

#### Example: Passive Only

Option `8` runs the passive engine alone. No outgoing packets, just listening.

```text
$ sudo netscoutx
... 
MAIN MENU
... 
  8) Passive scan (listen only, no packets sent)
Choose an option (1-8): 8

PASSIVE SCAN
Starting passive network analysis. This will run until you stop it (Ctrl+C).
Listening for ARP, DHCP, mDNS, DNS, and TLS fingerprints...
Capture started. Press Ctrl+C to stop and see results.
^C
Passive: stopping capture...
Passive: capture stopped.

============================================================
PASSIVE SCAN RESULTS
============================================================

PASSIVE DISCOVERY SUMMARY:
   - Passively discovered hosts: 2
   - DHCP servers observed: 1

HOST OVERVIEW:
IP             MAC                VENDOR          HOSTNAME        RISK           JA3s   OPEN PORTS
192.168.1.100  00:22:33:44:55:66  Intel           my-pc           low (5)        1      -
192.168.1.102  00:ff:ee:dd:cc:bb  Samsung         smart-tv        low (8)        0      -
```

### Flag-based CLI (`net-scout`)

```bash
# Simple active scan
sudo ./net-scout -subnet 192.168.1.0/24 -output scan_report.json

# Active scan + UDP + 30s passive
sudo ./net-scout -subnet 192.168.1.0/24 -enable-udp -passive-duration 30s -output scan_report_full.json
```

## Risk Scoring – What's the Deal with the Points?

NetScoutX calculates a risk score on a scale of 0–100. This isn't CVSS; it's a quick heuristic to tell you "what to look at first."

Factors considered include:

* **Open ports:** each open port adds something.
* **Vulnerabilities:** vulnerabilities derived from banners (CRITICAL / HIGH / MEDIUM) significantly increase the score.
* **Specifically dangerous services:** Telnet, SMB, RDP, and the like.
* **HTTP without HTTPS:** HTTP on 80 without a sensible HTTPS on 443 = extra points.
* **ARP anomalies:** IP conflict / strangely behaving MAC = substantial risk bonus.
* **Passive signals:**
  * hosts observed only passively,
  * presence of JA3,
  * DNS queries to strange / "entropic" domains,
  * leaks via mDNS,
  * potentially rogue DHCP.

## Anomaly Detection

NetScoutX doesn't just list hosts; it tries to explain why something might be off.

* **ARP:**
  * `ip_conflict` – the same IP seen from different MACs (immediately suggests ARP spoofing or a serious misconfiguration).
  * `greedy_mac` – one MAC collecting many IPs. Sometimes this is a normal router, sometimes something more creative. The tool tries to filter out typical gateways.
* **DHCP:**
  * rogue DHCP detection – unknown servers, unusual vendors, multiple servers in one segment.
* **DNS:**
  * high-entropy domains (suspected DGA),
  * exotic / suspicious TLDs.
* **mDNS:**
  * services you might not want to be broadcasting across the entire network (e.g., file sharing, remote access).
* **JA3:**
  * better detection of "odd" fingerprints typical of custom tools / malware is planned.

## JSON Report – What's Inside

NetScoutX can output a full JSON report. The `ScanResult` structure looks roughly like this:

```json
{
  "timestamp": "2025-11-17T12:34:56.789Z",
  "subnet": "192.168.1.0/24",
  "hosts": [
    {
      "ip": "192.168.1.1",
      "mac": "00:11:22:33:44:55",
      "hostname": "router.local",
      "os_guess": "Network device (Cisco)",
      "os_confidence": "medium",
      "open_ports": [
        {
          "number": 53,
          "protocol": "udp",
          "state": "open",
          "service": "DNS"
        },
        {
          "number": 80,
          "protocol": "tcp",
          "state": "open",
          "service": "HTTP",
          "version": "Apache/2.4.29",
          "banner": "Server: Apache/2.4.29",
          "vulnerabilities": [
            {
              "cve_id": "CVE-2018-1312",
              "description": "Path traversal in Apache HTTPD 2.4.29 allowing exposure of arbitrary files.",
              "severity": "HIGH"
            }
          ]
        },
        {
          "number": 443,
          "protocol": "tcp",
          "state": "open",
          "service": "HTTPS",
          "version": "nginx/1.18.0",
          "banner": "Server: nginx/1.18.0"
        }
      ],
      "risk_score": 45,
      "risk_level": "medium",
      "arp_flags": [
        "greedy_mac"
      ],
      "ja3_fingerprints": [],
      "dns_queries": [],
      "passively_discovered": false
    },
    {
      "ip": "192.168.1.100",
      "mac": "00:22:33:44:55:66",
      "hostname": "my-pc",
      "os_guess": "Linux (OpenSSH)",
      "os_confidence": "medium",
      "open_ports": [
        {
          "number": 22,
          "protocol": "tcp",
          "state": "open",
          "service": "SSH",
          "version": "SSH-2.0-OpenSSH_8.2p1",
          "banner": "SSH-2.0-OpenSSH_8.2p1"
        },
        {
          "number": 8080,
          "protocol": "tcp",
          "state": "open",
          "service": "HTTP",
          "version": "Caddy/2.4.5",
          "banner": "Server: Caddy/2.4.5"
        }
      ],
      "risk_score": 30,
      "risk_level": "medium",
      "arp_flags": [],
      "ja3_fingerprints": [
        "e7d705a3286e19ea42f587b344ee6865"
      ],
      "dns_queries": [
        "www.google.com",
        "update.microsoft.com"
      ],
      "passively_discovered": false
    },
    {
      "ip": "192.168.1.101",
      "mac": "00:aa:bb:cc:dd:ee",
      "hostname": "raspberrypi",
      "os_guess": "Unknown",
      "os_confidence": "low",
      "open_ports": [],
      "risk_score": 10,
      "risk_level": "low",
      "arp_flags": [],
      "ja3_fingerprints": [],
      "dns_queries": [],
      "passively_discovered": true
    }
  ],
  "scan_duration": "12.543s",
  "security_warnings": [
    "ARP anomaly: MAC 00:11:22:33:44:55 is associated with multiple IP addresses: [192.168.1.1, 192.168.1.100]",
    "ARP anomaly: MAC 00:11:22:33:44:55 acts as a gateway/proxy for 2 IPs (e.g., 192.168.1.1)"
  ]
}
```

## Contributing

If NetScoutX is useful to you and you'd like to contribute, please check out `CONTRIBUTING.md`. Pull requests are welcome – from typo fixes to new heuristics and parsers.

## License

NetScoutX is released under the MIT License. Details can be found in the `LICENSE` file.

## Maintainer Info

**Hexe**

* Founder of SYNTH1CA LABS | PROSTA SPÓŁKA AKCYJNA
* CFO - Head of developers
* Cybersecurity Engineer
* ex Tattoo Artist

## Credits

* `gopacket` – a solid foundation for capture and decoding.
* `golang.org/x/net/icmp` – for TTL / ICMP support.
* The community – for feedback, bug reports, and ideas.
* `https://www.linkedin.com/in/lucas-piatek-891201376/` and `https://varasystems.eu/` and `https://entropy.varasystems.eu/` – if you want to check me out outside of GitHub.

If you're interested in what's next for the project, take a look at `codozrobienia.md` – that's where you'll find more "human-readable" notes with ideas for development.
---