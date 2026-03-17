````markdown
# NetScoutX - User Guide

## 🚀 Quick Start

### Step 1: Prepare the environment

```bash
# Check required tools are installed
go version          # Required: Go 1.21+
docker --version    # Required: Docker
jq --version        # Required: jq (for E2E tests)
```

### Step 2: Build the application

```bash
# Change to the project directory
cd net-scout

# Install dependencies
go mod tidy

# Build the application
go build -o net-scout ./cmd/net-scout
```

### Step 3: Basic usage

```bash
# Scan a subnet (output to console)
./net-scout -subnet=192.168.1.0/24

# Scan and save to JSON file
./net-scout -subnet=192.168.1.0/24 -output=report.json

# Show help
./net-scout -h
```

## 🧪 Testing

### Test 1: Basic local test

```bash
# Scan a small subnet (e.g., the router)
./net-scout -subnet=192.168.1.0/30

# Expected result: it will find the router with port 80 open
```

### Test 2: E2E test with Docker

```bash
# Run full E2E tests (requires Docker)
./run_e2e_tests.sh

# The test will automatically:
# 1. Start 3 containers with vulnerable services
# 2. Scan the 172.28.0.0/24 network
# 3. Verify detection of CVE vulnerabilities
# 4. Print ✅ Tests passed! if everything is OK
```

### Test 3: Manual test with Docker

```bash
# Start the test environment
docker compose -f docker-compose.yml up -d

# Wait 5 seconds for services to start
sleep 5

# Run a scan
./net-scout -subnet=172.28.0.0/24 -output=test_manual.json

# Inspect results
cat test_manual.json | jq '.'

# Tear down the environment
docker compose -f docker-compose.yml down
```

## 📊 Interpreting results

### Example console output:

```
--- Scan Results for subnet 192.168.1.0/24 ---
Scan finished in 4.512s. Found 3 hosts.

!!! SECURITY WARNINGS (ARP) !!!
- ARP conflict detected! IP 192.168.1.1 is associated with two MAC addresses.

--- Detailed Hosts Report ---
--------------------------------------------------
HOST: 192.168.1.1 (00:1A:2B:3C:4D:5E)
  OS (Estimate): Linux/Unix/macOS
  Open ports:
    80/tcp  Apache/2.4.41 (Ubuntu)
    22/tcp  OpenSSH_7.6p1 Ubuntu-4ubuntu0.7
                        [!] VULNERABILITY FOUND (MEDIUM)!
                            CVE: CVE-2018-15473
                            Description: Username Enumeration - a remote attacker can confirm existence of user accounts on the system.
--------------------------------------------------
```

### JSON file structure:

```json
{
  "timestamp": "2025-09-17T21:30:36.123456789+02:00",
  "subnet": "192.168.1.0/24",
  "hosts": [
    {
      "ip": "192.168.1.1",
      "mac": "00:1A:2B:3C:4D:5E",
      "open_ports": [
        {
          "number": 22,
          "protocol": "tcp",
          "state": "open",
          "banner": "SSH-2.0-OpenSSH_7.6p1",
          "vulnerabilities": [
            {
              "cve_id": "CVE-2018-15473",
              "description": "Username Enumeration",
              "severity": "MEDIUM"
            }
          ]
        }
      ]
    }
  ],
  "scan_duration": 4512000000,
  "security_warnings": [
    "ARP conflict detected! IP 192.168.1.1 is associated with two MAC addresses."
  ]
}
```

## 🔧 Troubleshooting

### Issue: "operation not permitted" (ICMP)

```
Error listening for ICMP for 192.168.1.1: listen ip4:icmp 0.0.0.0: socket: operation not permitted
```

**Solution:** This is expected in the unprivileged mode. OS fingerprinting requires root privileges.

### Issue: No hosts detected

```bash
# Check if hosts respond to ping
ping 192.168.1.1

# Check if ports are open
nc -zv 192.168.1.1 80
nc -zv 192.168.1.1 22
```

### Issue: E2E test fails

```bash
# Check Docker is running
docker ps

# Check containers are up
docker compose -f docker-compose.yml ps

# Check container logs
docker compose -f docker-compose.yml logs
```

## 🎯 Usage examples

### Scanning a home network

```bash
# Find your subnet
ip route | grep default

# Scan your home network
./net-scout -subnet=192.168.1.0/24 -output=home_network.json
```

### Scanning a small network

```bash
# Scan just a few addresses
./net-scout -subnet=192.168.1.0/30
```

### Analyzing results with jq

```bash
# Show only hosts with vulnerabilities
jq '.hosts[] | select(.open_ports[].vulnerabilities | length > 0)' report.json

# Show only critical vulnerabilities
jq '.hosts[].open_ports[].vulnerabilities[] | select(.severity == "CRITICAL")' report.json

# Count discovered hosts
jq '.hosts | length' report.json
```

## 🔒 Security

### ⚠️ Important warnings:

1. **Use only on networks you own** - Scanning networks without permission is illegal
2. **Root privileges** - Full functionality requires sudo (ARP/ICMP)
3. **Unprivileged mode** - Works without privileges but with reduced functionality

### Recommendations:

- Test on isolated networks (Docker, VM)
- Use unprivileged mode for basic scanning
- Always analyze results before taking action

## 📈 Performance

### Optimization:

```bash
# Scan smaller subnets for faster results
./net-scout -subnet=192.168.1.0/28  # 16 addresses
./net-scout -subnet=192.168.1.0/30  # 4 addresses
```

### Scan time estimates:

- **Small network (/30)**: ~2-3 seconds
- **Home network (/24)**: ~10-30 seconds
- **Large network (/16)**: ~5-15 minutes

## 🛠️ Extending functionality

### Adding new vulnerability checks:

Edit the file `internal/scanner/vulndb.go`:

```go
{
    SoftwareName: "NewService",
    CheckFunc: func(banner string) bool {
        return strings.Contains(banner, "NewService 1.0.0")
    },
    VulnInfo: Vulnerability{
        CVE_ID:      "CVE-2024-XXXX",
        Description: "Description of the vulnerability",
        Severity:    "HIGH",
    },
},
```

### Adding new ports:

Edit the `commonPorts()` function in `internal/scanner/scan.go`:

```go
func commonPorts() []int {
    return []int{
        20, 21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
        993, 995, 1723, 3306, 3389, 5900, 8080,
        8443,  // Add new port here
    }
}
```

## 📞 Support

### Debug logs:

```bash
# Run with additional logs
./net-scout -subnet=192.168.1.0/24 2>&1 | tee debug.log
```

### Check versions:

```bash
# Check Go version
go version

# Check the binary size
ls -lh net-scout
```

---

**NetScoutX** - Advanced network scanner with vulnerability analysis
*made_by_h.exe | CLI TOOL WRITTEN IN .GO*

````
