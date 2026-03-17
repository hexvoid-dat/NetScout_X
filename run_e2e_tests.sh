#!/bin/bash

# Exit on any command failure
set -e

# --- Configuration ---
DOCKER_COMPOSE_FILE="docker-compose.yml"
SUBNET="172.28.0.0/24"
OUTPUT_FILE="test_results.json"
NET_SCOUT_BINARY="net-scout"

# --- Cleanup Logic ---
cleanup() {
  echo "[INFO] Tearing down test environment..."
  docker compose -f "$DOCKER_COMPOSE_FILE" down
  rm -f "$OUTPUT_FILE"
}

# Register cleanup to run on exit
trap cleanup EXIT

# --- Main Test Execution ---
echo "[INIT] Starting Docker test environment..."
docker compose -f "$DOCKER_COMPOSE_FILE" up -d

# Brief pause for services to stabilize
sleep 5

echo "[BUILD] Compiling net-scout binary..."
go build -o "$NET_SCOUT_BINARY" ./cmd/net-scout

echo "[SCAN] Executing network scan in isolated environment..."
./"$NET_SCOUT_BINARY" -subnet="$SUBNET" -output="$OUTPUT_FILE"

echo "[VERIFY] Running validation checks..."

# Check 1: Host discovery count
host_count=$(jq '.hosts | length' "$OUTPUT_FILE")
if [ "$host_count" -lt 3 ]; then
  echo "[FAIL] Expected at least 3 active hosts, but found: $host_count"
  exit 1
fi
echo "[PASS] Discovered $host_count hosts."

# Check 2: vsftpd vulnerability detection (172.28.0.10)
ftp_vuln=$(jq -r '.hosts[] | select(.ip == "172.28.0.10") | .open_ports[] | select(.number == 21) | .vulnerabilities[] | select(.cve_id == "CVE-2011-2523") | .cve_id' "$OUTPUT_FILE")
if [ "$ftp_vuln" != "CVE-2011-2523" ]; then
  echo "[FAIL] Missing CVE-2011-2523 on FTP server (172.28.0.10)."
  exit 1
fi
echo "[PASS] Successfully identified vulnerability on FTP server."

# Check 3: OpenSSH vulnerability detection (172.28.0.20)
ssh_vuln=$(jq -r '.hosts[] | select(.ip == "172.28.0.20") | .open_ports[] | select(.number == 22) | .vulnerabilities[] | select(.cve_id == "CVE-2018-15473") | .cve_id' "$OUTPUT_FILE")
if [ "$ssh_vuln" != "CVE-2018-15473" ]; then
  echo "[FAIL] Missing CVE-2018-15473 on SSH server (172.28.0.20)."
  exit 1
fi
echo "[PASS] Successfully identified vulnerability on SSH server."

# Check 4: Apache vulnerability detection (172.28.0.30)
apache_vuln=$(jq -r '.hosts[] | select(.ip == "172.28.0.30") | .open_ports[] | select(.number == 80) | .vulnerabilities[] | select(.cve_id == "CVE-2018-1312") | .cve_id' "$OUTPUT_FILE")
if [ "$apache_vuln" != "CVE-2018-1312" ]; then
  echo "[FAIL] Missing CVE-2018-1312 on Apache server (172.28.0.30)."
  exit 1
fi
echo "[PASS] Successfully identified vulnerability on Apache server."

echo "[SUCCESS] All end-to-end tests completed successfully."
exit 0
