# Installation Guide for NetScoutX

This document provides comprehensive instructions for installing and setting up NetScoutX.

## System Requirements

*   **Go 1.22+**: NetScoutX is developed with Go 1.22 and requires this version or newer.
*   **Linux/Unix-like OS**: Tested primarily on Linux distributions (e.g., Ubuntu 22.04).
*   **`libpcap` development libraries**: Essential for passive packet capture functionality.
*   **Elevated Privileges (or `CAP_NET_RAW`)**: Full functionality, especially for passive mode and TTL-based OS fingerprinting, requires root privileges (`sudo`) or specific Linux capabilities (`CAP_NET_RAW`, `CAP_NET_ADMIN`).

## Prerequisites

### 1. Install Go

Ensure you have Go 1.22 or newer installed. You can check your version with:

```bash
go version
```

If Go is not installed, follow the official installation guide: [go.dev/doc/install](https://go.dev/doc/install)

### 2. Install `libpcap` Development Libraries

NetScoutX relies on `libpcap` for raw packet capture. Install the development headers for your operating system:

*   **Ubuntu/Debian:**
    ```bash
    sudo apt-get update
    sudo apt-get install libpcap-dev
    ```
*   **CentOS/RHEL:**
    ```bash
    sudo yum install libpcap-devel
    ```
*   **macOS (via Homebrew):**
    ```bash
    brew install libpcap
    ```

## Building and Installing NetScoutX

### 1. Clone the Repository

First, clone the NetScoutX repository to your local machine:

```bash
git clone https://github.com/hexe/net-scout.git
cd net-scout
```

### 2. Download Go Modules

Navigate into the project directory and download the required Go modules:

```bash
go mod tidy
```

### 3. Build the Executables

NetScoutX provides two main executables: `netscoutx` (interactive CLI) and `net-scout` (flag-based CLI).

#### Recommended: Install `netscoutx` (Interactive CLI) System-Wide

This is the recommended method for most users, making the interactive CLI available from any directory.

```bash
# Build the interactive CLI executable
go build -o netscoutx ./cmd/net-scout-cli

# Move the executable to a system PATH directory (e.g., /usr/local/bin)
sudo mv netscoutx /usr/local/bin/
```

Now you can run `netscoutx` from anywhere.

#### Build `net-scout` (Flag-based CLI)

If you prefer the flag-based CLI or need it for scripting:

```bash
go build -o net-scout ./cmd/net-scout
```

This will create an executable named `net-scout` in your current directory.

## Running NetScoutX with Proper Permissions

NetScoutX's advanced features (passive mode, active ARP requests, TTL-based OS fingerprinting) require access to raw network sockets. This typically means running with elevated privileges.

### Option 1: Run with `sudo` (Simplest)

The easiest way to ensure NetScoutX has the necessary permissions is to run it with `sudo`:

```bash
sudo netscoutx
# or
sudo ./net-scout -subnet 192.168.1.0/24
```

### Option 2: Grant `CAP_NET_RAW` Capability (More Secure)

For a more secure approach, you can grant the `CAP_NET_RAW` and `CAP_NET_ADMIN` capabilities to the `netscoutx` executable, allowing it to access raw sockets without running as root:

```bash
sudo setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/netscoutx
```

*Note: If you rebuild the executable, you will need to reapply these capabilities.*

## Testing Your Installation

You can run the project's unit tests to verify everything is set up correctly:

```bash
go test ./...
```

*Note: Some passive tests require `.pcap` files in `internal/passive/testdata/`. If these are missing, the tests will log a message and skip the relevant checks.*

## Troubleshooting

### Error: "pcap.h: No such file or directory"
This indicates that `libpcap` development headers are missing. Install them as described in the "Prerequisites" section.

### Error: "operation not permitted" or "permission denied"
This usually means NetScoutX is trying to access raw network sockets without sufficient privileges. Run with `sudo` or grant `CAP_NET_RAW` capabilities.

### Error: "listen ip4:icmp"
This error might occur if TTL-based OS fingerprinting is attempted without root privileges or `CAP_NET_RAW`. The tool will still function, but OS guessing via TTL will be disabled.

---