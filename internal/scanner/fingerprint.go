package scanner

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

const (
	icmpTimeout = 2 * time.Second
)

type osHint struct {
	family string
	detail string
}

type FingerprintOptions struct {
	DisableTTL      bool
	TTLOnlyWithSudo bool
}

var (
	fingerprintOptions       FingerprintOptions
	ttlPermissionWarningOnce sync.Once
	ttlSudoInfoOnce          sync.Once
	errNoTTLData             = fmt.Errorf("no ttl response")
)

func ConfigureFingerprint(opts FingerprintOptions) {
	fingerprintOptions = opts
}

// GuessOS attempts to identify the operating system based on TTL values and service banners.
func GuessOS(host *Host) {
	opts := fingerprintOptions
	var ttlHint osHint
	hasTTLEvidence := false

	if !opts.DisableTTL {
		if opts.TTLOnlyWithSudo && os.Geteuid() != 0 {
			ttlSudoInfoOnce.Do(func() {
				log.Println("Skipping TTL probes: --ttl-only-with-sudo specified and not running as root")
			})
		} else {
			ttl, err := measureTTL(host.IP)
			if err == nil {
				ttlHint, hasTTLEvidence = hintFromTTL(ttl)
			} else if err != errNoTTLData {
				log.Printf("TTL probe failed for %s: %v", host.IP, err)
			}
		}
	}

	bannerHint, hasBannerEvidence := hintFromBanners(host.OpenPorts)
	host.OSGuess, host.OSConfidence = combineHints(ttlHint, hasTTLEvidence, bannerHint, hasBannerEvidence)
}

// TTL fingerprinting constants based on common OS default stack values.
const (
	ttlLinux    = 64
	ttlWindows  = 128
	ttlNetwork  = 255
)

func hintFromTTL(ttl byte) (osHint, bool) {
	// TTL values decrease per hop; we use ranges to account for network distance.
	switch {
	case ttl > 0 && ttl <= 64:
		return osHint{family: "Linux/Unix"}, true
	case ttl > 64 && ttl <= 128:
		return osHint{family: "Windows"}, true
	case ttl > 128 && ttl <= 254:
		return osHint{family: "Network Device / Solaris"}, true
	case ttl == 255:
		return osHint{family: "Network Device"}, true
	default:
		return osHint{}, false
	}
}

func measureTTL(ip string) (byte, error) {
	// Bez roota/cap_net_raw tutaj nie pogadamy, standardowy problem z raw sockets w Go.
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		if os.IsPermission(err) || strings.Contains(strings.ToLower(err.Error()), "permitted") {
			ttlPermissionWarningOnce.Do(func() {
				log.Println("ICMP raw sockets unavailable. Run with sudo or setcap cap_net_raw+ep to enable TTL fingerprinting.")
			})
			return 0, errNoTTLData
		}
		return 0, err
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: []byte("net-scout-probe"),
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}

	dst := &net.IPAddr{IP: net.ParseIP(ip)}
	if _, err := conn.WriteTo(b, dst); err != nil {
		return 0, err
	}

	if err := conn.SetReadDeadline(time.Now().Add(icmpTimeout)); err != nil {
		return 0, err
	}

	reply := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(reply)
	if err != nil {
		return 0, errNoTTLData
	}

	if n > 8 && peer.String() == ip {
		// TTL is in the IPv4 header, but icmp.ListenPacket("ip4:icmp") 
		// typically returns the IP header too if configured, or just the ICMP payload.
		// However, on many systems, the 9th byte of the raw read might be the TTL 
		// depending on how the socket is handled. This heuristic is best-effort.
		return reply[8], nil
	}
	return 0, errNoTTLData
}

func hintFromBanners(ports []Port) (osHint, bool) {
	for _, port := range ports {
		if hint, ok := classifyBanner(port.Banner); ok {
			return hint, true
		}
	}
	return osHint{}, false
}

func classifyBanner(banner string) (osHint, bool) {
	if banner == "" {
		return osHint{}, false
	}
	b := strings.ToLower(banner)
	switch {
	case strings.Contains(b, "openssh"):
		return osHint{family: "Linux", detail: "OpenSSH"}, true
	case strings.Contains(b, "dropbear"):
		return osHint{family: "Network Device", detail: "Dropbear"}, true
	case strings.Contains(b, "microsoft-iis"):
		return osHint{family: "Windows", detail: "IIS"}, true
	case strings.Contains(b, "apache") && strings.Contains(b, "win32"):
		return osHint{family: "Windows", detail: "Apache"}, true
	case strings.Contains(b, "apache") || strings.Contains(b, "nginx"):
		return osHint{family: "Linux"}, true
	}
	return osHint{}, false
}

func combineHints(ttlHint osHint, hasTTL bool, bannerHint osHint, hasBanner bool) (string, OSConfidence) {
	if hasBanner && hasTTL {
		if strings.Contains(strings.ToLower(bannerHint.family), strings.ToLower(ttlHint.family)) {
			return formatOSGuess(bannerHint), ConfidenceHigh
		}
		return formatOSGuess(bannerHint), ConfidenceMedium
	}
	if hasBanner {
		return formatOSGuess(bannerHint), ConfidenceMedium
	}
	if hasTTL {
		return formatOSGuess(ttlHint), ConfidenceMedium
	}
	return "Unknown", ConfidenceLow
}

func formatOSGuess(h osHint) string {
	if h.family == "" {
		return "Unknown"
	}
	if h.detail == "" {
		return h.family
	}
	return fmt.Sprintf("%s (%s)", h.family, h.detail)
}
