package passive

import "strings"

// ouiMap is a curated list of OUI prefixes to vendors.
// This is not exhaustive but covers many common device manufacturers.
var ouiMap = map[string]string{
	"00:00:0c": "Cisco",
	"00:01:5c": "Netgear",
	"00:03:7f": "Apple",
	"00:09:0f": "Hewlett Packard",
	"00:0c:29": "VMware",
	"00:1a:11": "Google",
	"00:1b:21": "Intel",
	"00:50:56": "VMware",
	"08:00:27": "Oracle (VirtualBox)",
	"0c:4d:e9": "TP-Link",
	"18:b4:30": "Google",
	"2c:f0:ee": "Apple",
	"3c:d9:2b": "Hewlett Packard",
	"40:a6:d9": "Amazon",
	"48:d7:05": "Google",
	"50:c7:bf": "Belkin",
	"70:b3:d5": "Amazon",
	"8c:85:90": "Apple",
	"a4:77:33": "Google",
	"b8:27:eb": "Raspberry Pi Foundation",
	"cc:65:ad": "Intel",
	"d8:eb:97": "Dell",
	"e0:2a:82": "Intel",
	"f4:f5:d8": "Apple",
	"fc:a1:83": "Samsung",
}

// GetVendorFromMAC looks up the vendor from the OUI portion of a MAC address.
func GetVendorFromMAC(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	prefix := strings.ToLower(mac[:8])
	if vendor, ok := ouiMap[prefix]; ok {
		return vendor
	}
	return ""
}
