package passive

import (
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// parseJA3 processes a TLS ClientHello packet to generate a JA3 fingerprint.
func (e *Engine) parseJA3(packet gopacket.Packet) {
	tcpLayer, ok := packet.Layer(layers.LayerTypeTCP).(*layers.TCP)
	if !ok {
		return
	}

	payload := tcpLayer.Payload
	if len(payload) == 0 {
		return
	}

	ja3String, err := extractJA3String(payload)
	if err != nil {
		return
	}
	ja3Hash := fmt.Sprintf("%x", md5.Sum([]byte(ja3String)))

	var srcIP string
	if ipv4Layer, ok := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4); ok {
		srcIP = ipv4Layer.SrcIP.String()
	} else if ipv6Layer, ok := packet.Layer(layers.LayerTypeIPv6).(*layers.IPv6); ok {
		srcIP = ipv6Layer.SrcIP.String()
	}

	var mac string
	if ethLayer, ok := packet.Layer(layers.LayerTypeEthernet).(*layers.Ethernet); ok {
		mac = ethLayer.SrcMAC.String()
	}

	resultMutex.Lock()
	defer resultMutex.Unlock()

	var host *Host
	var created bool
	if mac != "" {
		host, created = e.ensureHostLocked(mac)
		if created {
			log.Printf("Passive JA3: discovered new host %s via TLS", mac)
		}
	}

	if host == nil && srcIP != "" {
		for _, h := range e.Result.Hosts {
			if _, ok := h.IPs[srcIP]; ok {
				host = h
				break
			}
		}
	}

	if host == nil {
		return
	}

	if srcIP != "" {
		host.IPs[srcIP] = time.Now()
	}

	before := len(host.JA3Fingerprints)
	addUniqueString(&host.JA3Fingerprints, ja3Hash)
	after := len(host.JA3Fingerprints)
	if after == before {
		return // already recorded
	}

	obs := e.recordJA3Observation(ja3Hash, mac)
	isRare := !isCommonJA3(ja3Hash) && obs.Count <= ja3RareObservationThreshold
	if isRare {
		addUniqueString(&host.RareJA3Fingerprints, ja3Hash)
	}

	log.Printf("Passive JA3: new fingerprint %s for host %s (%s)", ja3Hash, host.MAC, srcIP)
}

func (e *Engine) recordJA3Observation(hash, source string) *JA3Observation {
	obs, exists := e.Result.JA3Observatory[hash]
	if !exists {
		obs = &JA3Observation{Fingerprint: hash, FirstSeen: time.Now()}
		e.Result.JA3Observatory[hash] = obs
	}
	obs.Count++
	obs.LastSeen = time.Now()
	obs.LastSource = source
	return obs
}

func extractJA3String(payload []byte) (string, error) {
	if len(payload) < 45 {
		return "", fmt.Errorf("payload too short for TLS record")
	}

	if payload[0] != 0x16 { // Handshake
		return "", fmt.Errorf("not a handshake record")
	}

	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	if len(payload) < 5+recordLen {
		return "", fmt.Errorf("truncated TLS record")
	}
	record := payload[5 : 5+recordLen]
	if len(record) < 4 || record[0] != 0x01 { // ClientHello
		return "", fmt.Errorf("missing client hello")
	}

	handshakeLen := int(record[1])<<16 | int(record[2])<<8 | int(record[3])
	if len(record[4:]) < handshakeLen {
		return "", fmt.Errorf("client hello truncated")
	}
	body := record[4 : 4+handshakeLen]
	if len(body) < 34 {
		return "", fmt.Errorf("client hello missing mandatory fields")
	}

	clientVersion := binary.BigEndian.Uint16(body[0:2])
	offset := 2 + 32 // version + random

	if len(body) < offset+1 {
		return "", fmt.Errorf("missing session id length")
	}
	sessionLen := int(body[offset])
	offset++
	if len(body) < offset+sessionLen {
		return "", fmt.Errorf("invalid session id length")
	}
	offset += sessionLen

	if len(body) < offset+2 {
		return "", fmt.Errorf("missing cipher length")
	}
	cipherLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if len(body) < offset+cipherLen {
		return "", fmt.Errorf("cipher list truncated")
	}
	cipherBytes := body[offset : offset+cipherLen]
	offset += cipherLen

	if len(body) < offset+1 {
		return "", fmt.Errorf("missing compression length")
	}
	compLen := int(body[offset])
	offset++
	if len(body) < offset+compLen {
		return "", fmt.Errorf("compression list truncated")
	}
	offset += compLen

	var extBytes []byte
	if len(body) > offset {
		if len(body) < offset+2 {
			return "", fmt.Errorf("missing extensions length")
		}
		extLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
		offset += 2
		if len(body) < offset+extLen {
			return "", fmt.Errorf("extensions truncated")
		}
		extBytes = body[offset : offset+extLen]
	}

	cipherList := serializeCipherSuites(cipherBytes)
	extensions, curves, formats := parseExtensions(extBytes)

	ja3Parts := []string{
		strconv.Itoa(int(clientVersion)),
		strings.Join(cipherList, "-"),
		strings.Join(extensions, "-"),
		strings.Join(curves, "-"),
		strings.Join(formats, "-"),
	}

	return strings.Join(ja3Parts, ","), nil
}

func serializeCipherSuites(data []byte) []string {
	var suites []string
	for i := 0; i+1 < len(data); i += 2 {
		value := binary.BigEndian.Uint16(data[i : i+2])
		if isGREASEValue(value) {
			continue
		}
		suites = append(suites, strconv.Itoa(int(value)))
	}
	return suites
}

func parseExtensions(data []byte) ([]string, []string, []string) {
	if len(data) == 0 {
		return []string{}, []string{}, []string{}
	}
	var extensions, curves, formats []string
	idx := 0
	for idx+4 <= len(data) {
		extType := binary.BigEndian.Uint16(data[idx : idx+2])
		extLen := int(binary.BigEndian.Uint16(data[idx+2 : idx+4]))
		idx += 4
		if idx+extLen > len(data) {
			break
		}
		payload := data[idx : idx+extLen]
		idx += extLen

		if !isGREASEValue(extType) {
			extensions = append(extensions, strconv.Itoa(int(extType)))
		}

		switch extType {
		case 0x000a: // supported groups
			curves = parseNamedGroups(payload)
		case 0x000b: // ec point formats
			formats = parsePointFormats(payload)
		}
	}
	return extensions, curves, formats
}

func parseNamedGroups(data []byte) []string {
	if len(data) < 2 {
		return nil
	}
	total := int(binary.BigEndian.Uint16(data[0:2]))
	if total > len(data)-2 {
		total = len(data) - 2
	}
	payload := data[2 : 2+total]
	var groups []string
	for i := 0; i+1 < len(payload); i += 2 {
		value := binary.BigEndian.Uint16(payload[i : i+2])
		if isGREASEValue(value) {
			continue
		}
		groups = append(groups, strconv.Itoa(int(value)))
	}
	return groups
}

func parsePointFormats(data []byte) []string {
	if len(data) < 1 {
		return nil
	}
	total := int(data[0])
	if total > len(data)-1 {
		total = len(data) - 1
	}
	payload := data[1 : 1+total]
	var formats []string
	for _, b := range payload {
		formats = append(formats, strconv.Itoa(int(b)))
	}
	return formats
}
