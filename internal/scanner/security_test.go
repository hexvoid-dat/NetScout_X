package scanner

import (
	"testing"
)

func TestAnalyzeARP(t *testing.T) {
	t.Run("ignores placeholder macs", func(t *testing.T) {
		hosts := []Host{
			{IP: "192.168.0.10", MAC: "00:00:00:00:00:00"},
			{IP: "192.168.0.11", MAC: ""},
		}

		if anomalies := AnalyzeARP(hosts); len(anomalies) != 0 {
			t.Fatalf("expected no anomalies, got %v", anomalies)
		}
	})

	t.Run("detects ip conflicts with high severity", func(t *testing.T) {
		hosts := []Host{
			{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:01"},
			{IP: "192.168.1.10", MAC: "aa:bb:cc:dd:ee:02"},
		}

		anomalies := AnalyzeARP(hosts)
		if len(anomalies) != 1 {
			t.Fatalf("expected 1 anomaly, got %d", len(anomalies))
		}
		anomaly := anomalies[0]
		if anomaly.Kind != ARPConflictIP || anomaly.Severity != RiskHigh {
			t.Fatalf("expected high severity IP conflict, got kind=%s, severity=%s", anomaly.Kind, anomaly.Severity)
		}
		if anomaly.IP != "192.168.1.10" {
			t.Fatalf("expected anomaly for IP 192.168.1.10, got %s", anomaly.IP)
		}
	})

	t.Run("detects greedy mac with medium severity", func(t *testing.T) {
		hosts := []Host{
			{IP: "192.168.1.20", MAC: "AA-BB-CC-DD-EE-FF"},
			{IP: "192.168.1.21", MAC: "aa:bb:cc:dd:ee:ff"},
		}

		anomalies := AnalyzeARP(hosts)
		if len(anomalies) != 1 {
			t.Fatalf("expected 1 anomaly, got %d", len(anomalies))
		}
		anomaly := anomalies[0]
		if anomaly.Kind != ARPGreedyMAC || anomaly.Severity != RiskMedium {
			t.Fatalf("expected medium severity greedy MAC, got kind=%s, severity=%s", anomaly.Kind, anomaly.Severity)
		}
		if anomaly.MAC != "aa:bb:cc:dd:ee:ff" {
			t.Fatalf("expected anomaly for MAC aa:bb:cc:dd:ee:ff, got %s", anomaly.MAC)
		}
	})

	t.Run("detects likely gateway with low severity", func(t *testing.T) {
		hosts := []Host{
			{IP: "192.168.1.1", MAC: "aa:bb:cc:dd:ee:ff", OpenPorts: []Port{{Number: 53, Protocol: "udp"}}},
			{IP: "192.168.1.20", MAC: "AA-BB-CC-DD-EE-FF"},
			{IP: "192.168.1.21", MAC: "aa:bb:cc:dd:ee:ff"},
		}

		anomalies := AnalyzeARP(hosts)
		if len(anomalies) != 1 {
			t.Fatalf("expected 1 anomaly, got %d", len(anomalies))
		}
		anomaly := anomalies[0]
		if anomaly.Kind != ARPGreedyMAC || anomaly.Severity != RiskLow {
			t.Fatalf("expected low severity greedy MAC for gateway, got kind=%s, severity=%s", anomaly.Kind, anomaly.Severity)
		}
	})
}