package report

import (
	"testing"

	"github.com/hexe/net-scout/internal/scanner"
)

func TestComputeScanDiff(t *testing.T) {
	oldResult := scanner.ScanResult{
		Hosts: []scanner.Host{
			{
				IP:  "192.168.0.10",
				MAC: "aa:aa:aa:aa:aa:10",
				OpenPorts: []scanner.Port{
					{Number: 22, Protocol: "tcp", State: scanner.StateOpen},
				},
			},
			{
				IP:  "192.168.0.20",
				MAC: "aa:aa:aa:aa:aa:20",
				OpenPorts: []scanner.Port{
					{Number: 443, Protocol: "tcp", State: scanner.StateOpen},
				},
			},
		},
	}

	newResult := scanner.ScanResult{
		Hosts: []scanner.Host{
			{
				IP:  "192.168.0.20",
				MAC: "aa:aa:aa:aa:aa:20",
				OpenPorts: []scanner.Port{
					{Number: 80, Protocol: "tcp", State: scanner.StateOpen},
				},
			},
			{
				IP:  "192.168.0.30",
				MAC: "aa:aa:aa:aa:aa:30",
				OpenPorts: []scanner.Port{
					{Number: 22, Protocol: "tcp", State: scanner.StateOpen},
				},
			},
		},
	}

	diff := ComputeScanDiff(oldResult, newResult)

	if len(diff.NewHosts) != 1 || diff.NewHosts[0].IP != "192.168.0.30" {
		t.Fatalf("expected one new host (192.168.0.30), got %+v", diff.NewHosts)
	}

	if len(diff.MissingHosts) != 1 || diff.MissingHosts[0].IP != "192.168.0.10" {
		t.Fatalf("expected one missing host (192.168.0.10), got %+v", diff.MissingHosts)
	}

	if len(diff.PortChanges) != 1 {
		t.Fatalf("expected one port change entry, got %+v", diff.PortChanges)
	}

	change := diff.PortChanges[0]
	if change.IP != "192.168.0.20" {
		t.Fatalf("expected port change for 192.168.0.20, got %s", change.IP)
	}

	if len(change.NewlyOpen) != 1 || change.NewlyOpen[0] != "80/tcp" {
		t.Fatalf("expected newly open 80/tcp, got %+v", change.NewlyOpen)
	}

	if len(change.NoLongerOpen) != 1 || change.NoLongerOpen[0] != "443/tcp" {
		t.Fatalf("expected closed 443/tcp, got %+v", change.NoLongerOpen)
	}
}
