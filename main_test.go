package main

import (
	"net"
	"testing"
)

func TestParseIPs(t *testing.T) {
	input := "192.168.1.10, 10.0.0.1, invalid, 172.16.0.5"
	ips := parseIPs(input)

	if len(ips) != 3 {
		t.Fatalf("Expected 3 valid IPs, got %d", len(ips))
	}

	if !ips[0].Equal(net.ParseIP("192.168.1.10")) {
		t.Errorf("IP 0 mismatch: %v", ips[0])
	}
	if !ips[1].Equal(net.ParseIP("10.0.0.1")) {
		t.Errorf("IP 1 mismatch: %v", ips[1])
	}
	if !ips[2].Equal(net.ParseIP("172.16.0.5")) {
		t.Errorf("IP 2 mismatch: %v", ips[2])
	}
}
