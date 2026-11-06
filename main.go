package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	ifaceName := flag.String("iface", "lo", "Network interface to attach XDP load balancer to")
	backendsFlag := flag.String("backends", "10.0.0.1,10.0.0.2", "Comma-separated backend IPv4 addresses")
	flag.Parse()

	fmt.Println("==================================================================")
	fmt.Println(" ⚡ xdp-lb - High-Performance Layer-4 XDP Load Balancer in Go")
	fmt.Println("==================================================================")

	// Remove memlock limit for BPF map allocation
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("Warning: remove memlock: %v", err)
	}

	iface, err := net.InterfaceByName(*ifaceName)
	if err != nil {
		log.Fatalf("Invalid interface %s: %v", *ifaceName, err)
	}

	// Load pre-compiled XDP eBPF program
	var objs xdplbObjects
	if err := loadXdplbObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load XDP objects: %v (Requires sudo/CAP_NET_ADMIN)", err)
	}
	defer objs.Close()

	// Populate backend pool
	backendList := parseIPs(*backendsFlag)
	for i, ip := range backendList {
		var key uint32 = uint32(i)
		ipInt := binary.LittleEndian.Uint32(ip.To4())
		if err := objs.Backends.Put(key, ipInt); err != nil {
			log.Fatalf("Failed to register backend %s: %v", ip, err)
		}
		fmt.Printf("  [✓] Registered Backend [%d]: %s\n", i, ip)
	}

	// Attach XDP to interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpLoadBalancer,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP to %s: %v", *ifaceName, err)
	}
	defer l.Close()

	fmt.Printf("  [✓] XDP kernel hook attached to interface '%s' (Index %d)\n", *ifaceName, iface.Index)
	fmt.Println("==================================================================")
	fmt.Println("Forwarding L4 packets at the network driver layer... (Ctrl+C to stop)")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sigChan:
			fmt.Println("\nDetaching XDP program and exiting...")
			return
		case <-ticker.C:
			var totalPkts, fwdPkts uint64
			var k0, k1 uint32 = 0, 1
			_ = objs.LbStats.Lookup(k0, &totalPkts)
			_ = objs.LbStats.Lookup(k1, &fwdPkts)
			fmt.Printf("  [Stats] Total packets: %-8d | Forwarded through XDP: %-8d\n", totalPkts, fwdPkts)
		}
	}
}

func parseIPs(csv string) []net.IP {
	var ips []net.IP
	for _, s := range splitComma(csv) {
		s = strings.TrimSpace(s)
		if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
			ips = append(ips, ip)
		}
	}
	return ips
}

func splitComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
