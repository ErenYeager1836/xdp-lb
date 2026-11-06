# xdp-lb

A high-performance Layer-4 (L4) load balancer and packet router written in **C** and **Go**, powered by **eBPF and XDP (eXpress Data Path)**.

`xdp-lb` intercepts network packets at the lowest possible layer in the Linux kernel—directly inside the network device driver before memory allocation (`sk_buff`) or the Linux networking stack (`netfilter/iptables`).

---

## Architecture

```text
[ Incoming Ingress Packet ]
           │
           ▼
[ Network Interface Driver (XDP Hook) ]
  ├── 1. Parse Ethernet & IPv4 Headers (Bounds-checked for BPF verifier)
  ├── 2. 5-Tuple Hash across Source & Destination IP
  ├── 3. Dynamic Backend Lookup from BPF Array Map (O(1))
  ├── 4. In-place IP Rewrite & Incremental Checksum recalculation
  └── 5. XDP_TX (Redirect immediately back out NIC) or XDP_PASS
```

---

## Features

- **Kernel-Bypass Performance**:
  - Drops latency to sub-microsecond levels by processing packets before kernel socket buffers are allocated.
- **Dynamic Backend Management**:
  - Userspace daemon dynamically registers, adds, and removes backend pool IPs directly inside BPF Maps without recompilation or connection interruption.
- **Embedded eBPF Bytecode**:
  - Compiles the C XDP kernel program via `bpf2go` into a self-contained, statically linked Go binary.
- **Real-Time Telemetry**:
  - Maintains atomic counters in `BPF_MAP_TYPE_ARRAY` for total packet ingress vs forwarded traffic.

---

## Quick Start

### 1. Requirements
- Linux kernel 5.4+ with XDP driver support
- Clang & LLVM
- Go 1.22+

### 2. Build
```bash
go generate ./...
go build -ldflags="-s -w" -o xdp-lb .
```

### 3. Run
```bash
# Attach XDP load balancer to loopback or ethernet interface
sudo ./xdp-lb -iface lo -backends 192.168.1.10,192.168.1.20
```

---

## License
Dual MIT/GPL
