package main

//go:generate bpf2go -target bpfel xdplb ./bpf/xdp_lb.bpf.c -- -I/usr/include -I/usr/include/x86_64-linux-gnu
