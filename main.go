package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type config lb bpf/lb.bpf.c -- -O2 -g -I/usr/include/x86_64-linux-gnu

import (
	"encoding/binary"
	"flag"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Order must match the C enum.
var counterNames = []string{"total", "not_ipv4", "not_tcp", "opts_or_frag", "not_vip",
	"port_miss", "matched", "fwd", "encap_err", "redir_err"}

// BPF stores the IP as __be32, so the bytes in memory must be in network order.
func be32(s string) uint32 {
	a := netip.MustParseAddr(s).As4()
	return binary.NativeEndian.Uint32(a[:])
}

func main() {
	iface := flag.String("iface", "eth0", "interface to attach to")
	ip := flag.String("ip", "10.0.1.10", "LB IP (the VIP)")
	portList := flag.String("ports", "8080,9090", "comma-separated TCP ports to intercept")
	backend := flag.String("backend", "10.0.1.20", "backend real IP")
	outerSrc := flag.String("outer-src", "", "outer IPIP source (default: same as -ip)")

	flag.Parse()

	if *outerSrc == "" {
		*outerSrc = *ip
	}

	ifc, err := net.InterfaceByName(*iface)
	if err != nil {
		log.Fatal(err)
	}

	var objs lbObjects
	if err := loadLbObjects(&objs, nil); err != nil {
		log.Fatalf("load: %v", err)
	}
	defer objs.Close()

	cfg := lbConfig{Vip: be32(*ip), Backend: be32(*backend), OuterSrc: be32(*outerSrc)}
	if err := objs.CfgMap.Put(uint32(0), cfg); err != nil {
		log.Fatal(err)
	}
	for _, s := range strings.Split(*portList, ",") {
		p, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
		if err != nil {
			log.Fatalf("bad port %q", s)
		}
		if err := objs.Ports.Put(uint16(p), uint8(1)); err != nil {
			log.Fatal(err)
		}
	}

	l, err := link.AttachTCX(link.TCXOptions{
		Interface: ifc.Index, Program: objs.LbIngress, Attach: ebpf.AttachTCXIngress,
	})
	if err != nil {
		log.Fatalf("attach: %v", err)
	}
	defer l.Close()
	log.Printf("attached to %s, vip=%s ports=%s", *iface, *ip, *portList)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	tick := time.NewTicker(2 * time.Second)
	for {
		select {
		case <-sig:
			return
		case <-tick.C:
			out := ""
			for i, name := range counterNames {
				var perCPU []uint64
				if err := objs.Counters.Lookup(uint32(i), &perCPU); err != nil {
					log.Fatal(err)
				}
				var sum uint64
				for _, v := range perCPU {
					sum += v
				}
				out += name + "=" + strconv.FormatUint(sum, 10) + " "
			}
			log.Println(out)
		}
	}
}
