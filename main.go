package main

import (
    "bytes"
    _"embed"
    "flag"
    "fmt"
    "log"
    "os"
    "os/signal"
    "syscall"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
)

//go:embed ebpf/drop_tcp_packets.c
var dropTcpPacketsProgram []byte

const defaultBlockPort = 4040

func main() {
    // Parse command-line arguments for the port number
    port := flag.Int("port", defaultBlockPort, "TCP port to block")
    flag.Parse()

    // Load the eBPF program
    spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(dropTcpPacketsProgram))
    if err != nil {
        log.Fatalf("failed to load eBPF program: %v", err)
    }

    // Create a new eBPF collection based on the spec
    coll, err := ebpf.NewCollection(spec)
    if err != nil {
        log.Fatalf("failed to create eBPF collection: %v", err)
    }
    defer coll.Close()

    // Find the eBPF map and update the port to block
    blockPortMap := coll.Maps["block_port"]
    if blockPortMap == nil {
        log.Fatalf("failed to find eBPF map: block_port")
    }

    key := uint32(0)
    err = blockPortMap.Update(&key, &(*port), ebpf.UpdateAny)
    if err != nil {
        log.Fatalf("failed to update eBPF map: %v", err)
    }

    // Attach the eBPF program to a network interface (e.g., eth0)
    // Replace 0 with the correct network interface index (use `ip link` to find it)
    ifceIndex := 0 // You need to find and set the correct interface index for your setup
    link, err := link.AttachXDP(link.XDPOptions{
        Program:   coll.Programs["drop_tcp_packets"],
        Interface: ifceIndex,
        Flags:     link.XDPGenericMode,
    })
    if err != nil {
        log.Fatalf("failed to attach XDP program: %v", err)
    }
    defer link.Close()

    fmt.Printf("Blocking TCP packets on port %d\n", *port)

    // Handle termination signals to clean up
    sig := make(chan os.Signal, 1)
    signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
    <-sig

    fmt.Println("Exiting...")
}
