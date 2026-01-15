// Package main provides a command-line utility for generating test PCAP files.
//
// This utility creates synthetic network packet captures for testing and development
// purposes. It generates valid PCAP files with configurable Ethernet, IPv4, and TCP
// layer data that can be used to validate pcap analyzer functionality.
//
// Usage:
//
//	go run gen_pcap.go
//
// Output:
//
//	Creates a file named "test.pcap" in the current directory containing
//	two TCP packets simulating a simple request-response exchange.
package main

import (
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// main initializes the PCAP file writer and generates sample network packets.
//
// The function creates a test.pcap file containing two packets:
//   - Packet 1: 192.168.1.1:1234 -> 192.168.1.5:80 (simulating an HTTP request)
//   - Packet 2: 192.168.1.5:80 -> 192.168.1.1:1234 (simulating an HTTP response)
//
// The generated file uses the standard PCAP format with Ethernet link type
// and a maximum snapshot length of 65536 bytes.
func main() {
	f, err := os.Create("test.pcap")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		log.Fatalf("failed to write file header: %v", err)
	}

	// Packet 1: 192.168.1.1 -> 192.168.1.5 (client to server)
	if err := writePacket(w, "192.168.1.1", "192.168.1.5", 1234, 80); err != nil {
		log.Fatalf("failed to write packet 1: %v", err)
	}

	// Packet 2: 192.168.1.5 -> 192.168.1.1 (server to client)
	if err := writePacket(w, "192.168.1.5", "192.168.1.1", 80, 1234); err != nil {
		log.Fatalf("failed to write packet 2: %v", err)
	}

	log.Println("Successfully created test.pcap")
}

// writePacket constructs and writes a single TCP/IP packet to the PCAP file.
//
// The function creates a complete network packet with Ethernet, IPv4, and TCP layers,
// serializes it with proper checksums and lengths, and writes it to the PCAP writer.
//
// Parameters:
//   - w: The PCAP writer to write the packet to.
//   - srcIP: Source IP address as a string (e.g., "192.168.1.1").
//   - dstIP: Destination IP address as a string (e.g., "192.168.1.5").
//   - srcPort: Source TCP port number.
//   - dstPort: Destination TCP port number.
//
// Returns:
//   - error: Non-nil if serialization or writing fails.
//
// The packet is written with the current timestamp and uses placeholder MAC addresses
// (all zeros). The IPv4 header is configured with a TTL of 64, which is standard
// for most operating systems.
func writePacket(w *pcapgo.Writer, srcIP, dstIP string, srcPort, dstPort int) error {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	// Construct Ethernet layer with placeholder MAC addresses
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstMAC:       net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// Construct IPv4 layer
	ip := &layers.IPv4{
		SrcIP:    net.ParseIP(srcIP),
		DstIP:    net.ParseIP(dstIP),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}

	// Construct TCP layer
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
	}

	// Set network layer for TCP checksum calculation
	tcp.SetNetworkLayerForChecksum(ip)

	// Serialize all layers into the packet buffer
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp); err != nil {
		return err
	}

	// Construct capture metadata
	ci := gopacket.CaptureInfo{
		Timestamp:     time.Now(),
		CaptureLength: len(buf.Bytes()),
		Length:        len(buf.Bytes()),
	}

	// Write packet to PCAP file
	return w.WritePacket(ci, buf.Bytes())
}
