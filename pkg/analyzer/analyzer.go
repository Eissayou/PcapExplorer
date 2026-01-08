// Package analyzer provides PCAP file parsing and traffic analysis functionality.
//
// This package supports both traditional PCAP and modern PCAPNG file formats,
// automatically detecting the format based on the file's magic bytes. It analyzes
// network traffic relative to a specified target IP address, categorizing packets
// as either "sent" (originating from target) or "received" (destined to target).
//
// # Supported Formats
//
//   - PCAP: Traditional libpcap format (magic: 0xa1b2c3d4 or 0xd4c3b2a1)
//   - PCAPNG: Next-generation format (magic: 0x0A0D0D0A)
//
// # Supported Protocols
//
//   - IPv4: Full support for source/destination IP extraction
//   - IPv6: Full support for source/destination IP extraction
//   - TCP/UDP: Port information available via packet layers (not extracted in analysis)
//
// # Usage Example
//
//	content, err := os.ReadFile("capture.pcap")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	result, err := analyzer.Analyze(content, "192.168.1.100")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	fmt.Printf("Sent %d packets to %d unique IPs\n",
//	    len(result.SentTime), len(result.SentIP))
package analyzer

import (
	"bytes"
	"fmt"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// AnalysisResult contains aggregated statistics from a PCAP analysis.
//
// All traffic is categorized relative to a target IP address:
//   - "Sent" refers to packets originating FROM the target IP
//   - "Received" refers to packets destined TO the target IP
//
// Time-based maps use relative seconds from the first packet's timestamp,
// allowing for easy timeline visualization regardless of capture start time.
type AnalysisResult struct {
	// SentTime maps relative time (seconds from first packet) to the count of
	// packets sent by the target IP during that second.
	SentTime map[int]int `json:"sentTime"`

	// ReceivedTime maps relative time (seconds from first packet) to the count
	// of packets received by the target IP during that second.
	ReceivedTime map[int]int `json:"receivedTime"`

	// SentIP maps destination IP addresses (as strings) to the count of packets
	// sent to each address by the target IP.
	SentIP map[string]int `json:"sentIP"`

	// ReceivedIP maps source IP addresses (as strings) to the count of packets
	// received from each address by the target IP.
	ReceivedIP map[string]int `json:"receivedIP"`

	// SentSize maps relative time (seconds from first packet) to the total bytes
	// of packet data sent by the target IP during that second.
	SentSize map[int]int `json:"sentSize"`
}

// NewAnalysisResult creates and returns a new AnalysisResult with initialized maps.
//
// This constructor ensures all internal maps are properly initialized,
// preventing nil map panics during analysis operations.
//
// Returns:
//   - *AnalysisResult: A pointer to a newly allocated result with empty maps.
func NewAnalysisResult() *AnalysisResult {
	return &AnalysisResult{
		SentTime:     make(map[int]int),
		ReceivedTime: make(map[int]int),
		SentIP:       make(map[string]int),
		ReceivedIP:   make(map[string]int),
		SentSize:     make(map[int]int),
	}
}

// pcapngMagic is the magic byte sequence identifying PCAPNG format files.
// PCAPNG files begin with a Section Header Block (SHB) which starts with 0x0A0D0D0A.
var pcapngMagic = []byte{0x0A, 0x0D, 0x0D, 0x0A}

// Analyze parses a PCAP or PCAPNG file and returns traffic analysis relative to targetIP.
//
// This function automatically detects the file format (PCAP vs PCAPNG) based on
// magic bytes and processes all IP packets in the capture. Packets are categorized
// as "sent" or "received" based on whether the source or destination IP matches
// the target.
//
// Parameters:
//   - content: The complete PCAP/PCAPNG file contents as a byte slice.
//   - targetIP: The IP address to analyze traffic for (e.g., "192.168.1.100").
//
// Returns:
//   - *AnalysisResult: Aggregated traffic statistics, or nil on error.
//   - error: Non-nil if the file cannot be parsed or the target IP is invalid.
//
// Format Detection:
//   - PCAPNG is detected by magic bytes 0x0A0D0D0A at file offset 0.
//   - All other files are assumed to be PCAP format. Invalid PCAP files will
//     return an error from the reader initialization.
//
// Non-IP Packets:
//
//	Packets without an IPv4 or IPv6 layer (e.g., ARP, raw Ethernet) are silently
//	skipped and not included in the analysis.
//
// Note: For PCAPNG files, this function assumes Ethernet link type. PCAP files
// use the link type specified in their file header.
func Analyze(content []byte, targetIP string) (*AnalysisResult, error) {
	reader := bytes.NewReader(content)

	// Read magic bytes to determine file format
	magic := make([]byte, 4)
	if _, err := reader.ReadAt(magic, 0); err != nil {
		return nil, fmt.Errorf("failed to read magic bytes: %w", err)
	}

	var packetSource *gopacket.PacketSource

	// Detect file format and create appropriate reader
	if bytes.Equal(magic, pcapngMagic) {
		// PCAPNG format detected
		ngReader, err := pcapgo.NewNgReader(reader, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to create pcapng reader: %w", err)
		}
		// FIXME: hardcoded to Ethernet, should read link type from interface block
		packetSource = gopacket.NewPacketSource(ngReader, layers.LinkTypeEthernet)
	} else {
		// Assume PCAP format (handles both big and little endian magic)
		pcapReader, err := pcapgo.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to create pcap reader: %w", err)
		}
		packetSource = gopacket.NewPacketSource(pcapReader, pcapReader.LinkType())
	}

	result := NewAnalysisResult()

	var startTime time.Time
	firstPacket := true

	// Parse and validate target IP address
	targetIPNet := net.ParseIP(targetIP)
	if targetIPNet == nil {
		return nil, fmt.Errorf("invalid target IP: %s", targetIP)
	}

	// TODO: consider parallelizing with worker pool for large captures
	for packet := range packetSource.Packets() {
		// Extract source and destination IPs from IPv4 or IPv6 layer
		srcIP, dstIP, ok := extractIPAddresses(packet)
		if !ok {
			continue // Skip non-IP packets (e.g., ARP)
		}

		// Initialize start time from first packet for relative timestamps
		if firstPacket {
			startTime = packet.Metadata().Timestamp
			firstPacket = false
		}

		// Calculate relative time in seconds
		relativeTime := int(packet.Metadata().Timestamp.Sub(startTime).Seconds())

		// Categorize packet as sent or received based on target IP
		if srcIP.Equal(targetIPNet) {
			// Packet sent FROM target IP
			result.SentTime[relativeTime]++
			result.SentSize[relativeTime] += len(packet.Data())
			result.SentIP[dstIP.String()]++
		} else if dstIP.Equal(targetIPNet) {
			// Packet sent TO target IP
			result.ReceivedTime[relativeTime]++
			result.ReceivedIP[srcIP.String()]++
		}
	}

	return result, nil
}

// extractIPAddresses extracts source and destination IP addresses from a packet.
//
// This helper function checks for both IPv4 and IPv6 layers and returns the
// source and destination addresses. It supports mixed IPv4/IPv6 captures.
//
// Parameters:
//   - packet: The gopacket.Packet to extract addresses from.
//
// Returns:
//   - srcIP: Source IP address, or nil if not an IP packet.
//   - dstIP: Destination IP address, or nil if not an IP packet.
//   - ok: True if IP addresses were successfully extracted.
func extractIPAddresses(packet gopacket.Packet) (srcIP, dstIP net.IP, ok bool) {
	// Try IPv4 first (more common)
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		return ip.SrcIP, ip.DstIP, true
	}

	// Fall back to IPv6
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ip, _ := ipv6Layer.(*layers.IPv6)
		return ip.SrcIP, ip.DstIP, true
	}

	// Not an IP packet
	return nil, nil, false
}
