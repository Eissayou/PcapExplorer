// Package analyzer provides PCAP file parsing and traffic analysis functionality.
package analyzer

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// TestAnalyze verifies that the Analyze function correctly categorizes packets
// as sent or received based on the target IP address.
//
// Test scenario:
//   - Packet 1: 192.168.1.1 -> 192.168.1.5 (target receives from .1)
//   - Packet 2: 192.168.1.5 -> 192.168.1.1 (target sends to .1)
//
// Expected results:
//   - ReceivedTime[0] = 1 (target received 1 packet at T=0)
//   - ReceivedIP["192.168.1.1"] = 1 (received 1 packet from .1)
//   - SentTime[1] = 1 (target sent 1 packet at T=1)
//   - SentIP["192.168.1.1"] = 1 (sent 1 packet to .1)
func TestAnalyze(t *testing.T) {
	// Create in-memory PCAP file
	buf := new(bytes.Buffer)
	w := pcapgo.NewWriter(buf)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("WriteFileHeader: %v", err)
	}

	// Create Ethernet layer (shared between packets)
	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66},
		EthernetType: layers.EthernetTypeIPv4,
	}

	// --- Packet 1: External (192.168.1.1) -> Target (192.168.1.5) ---
	ip1 := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 1},
		DstIP:    net.IP{192, 168, 1, 5},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp1 := &layers.TCP{
		SrcPort: layers.TCPPort(1234),
		DstPort: layers.TCPPort(80),
		Seq:     111,
	}
	tcp1.SetNetworkLayerForChecksum(ip1)

	sb1 := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(sb1, opts, eth, ip1, tcp1); err != nil {
		t.Fatalf("SerializeLayers packet 1: %v", err)
	}
	packetData1 := sb1.Bytes()
	t.Logf("Packet1 Data (%d bytes): %x", len(packetData1), packetData1)

	baseTime := time.Now()
	ci1 := gopacket.CaptureInfo{
		Timestamp:      baseTime,
		CaptureLength:  len(packetData1),
		Length:         len(packetData1),
		InterfaceIndex: 0,
	}
	if err := w.WritePacket(ci1, packetData1); err != nil {
		t.Fatalf("WritePacket packet 1: %v", err)
	}

	// --- Packet 2: Target (192.168.1.5) -> External (192.168.1.1) ---
	ip2 := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 1, 5},
		DstIP:    net.IP{192, 168, 1, 1},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcp2 := &layers.TCP{
		SrcPort: layers.TCPPort(80),
		DstPort: layers.TCPPort(1234),
		Seq:     222,
		Ack:     112,
	}
	tcp2.SetNetworkLayerForChecksum(ip2)

	sb2 := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(sb2, opts, eth, ip2, tcp2); err != nil {
		t.Fatalf("SerializeLayers packet 2: %v", err)
	}
	packetData2 := sb2.Bytes()
	t.Logf("Packet2 Data (%d bytes): %x", len(packetData2), packetData2)

	ci2 := gopacket.CaptureInfo{
		Timestamp:      baseTime.Add(1 * time.Second),
		CaptureLength:  len(packetData2),
		Length:         len(packetData2),
		InterfaceIndex: 0,
	}
	if err := w.WritePacket(ci2, packetData2); err != nil {
		t.Fatalf("WritePacket packet 2: %v", err)
	}

	// --- Run Analyze ---
	res, err := Analyze(buf.Bytes(), "192.168.1.5")
	if err != nil {
		t.Fatalf("Analyze failed: %v", err)
	}

	// --- Verify received traffic (packets TO target) ---
	// Packet 1: Received by 192.168.1.5 at T=0
	if res.ReceivedTime[0] != 1 {
		t.Errorf("ReceivedTime[0]: expected 1, got %d", res.ReceivedTime[0])
	}
	if res.ReceivedIP["192.168.1.1"] != 1 {
		t.Errorf("ReceivedIP[192.168.1.1]: expected 1, got %d", res.ReceivedIP["192.168.1.1"])
	}

	// --- Verify sent traffic (packets FROM target) ---
	// Packet 2: Sent by 192.168.1.5 at T=1
	if res.SentTime[1] != 1 {
		t.Errorf("SentTime[1]: expected 1, got %d", res.SentTime[1])
	}
	if res.SentIP["192.168.1.1"] != 1 {
		t.Errorf("SentIP[192.168.1.1]: expected 1, got %d", res.SentIP["192.168.1.1"])
	}

	// Verify that SentSize was tracked
	if res.SentSize[1] <= 0 {
		t.Errorf("SentSize[1]: expected positive value, got %d", res.SentSize[1])
	}
}

// TestAnalyzeInvalidIP verifies that Analyze returns an error for invalid target IPs.
func TestAnalyzeInvalidIP(t *testing.T) {
	// Create minimal valid PCAP file
	buf := new(bytes.Buffer)
	w := pcapgo.NewWriter(buf)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("WriteFileHeader: %v", err)
	}

	// Test with invalid IP format
	_, err := Analyze(buf.Bytes(), "not-an-ip")
	if err == nil {
		t.Error("expected error for invalid IP, got nil")
	}
}

// TestAnalyzeEmptyPcap verifies that Analyze handles empty PCAP files gracefully.
func TestAnalyzeEmptyPcap(t *testing.T) {
	// Create PCAP file with no packets
	buf := new(bytes.Buffer)
	w := pcapgo.NewWriter(buf)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		t.Fatalf("WriteFileHeader: %v", err)
	}

	res, err := Analyze(buf.Bytes(), "192.168.1.5")
	if err != nil {
		t.Fatalf("Analyze failed on empty pcap: %v", err)
	}

	// All maps should be empty
	if len(res.SentTime) != 0 {
		t.Errorf("SentTime should be empty, got %d entries", len(res.SentTime))
	}
	if len(res.ReceivedTime) != 0 {
		t.Errorf("ReceivedTime should be empty, got %d entries", len(res.ReceivedTime))
	}
}

// TestNewAnalysisResult verifies that NewAnalysisResult initializes all maps.
func TestNewAnalysisResult(t *testing.T) {
	result := NewAnalysisResult()

	if result == nil {
		t.Fatal("NewAnalysisResult returned nil")
	}

	// Verify all maps are initialized (not nil)
	if result.SentTime == nil {
		t.Error("SentTime map is nil")
	}
	if result.ReceivedTime == nil {
		t.Error("ReceivedTime map is nil")
	}
	if result.SentIP == nil {
		t.Error("SentIP map is nil")
	}
	if result.ReceivedIP == nil {
		t.Error("ReceivedIP map is nil")
	}
	if result.SentSize == nil {
		t.Error("SentSize map is nil")
	}
}
