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

// generateLargePcap creates a synthetic PCAP file with the specified number of TCP packets.
// Packets alternate between sent and received relative to the target IP 192.168.1.5.
// Uses random source IPs to simulate realistic traffic patterns.
func generateLargePcap(numPackets int) ([]byte, error) {
	buf := new(bytes.Buffer)
	w := pcapgo.NewWriter(buf)
	if err := w.WriteFileHeader(65536, layers.LinkTypeEthernet); err != nil {
		return nil, err
	}

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		DstMAC:       net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x66},
		EthernetType: layers.EthernetTypeIPv4,
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	baseTime := time.Now()
	targetIP := net.IP{192, 168, 1, 5}

	for i := 0; i < numPackets; i++ {
		// Generate varying external IPs to simulate different hosts
		externalIP := net.IP{10, byte(i % 256), byte((i / 256) % 256), byte((i / 65536) % 256)}

		var ip *layers.IPv4
		var tcp *layers.TCP

		// Alternate between sent and received packets
		if i%2 == 0 {
			// Packet TO target (received by target)
			ip = &layers.IPv4{
				SrcIP:    externalIP,
				DstIP:    targetIP,
				Version:  4,
				TTL:      64,
				Protocol: layers.IPProtocolTCP,
			}
			tcp = &layers.TCP{
				SrcPort: layers.TCPPort(1024 + (i % 60000)),
				DstPort: layers.TCPPort(80),
				Seq:     uint32(i * 100),
			}
		} else {
			// Packet FROM target (sent by target)
			ip = &layers.IPv4{
				SrcIP:    targetIP,
				DstIP:    externalIP,
				Version:  4,
				TTL:      64,
				Protocol: layers.IPProtocolTCP,
			}
			tcp = &layers.TCP{
				SrcPort: layers.TCPPort(80),
				DstPort: layers.TCPPort(1024 + (i % 60000)),
				Seq:     uint32(i * 100),
				Ack:     uint32(i*100 + 1),
			}
		}
		tcp.SetNetworkLayerForChecksum(ip)

		// Add some payload data to simulate real traffic
		payload := make([]byte, 100+(i%400)) // Variable payload 100-500 bytes

		sb := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(sb, opts, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
			return nil, err
		}

		packetData := sb.Bytes()
		ci := gopacket.CaptureInfo{
			Timestamp:      baseTime.Add(time.Duration(i) * time.Millisecond),
			CaptureLength:  len(packetData),
			Length:         len(packetData),
			InterfaceIndex: 0,
		}
		if err := w.WritePacket(ci, packetData); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// TestAnalyzeLargeDataset tests processing a large number of packets and reports timing.
// This is useful for understanding the performance characteristics of parallel processing.
func TestAnalyzeLargeDataset(t *testing.T) {
	packetCounts := []int{1000, 10000, 50000, 100000}

	for _, numPackets := range packetCounts {
		t.Run(formatPacketCount(numPackets), func(t *testing.T) {
			// Generate test data
			t.Logf("Generating %d packets...", numPackets)
			genStart := time.Now()
			pcapData, err := generateLargePcap(numPackets)
			if err != nil {
				t.Fatalf("Failed to generate PCAP: %v", err)
			}
			genDuration := time.Since(genStart)
			t.Logf("Generation took %v (%.2f MB)", genDuration, float64(len(pcapData))/(1024*1024))

			// Run the analysis and measure time
			t.Logf("Analyzing %d packets...", numPackets)
			analysisStart := time.Now()
			result, err := Analyze(pcapData, "192.168.1.5")
			analysisDuration := time.Since(analysisStart)

			if err != nil {
				t.Fatalf("Analyze failed: %v", err)
			}

			// Calculate statistics
			totalSent := 0
			totalReceived := 0
			for _, v := range result.SentTime {
				totalSent += v
			}
			for _, v := range result.ReceivedTime {
				totalReceived += v
			}

			packetsPerSecond := float64(numPackets) / analysisDuration.Seconds()

			t.Logf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
			t.Logf("📊 Results for %d packets:", numPackets)
			t.Logf("   ⏱️  Analysis time:     %v", analysisDuration)
			t.Logf("   🚀 Packets/second:    %.0f", packetsPerSecond)
			t.Logf("   📤 Total sent:        %d packets", totalSent)
			t.Logf("   📥 Total received:    %d packets", totalReceived)
			t.Logf("   🌐 Unique sent IPs:   %d", len(result.SentIP))
			t.Logf("   🌐 Unique recv IPs:   %d", len(result.ReceivedIP))
			t.Logf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

			// Verify results are reasonable (alternating packets = ~50/50 split)
			expectedPerSide := numPackets / 2
			tolerance := numPackets / 10 // Allow 10% variance

			if totalSent < expectedPerSide-tolerance || totalSent > expectedPerSide+tolerance {
				t.Errorf("Sent count %d is outside expected range [%d, %d]",
					totalSent, expectedPerSide-tolerance, expectedPerSide+tolerance)
			}
			if totalReceived < expectedPerSide-tolerance || totalReceived > expectedPerSide+tolerance {
				t.Errorf("Received count %d is outside expected range [%d, %d]",
					totalReceived, expectedPerSide-tolerance, expectedPerSide+tolerance)
			}
		})
	}
}

// formatPacketCount returns a human-readable string for packet counts (e.g., "100K")
func formatPacketCount(n int) string {
	if n >= 1000000 {
		return string(rune('0'+n/1000000)) + "M"
	}
	if n >= 1000 {
		return string(rune('0'+n/1000)) + "K"
	}
	return string(rune('0' + n))
}

// BenchmarkAnalyze provides standard Go benchmarks for the Analyze function.
// Run with: go test -bench=. -benchmem ./internal/analyzer/...
func BenchmarkAnalyze(b *testing.B) {
	benchmarks := []struct {
		name       string
		numPackets int
	}{
		{"1K_packets", 1000},
		{"10K_packets", 10000},
		{"50K_packets", 50000},
	}

	for _, bm := range benchmarks {
		// Generate data once before benchmark loop
		pcapData, err := generateLargePcap(bm.numPackets)
		if err != nil {
			b.Fatalf("Failed to generate PCAP for %s: %v", bm.name, err)
		}

		b.Run(bm.name, func(b *testing.B) {
			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := Analyze(pcapData, "192.168.1.5")
				if err != nil {
					b.Fatalf("Analyze failed: %v", err)
				}
			}
		})
	}
}
