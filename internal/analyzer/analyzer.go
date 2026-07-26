// Package analyzer provides PCAP file parsing and TCP traffic analysis functionality.
//
// This package supports both traditional PCAP and modern PCAPNG file formats,
// automatically detecting the format based on the file's magic bytes. It analyzes
// TCP network traffic relative to a specified target IP address, categorizing packets
// as either "sent" (originating from target) or "received" (destined to target).
// Non-TCP packets (UDP, ICMP, etc.) are automatically filtered out.
//
// # Supported Formats
//
//   - PCAP: Traditional libpcap format (magic: 0xa1b2c3d4 or 0xd4c3b2a1)
//   - PCAPNG: Next-generation format (magic: 0x0A0D0D0A)
//
// # Supported Protocols
//
//   - TCP only: Analyzes TCP packets over both IPv4 and IPv6
//   - IPv4: Full support for source/destination IP extraction
//   - IPv6: Full support for source/destination IP extraction
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
//	fmt.Printf("Sent %d TCP packets to %d unique IPs\n",
//	    len(result.SentTime), len(result.SentIP))
package analyzer

import (
	"bytes"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"sync"

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

	// ReceivedSize maps relative time (seconds from first packet) to the total
	// bytes of packet data received by the target IP during that second.
	ReceivedSize map[int]int `json:"receivedSize"`

	// Hosts maps every IP address seen in the capture to the number of TCP
	// packets it appears in, as either source or destination. It does not depend
	// on the target IP, which is what lets a caller offer "analyze this host
	// instead" without reparsing the file.
	Hosts map[string]int `json:"hosts"`
}

// partial is what a single worker accumulates during the map phase.
//
// It mirrors AnalysisResult, except that addresses are keyed by netip.Addr
// rather than string. netip.Addr is a comparable value, so using it as a map key
// costs no allocation, while net.IP.String() would allocate twice for every
// packet in the capture. The keys are converted once, at the end of the reduce
// phase, in finalize.
type partial struct {
	sentTime     map[int]int
	receivedTime map[int]int
	sentSize     map[int]int
	receivedSize map[int]int
	sentIP       map[netip.Addr]int
	receivedIP   map[netip.Addr]int
	hosts        map[netip.Addr]int
}

func newPartial() *partial {
	return &partial{
		sentTime:     make(map[int]int),
		receivedTime: make(map[int]int),
		sentSize:     make(map[int]int),
		receivedSize: make(map[int]int),
		sentIP:       make(map[netip.Addr]int),
		receivedIP:   make(map[netip.Addr]int),
		hosts:        make(map[netip.Addr]int),
	}
}

// mergeCounts adds every count in src to dest. It is the one operation the
// reduce phase performs, over each of a partial's tallies in turn.
func mergeCounts[K comparable](dest, src map[K]int) {
	for k, v := range src {
		dest[k] += v
	}
}

// merge folds another worker's tallies into p during the reduce phase.
func (p *partial) merge(src *partial) {
	mergeCounts(p.sentTime, src.sentTime)
	mergeCounts(p.receivedTime, src.receivedTime)
	mergeCounts(p.sentSize, src.sentSize)
	mergeCounts(p.receivedSize, src.receivedSize)
	mergeCounts(p.sentIP, src.sentIP)
	mergeCounts(p.receivedIP, src.receivedIP)
	mergeCounts(p.hosts, src.hosts)
}

// finalize converts the merged tallies into the public result, turning each
// address into its string form exactly once.
func (p *partial) finalize() *AnalysisResult {
	return &AnalysisResult{
		SentTime:     p.sentTime,
		ReceivedTime: p.receivedTime,
		SentSize:     p.sentSize,
		ReceivedSize: p.receivedSize,
		SentIP:       stringKeys(p.sentIP),
		ReceivedIP:   stringKeys(p.receivedIP),
		Hosts:        stringKeys(p.hosts),
	}
}

// stringKeys rewrites an address-keyed tally as a string-keyed one for JSON.
func stringKeys(counts map[netip.Addr]int) map[string]int {
	out := make(map[string]int, len(counts))
	for addr, count := range counts {
		out[addr.String()] += count
	}
	return out
}

// NewAnalysisResult returns an AnalysisResult with every map initialized, so
// callers never have to guard against a nil map.
func NewAnalysisResult() *AnalysisResult {
	return newPartial().finalize()
}

// pcapngMagic is the magic byte sequence identifying PCAPNG format files.
// PCAPNG files begin with a Section Header Block (SHB) which starts with 0x0A0D0D0A.
var pcapngMagic = []byte{0x0A, 0x0D, 0x0D, 0x0A}

// Analyze parses a PCAP or PCAPNG file and returns TCP traffic analysis relative to targetIP.
//
// This function automatically detects the file format (PCAP vs PCAPNG) based on
// magic bytes and processes all TCP packets in the capture using parallel workers.
// Packets are categorized as "sent" or "received" based on whether the source or
// destination IP matches the target. Non-TCP packets (UDP, ICMP, etc.) are filtered out.
//
// Parameters:
//   - content: The complete PCAP/PCAPNG file contents as a byte slice.
//   - targetIP: The IP address to analyze traffic for (e.g., "192.168.1.100").
//
// Returns:
//   - *AnalysisResult: Aggregated TCP traffic statistics, or nil on error.
//   - error: Non-nil if the file cannot be parsed or the target IP is invalid.
//
// Format Detection:
//   - PCAPNG is detected by magic bytes 0x0A0D0D0A at file offset 0.
//   - All other files are assumed to be PCAP format. Invalid PCAP files will
//     return an error from the reader initialization.
//
// Packet Filtering:
//
//	Only TCP packets are analyzed. Non-TCP packets (UDP, ICMP, ARP, etc.) are
//	silently skipped and not included in the analysis.
//
// Note: For PCAPNG files, this function assumes Ethernet link type. PCAP files
// use the link type specified in their file header.
func Analyze(content []byte, targetIP string) (*AnalysisResult, error) {
	packetSource, err := newPacketSource(content)
	if err != nil {
		return nil, err
	}

	// Parse and validate target IP address
	target, err := parseAddr(targetIP)
	if err != nil {
		return nil, err
	}

	// Get packet channel from source
	packets := packetSource.Packets()

	// Read first packet to establish startTime
	firstPkt, ok := <-packets
	if !ok {
		// Empty capture file
		return NewAnalysisResult(), nil
	}
	startTime := firstPkt.Metadata().Timestamp

	// Set up worker pool (Map-Reduce pattern)
	numWorkers := runtime.NumCPU()
	var wg sync.WaitGroup
	resultsChan := make(chan *partial, numWorkers)

	// processPacket is the core logic each worker applies
	processPacket := func(packet gopacket.Packet, into *partial) {
		src, dst, ok := extractIPAddresses(packet)
		if !ok {
			return
		}

		// Every endpoint is tallied regardless of the target, so callers can
		// offer the other hosts in the capture as alternatives.
		into.hosts[src]++
		into.hosts[dst]++

		relativeTime := int(packet.Metadata().Timestamp.Sub(startTime).Seconds())

		switch target {
		case src:
			into.sentTime[relativeTime]++
			into.sentSize[relativeTime] += len(packet.Data())
			into.sentIP[dst]++
		case dst:
			into.receivedTime[relativeTime]++
			into.receivedSize[relativeTime] += len(packet.Data())
			into.receivedIP[src]++
		}
	}

	// Map phase: workers read directly from the packets channel, each keeping
	// its own tallies so no lock is needed on the hot path.
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := newPartial()

			for packet := range packets {
				processPacket(packet, local)
			}

			resultsChan <- local
		}()
	}

	// Process the first packet in the main goroutine's tallies
	// (we already consumed it, so workers won't see it)
	merged := newPartial()
	processPacket(firstPkt, merged)

	// Wait for all workers to finish
	wg.Wait()
	close(resultsChan)

	// Reduce phase: fold every worker's tallies into one
	for local := range resultsChan {
		merged.merge(local)
	}

	return merged.finalize(), nil
}

// parseAddr converts a textual IP address into the comparable form the analyzer
// keys everything on. IPv4-in-IPv6 addresses are unmapped so that "::ffff:10.0.0.1"
// and "10.0.0.1" are treated as the same host.
func parseAddr(ip string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid target IP: %s", ip)
	}
	return addr.Unmap(), nil
}

// newPacketSource detects the capture format from its magic bytes and returns a
// packet source for it. PCAPNG is identified by 0x0A0D0D0A at offset 0;
// everything else is read as classic PCAP, which fails loudly if the bytes are
// not a capture at all.
func newPacketSource(content []byte) (*gopacket.PacketSource, error) {
	reader := bytes.NewReader(content)

	magic := make([]byte, 4)
	if _, err := reader.ReadAt(magic, 0); err != nil {
		return nil, fmt.Errorf("failed to read magic bytes: %w", err)
	}

	if bytes.Equal(magic, pcapngMagic) {
		ngReader, err := pcapgo.NewNgReader(reader, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to create pcapng reader: %w", err)
		}
		// FIXME: hardcoded to Ethernet, should read link type from interface block
		return gopacket.NewPacketSource(ngReader, layers.LinkTypeEthernet), nil
	}

	pcapReader, err := pcapgo.NewReader(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to create pcap reader: %w", err)
	}
	return gopacket.NewPacketSource(pcapReader, pcapReader.LinkType()), nil
}

// HostCount pairs an IP address seen in a capture with how many TCP packets it
// took part in, in either direction.
type HostCount struct {
	// IP is the address of the endpoint.
	IP string `json:"ip"`

	// Packets is the number of TCP packets the address appears in as either
	// source or destination.
	Packets int `json:"packets"`
}

// BusiestHost returns the address that appears in the most TCP packets in the
// capture, which is almost always the machine the capture was taken on.
//
// It lets a caller analyze a file without the user having to know an IP address
// up front. The capture is parsed once and everything except endpoint counts is
// thrown away, so this is cheaper than a full Analyze.
//
// Returns an empty string, and a nil error, when the capture holds no TCP
// packets at all.
func BusiestHost(content []byte) (string, error) {
	packetSource, err := newPacketSource(content)
	if err != nil {
		return "", err
	}

	hosts := make(map[netip.Addr]int)
	for packet := range packetSource.Packets() {
		src, dst, ok := extractIPAddresses(packet)
		if !ok {
			continue
		}
		hosts[src]++
		hosts[dst]++
	}

	// Only the winner is needed, so scan for it instead of sorting the lot.
	// Ties break on the address so the answer does not change between runs.
	var best netip.Addr
	bestCount := 0
	for addr, count := range hosts {
		if count > bestCount || (count == bestCount && addr.Less(best)) {
			best, bestCount = addr, count
		}
	}
	if bestCount == 0 {
		return "", nil
	}
	return best.String(), nil
}

// RankHosts sorts a host tally by packet count, descending, keeping at most
// limit entries. Ties break on the address itself so the order is stable across
// runs, which Go's map iteration order is not.
//
// A limit of zero or less returns every host.
func RankHosts(hosts map[string]int, limit int) []HostCount {
	ranked := make([]HostCount, 0, len(hosts))
	for ip, packets := range hosts {
		ranked = append(ranked, HostCount{IP: ip, Packets: packets})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].Packets != ranked[j].Packets {
			return ranked[i].Packets > ranked[j].Packets
		}
		return ranked[i].IP < ranked[j].IP
	})
	if limit > 0 && len(ranked) > limit {
		ranked = ranked[:limit]
	}
	return ranked
}

// extractIPAddresses pulls the source and destination addresses out of a TCP
// packet, handling IPv4 and IPv6 so mixed captures work.
//
// Anything that is not TCP returns ok=false and is skipped by every caller.
// Addresses come back as netip.Addr because that type is comparable and can be
// used as a map key without allocating.
func extractIPAddresses(packet gopacket.Packet) (src, dst netip.Addr, ok bool) {
	// Filter: Only process TCP packets
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer == nil {
		return netip.Addr{}, netip.Addr{}, false
	}

	// Try IPv4 first (more common)
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		return toAddr(ip.SrcIP), toAddr(ip.DstIP), true
	}

	// Fall back to IPv6
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ip, _ := ipv6Layer.(*layers.IPv6)
		return toAddr(ip.SrcIP), toAddr(ip.DstIP), true
	}

	// Has TCP layer but no IP layer (shouldn't happen in practice)
	return netip.Addr{}, netip.Addr{}, false
}

// toAddr converts gopacket's net.IP into a comparable netip.Addr, unmapping the
// IPv4-in-IPv6 form so both spellings of an IPv4 address land on one key.
func toAddr(ip net.IP) netip.Addr {
	addr, _ := netip.AddrFromSlice(ip)
	return addr.Unmap()
}
