// Package main generates the sample capture that ships with PCAP Explorer.
//
// The output is a synthetic but structurally valid libpcap file: every flow
// carries a real TCP handshake, monotonic sequence/ack numbers and a clean
// teardown, so the file opens cleanly in Wireshark as well as in this tool.
// Destinations are real cloud/CDN addresses chosen because MaxMind GeoLite2
// resolves each one to a *distinct* city, which is what makes the demo map
// interesting instead of a single pin in the middle of Kansas.
//
// Generation is deterministic (fixed seed, fixed start time), so re-running it
// reproduces the committed file byte for byte.
//
// Usage (from the repository root):
//
//	go run ./cmd/gen_pcap
//	go run ./cmd/gen_pcap -out /tmp/other.pcap
package main

import (
	"flag"
	"log"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

const (
	// snapLen is the capture length recorded in the pcap file header.
	snapLen = 65536

	// mss is the TCP payload carried by a full-size Ethernet frame
	// (1514 on the wire - 14 Ethernet - 20 IPv4 - 20 TCP).
	mss = 1460

	// seed keeps generation deterministic so the committed sample file is
	// reproducible from source.
	seed = 20260704
)

// workstation is the host the sample is meant to be analyzed for. It is the
// value the UI pre-fills when a visitor loads the sample capture.
const workstation = "192.168.1.24"

// startTime is the (fixed) timestamp of the first packet. Only relative time
// matters to the analyzer, but pinning it keeps output byte-identical.
var startTime = time.Date(2026, time.July, 4, 17, 4, 12, 0, time.UTC)

// MAC addresses for the two ends of the simulated LAN segment.
var (
	macWorkstation = net.HardwareAddr{0x00, 0x1c, 0x42, 0x7a, 0x11, 0x24}
	macGateway     = net.HardwareAddr{0x3c, 0x22, 0xfb, 0x0e, 0x9d, 0x01}
)

// flowSpec describes one simulated TCP conversation.
type flowSpec struct {
	// label is a human-readable note; it exists to document the intent of each
	// flow at the call site and is not written to the capture.
	label string

	localIP  string // the LAN side of the conversation
	remoteIP string // the internet (or gateway) side
	dstPort  int

	start    float64 // seconds from capture start
	duration float64 // seconds the conversation stays open

	// rounds is how many request/response exchanges the conversation performs.
	rounds int

	// upBytes and downBytes bound the payload of a single exchange in each
	// direction; the generator picks a value in [min, max] per round.
	upMin, upMax     int
	downMin, downMax int
}

// sampleFlows is the script for the sample capture: roughly three minutes in
// the life of one workstation. It deliberately mixes a heavy download, a heavy
// upload, a long-lived SSH session, chatty background sync, LAN traffic to the
// gateway and a second LAN device, so every panel of the dashboard has
// something to show.
var sampleFlows = []flowSpec{
	// Background: cloud sync that runs for the whole capture.
	{"microsoft 365 sync", workstation, "20.42.65.85", 443, 0.4, 176, 44, 120, 500, 400, 1800},

	// Long-lived interactive SSH session: many tiny packets, few bytes.
	{"ssh to build server", workstation, "88.99.0.1", 22, 5.1, 170, 120, 32, 96, 48, 320},

	// The download burst: a big artifact pulled from AWS eu-west-1.
	{"artifact download", workstation, "18.200.0.1", 443, 21.0, 38, 120, 60, 140, 2600, 7200},

	// The upload burst: pushing a build cache to AWS eu-central-1.
	{"build cache upload", workstation, "52.28.0.1", 443, 72.0, 27, 80, 2200, 6400, 60, 200},

	// Ordinary browsing / API chatter, spread across the globe.
	{"cdn assets", workstation, "157.240.22.35", 443, 12.0, 150, 34, 200, 600, 500, 2600},
	{"api requests", workstation, "165.227.0.1", 443, 30.0, 130, 26, 300, 900, 300, 1500},
	{"eu edge", workstation, "35.180.0.1", 443, 44.0, 96, 14, 200, 600, 400, 1900},
	{"uk edge", workstation, "46.101.0.1", 443, 58.0, 88, 12, 180, 520, 320, 1400},
	{"tokyo region", workstation, "52.194.0.1", 443, 66.0, 92, 16, 200, 640, 380, 2100},
	{"seoul region", workstation, "3.5.140.2", 443, 88.0, 62, 9, 160, 480, 260, 1200},
	{"singapore region", workstation, "159.65.0.1", 443, 100.0, 58, 8, 150, 460, 240, 1100},
	{"sydney region", workstation, "13.55.0.1", 443, 112.0, 54, 7, 150, 440, 220, 1000},
	{"mumbai region", workstation, "3.6.0.1", 443, 124.0, 46, 7, 140, 420, 220, 980},
	{"sao paulo region", workstation, "15.228.0.1", 443, 134.0, 40, 6, 140, 400, 200, 900},
	{"nyc region", workstation, "104.248.0.1", 443, 146.0, 30, 6, 170, 500, 300, 1400},

	// LAN traffic: DNS-over-TLS to the gateway. Private IPs never geolocate,
	// which is exactly the behaviour the map's empty states describe.
	{"gateway dot", workstation, "192.168.1.1", 853, 2.0, 172, 30, 60, 140, 90, 400},

	// A second LAN device, so the host picker has a real alternative to offer.
	{"laptop to cdn", "192.168.1.42", "157.240.22.35", 443, 18.0, 120, 18, 200, 560, 400, 1900},
	{"laptop to gateway", "192.168.1.42", "192.168.1.1", 853, 9.0, 150, 12, 60, 140, 90, 380},

	// One IPv6 conversation, to exercise (and demo) dual-stack parsing.
	{"ipv6 browsing", "2601:646:9e00:1a::24", "2a00:1450:4009:81f::200e", 443, 26.0, 110, 20, 220, 700, 420, 2200},
}

func main() {
	out := flag.String("out", "frontend/public/sample-capture.pcap", "path of the pcap file to write")
	flag.Parse()

	f, err := os.Create(*out)
	if err != nil {
		log.Fatalf("create %s: %v", *out, err)
	}
	defer f.Close()

	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(snapLen, layers.LinkTypeEthernet); err != nil {
		log.Fatalf("write file header: %v", err)
	}

	rng := rand.New(rand.NewSource(seed))

	// Build every packet first so the whole capture can be sorted into true
	// chronological order; a pcap file with out-of-order timestamps is legal
	// but confuses most tools that read it.
	var packets []timedPacket
	for i, spec := range sampleFlows {
		packets = append(packets, buildFlow(spec, rng, 40000+i*137)...)
	}
	sortByTime(packets)

	var bytesWritten int
	for _, p := range packets {
		ci := gopacket.CaptureInfo{
			Timestamp:     p.ts,
			CaptureLength: len(p.data),
			Length:        len(p.data),
		}
		if err := w.WritePacket(ci, p.data); err != nil {
			log.Fatalf("write packet: %v", err)
		}
		bytesWritten += len(p.data)
	}

	log.Printf("wrote %s: %d packets, %d bytes of frame data, %.0fs of traffic",
		*out, len(packets), bytesWritten, packets[len(packets)-1].ts.Sub(startTime).Seconds())
}

// timedPacket is a serialized frame together with the moment it was captured.
type timedPacket struct {
	ts   time.Time
	data []byte
}

// sortByTime orders packets chronologically using an insertion sort. The input
// is already nearly sorted (flows are generated in start order), and the packet
// count is small, so the simplicity is worth more than the asymptotics.
func sortByTime(packets []timedPacket) {
	for i := 1; i < len(packets); i++ {
		p := packets[i]
		j := i - 1
		for j >= 0 && packets[j].ts.After(p.ts) {
			packets[j+1] = packets[j]
			j--
		}
		packets[j+1] = p
	}
}

// conn tracks the mutable state of one direction of a TCP conversation.
type conn struct {
	ip   net.IP
	port int
	seq  uint32
}

// buildFlow renders one flowSpec into a full TCP conversation: handshake,
// `rounds` request/response exchanges spread over the flow's duration, and a
// FIN teardown.
func buildFlow(spec flowSpec, rng *rand.Rand, srcPort int) []timedPacket {
	local := &conn{ip: net.ParseIP(spec.localIP), port: srcPort, seq: rng.Uint32()}
	remote := &conn{ip: net.ParseIP(spec.remoteIP), port: spec.dstPort, seq: rng.Uint32()}
	if local.ip == nil || remote.ip == nil {
		log.Fatalf("flow %q: invalid IP address", spec.label)
	}

	var out []timedPacket
	at := spec.start

	// Round trip time; a rough stand-in for the distance to the peer so the
	// timeline does not look mechanical.
	rtt := 0.008 + rng.Float64()*0.05

	emit := func(from, to *conn, flags tcpFlags, payload int, t float64) {
		out = append(out, timedPacket{
			ts:   startTime.Add(time.Duration(t * float64(time.Second))),
			data: buildPacket(from, to, flags, payload, rng),
		})
	}

	// Handshake.
	emit(local, remote, tcpFlags{syn: true}, 0, at)
	at += rtt
	emit(remote, local, tcpFlags{syn: true, ack: true}, 0, at)
	at += rtt / 2
	emit(local, remote, tcpFlags{ack: true}, 0, at)

	// Exchanges, spaced evenly across the flow's lifetime with a little jitter.
	gap := spec.duration / float64(spec.rounds+1)
	for i := 0; i < spec.rounds; i++ {
		at = spec.start + gap*float64(i+1) + (rng.Float64()-0.5)*gap*0.6

		up := randRange(rng, spec.upMin, spec.upMax)
		down := randRange(rng, spec.downMin, spec.downMax)

		t := at
		for _, seg := range segments(up) {
			emit(local, remote, tcpFlags{ack: true, psh: seg.last}, seg.size, t)
			t += 0.0004
		}
		t += rtt
		emit(remote, local, tcpFlags{ack: true}, 0, t)

		t += rtt / 3
		for _, seg := range segments(down) {
			emit(remote, local, tcpFlags{ack: true, psh: seg.last}, seg.size, t)
			t += 0.0004
			// Delayed ACKs: the receiver acknowledges roughly every other
			// full-size segment rather than every one.
			if seg.index%2 == 1 {
				emit(local, remote, tcpFlags{ack: true}, 0, t+rtt/4)
			}
		}
		emit(local, remote, tcpFlags{ack: true}, 0, t+rtt/2)
	}

	// Teardown.
	at = spec.start + spec.duration
	emit(local, remote, tcpFlags{fin: true, ack: true}, 0, at)
	at += rtt
	emit(remote, local, tcpFlags{fin: true, ack: true}, 0, at)
	at += rtt / 2
	emit(local, remote, tcpFlags{ack: true}, 0, at)

	return out
}

// segment is one MSS-bounded slice of an application-level message.
type segment struct {
	size  int
	index int
	last  bool
}

// segments splits a payload of n bytes into MSS-sized TCP segments, the way a
// real stack would.
func segments(n int) []segment {
	if n <= 0 {
		return nil
	}
	var segs []segment
	for i := 0; n > 0; i++ {
		size := n
		if size > mss {
			size = mss
		}
		n -= size
		segs = append(segs, segment{size: size, index: i, last: n == 0})
	}
	return segs
}

func randRange(rng *rand.Rand, min, max int) int {
	if max <= min {
		return min
	}
	return min + rng.Intn(max-min+1)
}

// tcpFlags is the subset of TCP control bits the generator sets.
type tcpFlags struct {
	syn, ack, psh, fin bool
}

// buildPacket serializes a single Ethernet/IP/TCP frame and advances the
// sender's sequence number.
func buildPacket(from, to *conn, flags tcpFlags, payload int, rng *rand.Rand) []byte {
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(from.port),
		DstPort: layers.TCPPort(to.port),
		Seq:     from.seq,
		Ack:     to.seq,
		Window:  64240,
		SYN:     flags.syn,
		ACK:     flags.ack,
		PSH:     flags.psh,
		FIN:     flags.fin,
	}

	// Encrypted traffic looks like noise on the wire, which is what almost
	// every port in this capture is carrying.
	body := make([]byte, payload)
	rng.Read(body)

	ethType := layers.EthernetTypeIPv4
	var netLayer gopacket.SerializableLayer = &layers.IPv4{
		Version:  4,
		SrcIP:    from.ip,
		DstIP:    to.ip,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	if from.ip.To4() == nil {
		ethType = layers.EthernetTypeIPv6
		netLayer = &layers.IPv6{
			Version:    6,
			SrcIP:      from.ip,
			DstIP:      to.ip,
			NextHeader: layers.IPProtocolTCP,
			HopLimit:   64,
		}
	}
	if err := tcp.SetNetworkLayerForChecksum(netLayer.(gopacket.NetworkLayer)); err != nil {
		log.Fatalf("set network layer: %v", err)
	}

	eth := &layers.Ethernet{SrcMAC: macWorkstation, DstMAC: macGateway, EthernetType: ethType}

	if err := gopacket.SerializeLayers(buf, opts, eth, netLayer, tcp, gopacket.Payload(body)); err != nil {
		log.Fatalf("serialize: %v", err)
	}

	// SYN and FIN each consume one sequence number, as does every payload byte.
	from.seq += uint32(payload)
	if flags.syn || flags.fin {
		from.seq++
	}

	return buf.Bytes()
}
