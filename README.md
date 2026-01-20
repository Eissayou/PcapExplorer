# PCAP Explorer 🔍

A lightweight network traffic analyzer that lets you drag-and-drop PCAP files and instantly visualize where your packets are going.

## Why I Built This

I got tired of firing up Wireshark every time I wanted to quickly see traffic patterns. Sometimes you just want to know "who is this machine talking to?" without wading through packet details. This tool gives you that at a glance.

## Features

- **Drag & Drop Analysis** - Just drop a .pcap or .pcapng file
- **Traffic Timeline** - See packets sent/received over time
- **Top Talkers** - Identify the most frequent IPs
- **GeoIP Mapping** - See where your traffic is going on a world map
- **IPv4 + IPv6** - Full support for both protocols

## Quick Start

```bash
# Clone the repo
git clone https://github.com/Eissayou/PcapExplorer.git
cd PcapExplorer/pcap-analyzer

# Download GeoLite2 database (free, requires MaxMind account)
# Place GeoLite2-City.mmdb in ./data/

# Run the server
go run .

# Open http://localhost:5432
```

## Tech Stack

- **Backend**: Go with [gopacket](https://github.com/google/gopacket) for PCAP parsing
- **Frontend**: React + TypeScript + Vite
- **GeoIP**: MaxMind GeoLite2 (free database, no API needed)

## How It Works

1. Upload a PCAP file + specify the IP you want to analyze
2. Backend parses packets and categorizes them as sent/received
3. Top IPs get geo-located using the local MaxMind database
4. Frontend renders charts and an interactive map

## Project Structure

```
pcap-analyzer/
├── main.go              # HTTP server + API handler
├── pkg/
│   ├── analyzer/        # PCAP parsing logic
│   └── geoip/           # GeoIP database reader
├── cmd/gen_pcap/        # Test PCAP generator
├── data/                # GeoLite2-City.mmdb goes here
└── frontend/            # React app
```

## What I Learned

- Go's `gopacket` library is excellent for packet analysis
- PCAPNG format detection via magic bytes (0x0A0D0D0A)
- MaxMind's free GeoLite2 database vs their paid API
- Graceful HTTP server shutdown patterns in Go

## License

MIT
