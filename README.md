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
cd PcapExplorer

# (Optional) Download the GeoLite2 database to enable the map — free, needs a
# MaxMind account. Place GeoLite2-City.mmdb in ./data/. Without it the app
# still works; the map is just disabled.
```

**Run it (two terminals, dev mode):**

```bash
# Terminal 1 — Go backend on :5432
go run .

# Terminal 2 — Vite dev server (proxies /api to the backend)
cd frontend
npm install
npm run dev          # open the URL Vite prints, e.g. http://localhost:5173
```

**Run it as one server (build the frontend, then serve everything on :5432):**

```bash
cd frontend && npm install && npm run build && cd ..
go run .             # serves the built frontend + API at http://localhost:5432
```

**Or with Docker (builds frontend + backend into one image):**

```bash
docker build -t pcap-explorer .
docker run -p 5432:5432 pcap-explorer   # http://localhost:5432
```

## Configuration

All settings are optional environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `5432` | Port the server listens on (hosting platforms like Cloud Run set this automatically). |
| `GEOIP_DATABASE_PATH` | `./data/GeoLite2-City.mmdb` | Path to the MaxMind GeoLite2 City database. |
| `GEOIP_MAX_LOOKUPS` | `20` | Max number of top IPs geo-located per analysis. |

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
PcapExplorer/
├── main.go              # HTTP server + /api/analyze handler
├── internal/
│   ├── analyzer/        # PCAP/PCAPNG parsing + TCP traffic analysis
│   └── geoip/           # MaxMind GeoLite2 database reader
├── cmd/gen_pcap/        # Test PCAP file generator
├── data/                # GeoLite2-City.mmdb goes here (git-ignored)
├── frontend/            # React + TypeScript + Vite app
├── Dockerfile           # Multi-stage build (frontend + backend)
└── go.mod
```

## What I Learned

- Go's `gopacket` library is excellent for packet analysis
- PCAPNG format detection via magic bytes (0x0A0D0D0A)
- MaxMind's free GeoLite2 database vs their paid API
- Graceful HTTP server shutdown patterns in Go

## License

MIT
