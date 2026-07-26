# PCAP Explorer 🔍

A lightweight network traffic analyzer. Drop in a PCAP file and see where your packets are going.

**Live:** https://pcap.eissayou.com

## Why I Built This

I got tired of firing up Wireshark every time I wanted to see traffic patterns. Sometimes you just want to know "who is this machine talking to?" without wading through a packet list. This tool answers that in one screen.

## Features

- **Drag & Drop Analysis** - Just drop a .pcap, .pcapng or .cap file
- **Auto-detected target** - Leave the IP field blank and it analyzes the busiest host in the file
- **Host switching** - Every endpoint in the capture is listed after the first run, so you can re-analyze without re-uploading
- **Traffic Timeline** - Packets/sec and bytes/sec, sent and received
- **Top Talkers** - The peers that dominated each direction
- **GeoIP Mapping** - Destinations on a world map, sized by packet volume
- **IPv4 + IPv6** - Both parsed in the same capture

## Try It

The app ships with a sample capture, so you can see real output without hunting for a PCAP first. Click **Try the sample capture** on the homepage, or grab the file directly:

```bash
curl -O https://pcap.eissayou.com/sample-capture.pcap
```

It's about three minutes of one workstation's TCP traffic: 3,281 packets across 16 peers in 11 countries, with a download burst, an upload burst, a long SSH session, LAN traffic to a gateway, and one IPv6 flow. Every conversation has a real TCP handshake and teardown, so it opens cleanly in Wireshark too.

Regenerate it with:

```bash
go run ./cmd/gen_pcap
```

Generation is deterministic (fixed seed and start time), so the committed file is reproducible from source. The traffic script lives at the top of [cmd/gen_pcap/main.go](cmd/gen_pcap/main.go).

## Quick Start

```bash
# Clone the repo
git clone https://github.com/Eissayou/PcapExplorer.git
cd PcapExplorer

# (Optional) Download the GeoLite2 database to enable the map. It's free but
# needs a MaxMind account. Place GeoLite2-City.mmdb in ./data/. Without it the
# app still works, the map is just disabled.
```

**Run it (two terminals, dev mode):**

```bash
# Terminal 1: Go backend on :5432
go run .

# Terminal 2: Vite dev server (proxies /api to the backend)
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
| `SITE_URL` | `https://pcap.eissayou.com` | Build-time only. The canonical origin baked into the meta tags, sitemap and robots.txt. Set it before `npm run build` if the app ever moves domains. |

## API

`POST /api/analyze` takes a multipart form:

| Field | Required | Notes |
|---|---|---|
| `file` | yes | The .pcap / .pcapng capture, up to 100 MB. |
| `ip` | no | Target host. Omit it and the server analyzes the busiest host in the capture. |

```bash
curl -F file=@sample-capture.pcap http://localhost:5432/api/analyze
```

The response echoes back `targetIp` and whether it was `autoDetected`, plus `hosts` (the busiest endpoints, which is what the host switcher uses), the chart data, and the resolved `locations`.

## Tech Stack

- **Backend**: Go with [gopacket](https://github.com/google/gopacket) for PCAP parsing
- **Frontend**: React + TypeScript + Vite + Tailwind
- **Charts and map**: Recharts and Leaflet
- **GeoIP**: MaxMind GeoLite2 (free database, no API needed)

## How It Works

1. Upload a PCAP file, optionally naming the IP you want to analyze
2. If you didn't name one, the server does a cheap first pass and picks the host that appears in the most packets
3. A worker pool parses the capture and categorizes each TCP packet as sent or received relative to that host (map phase), then the per-worker tallies get folded into one (reduce phase)
4. The top destination IPs are geo-located against the local MaxMind database
5. The frontend renders charts and an interactive map

While the map-reduce runs, addresses are keyed on `netip.Addr` rather than strings. It's comparable and allocation-free as a map key, and the conversion to strings happens once at the end. On a large capture that saves two `net.IP.String()` allocations per packet.

## Project Structure

```
PcapExplorer/
├── main.go              # HTTP server, /api/analyze, static file serving
├── internal/
│   ├── analyzer/        # PCAP/PCAPNG parsing + TCP traffic analysis
│   └── geoip/           # MaxMind GeoLite2 database reader
├── cmd/gen_pcap/        # Generator for the bundled sample capture
├── data/                # GeoLite2-City.mmdb goes here (git-ignored)
├── frontend/            # React + TypeScript + Vite app
│   └── public/sample-capture.pcap
├── Dockerfile           # Multi-stage build (frontend + backend)
└── go.mod
```

## What I Learned

- Go's `gopacket` library is excellent for packet analysis
- PCAPNG format detection via magic bytes (0x0A0D0D0A)
- `netip.Addr` beats `net.IP` as a map key: comparable, no allocation, no `.String()` on the hot path
- MaxMind's free GeoLite2 database vs their paid API
- Graceful HTTP server shutdown patterns in Go

## License

MIT
