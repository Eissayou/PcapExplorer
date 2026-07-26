// Package main provides the HTTP server for the PCAP Analyzer application.
//
// This server exposes a RESTful API for analyzing PCAP (Packet Capture) files
// and correlating captured IP addresses with geographic locations using the
// free MaxMind GeoLite2 database.
//
// # Endpoints
// POST /api/analyze - Analyzes an uploaded PCAP file and returns traffic statistics
// and optional geographic information for detected IP addresses.
//
// # Architecture
// The server uses a graceful shutdown pattern, allowing in-flight requests
// to complete before terminating. Static files are served from ./frontend/dist.
package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Eissayou/pcap-analyzer/internal/analyzer"
	"github.com/Eissayou/pcap-analyzer/internal/geoip"
)

const (
	// DefaultPort is the TCP port the server listens on when the PORT
	// environment variable is unset. Hosting platforms such as Cloud Run
	// inject their own PORT, which takes precedence.
	DefaultPort = "5432"

	// DefaultMaxGeoIPRequests caps how many of the most frequent IPs are
	// geo-located per request when GEOIP_MAX_LOOKUPS is unset.
	DefaultMaxGeoIPRequests = 20

	// DefaultGeoIPDBPath is the fallback GeoLite2 database location used when
	// the GEOIP_DATABASE_PATH environment variable is unset.
	DefaultGeoIPDBPath = "./data/GeoLite2-City.mmdb"

	// MaxUploadBytes caps the total size of an upload request body. This bounds
	// memory use (the file is read fully into memory for analysis) and guards
	// against a client streaming an unbounded body.
	MaxUploadBytes = 100 << 20 // 100 MB

	// MaxHostSuggestions is how many of the busiest endpoints are returned with
	// an analysis so the client can offer them as alternative targets.
	MaxHostSuggestions = 25

	// StaticRoot is the directory the built frontend is served from.
	StaticRoot = "./frontend/dist"

	// GzipMinBytes is the response size below which compression costs more than
	// it saves, since a small body fits in one packet either way.
	GzipMinBytes = 1024
)

// hashedAssetPrefix marks build output whose filename contains a content hash.
// Those URLs change whenever the bytes change, so they can be cached forever.
const hashedAssetPrefix = "/assets/"

// Messages sent straight to the browser when an upload cannot be used. Parser
// errors mention magic bytes and reader internals, which mean nothing to
// someone who just picked the wrong file, so the detail stays in the logs.
const (
	UnreadableCaptureMessage = "That file could not be read as a packet capture. PCAP Explorer accepts .pcap, .pcapng and .cap files."
	NoTCPTrafficMessage      = "No TCP traffic found in this capture. PCAP Explorer analyzes TCP packets only."
)

// geoReader is the global GeoIP database reader.
// It is initialized at startup and reused for all requests.
var geoReader *geoip.Reader

// maxGeoIPRequests caps the number of GeoIP lookups performed per analysis.
// It is set once at startup from GEOIP_MAX_LOOKUPS, falling back to
// DefaultMaxGeoIPRequests.
var maxGeoIPRequests = DefaultMaxGeoIPRequests

// AnalyzeResponse represents the JSON response returned by the /api/analyze endpoint.
// It contains aggregated traffic statistics organized for visualization (GraphObjects),
// geographic locations for the most frequent IP addresses (Locations), and any
// errors encountered during GeoIP lookups (MapError).
type AnalyzeResponse struct {
	// TargetIP is the host the analysis is relative to. It echoes back the IP
	// the client asked for, or the one the server picked when the client left
	// the field empty.
	TargetIP string `json:"targetIp"`

	// AutoDetected reports whether TargetIP was chosen by the server rather
	// than supplied by the client.
	AutoDetected bool `json:"autoDetected"`

	// Hosts lists the busiest endpoints in the capture so the client can offer
	// them as alternative targets without uploading the file again.
	Hosts []analyzer.HostCount `json:"hosts"`

	// GraphObjects contains aggregated packet and traffic statistics for visualization.
	GraphObjects GraphData `json:"graphObjects"`

	// Locations contains geographic information for the most frequently seen IPs.
	Locations []GeoLocation `json:"locations"`

	// MapError contains any error message related to GeoIP functionality.
	// Empty if GeoIP lookups succeeded or were not attempted.
	MapError string `json:"mapError,omitempty"`
}

// GraphData contains aggregated traffic statistics for chart visualization.
// All time-based maps use relative seconds from the first packet timestamp.
// IP-based maps use string representations of IP addresses as keys.
type GraphData struct {
	// SentTime maps relative time (seconds) to packet count for outbound traffic.
	SentTime map[int]int `json:"sentTime"`

	// ReceivedTime maps relative time (seconds) to packet count for inbound traffic.
	ReceivedTime map[int]int `json:"receivedTime"`

	// SentIP maps destination IP addresses to packet counts for outbound traffic.
	SentIP map[string]int `json:"sentIP"`

	// ReceivedIP maps source IP addresses to packet counts for inbound traffic.
	ReceivedIP map[string]int `json:"receivedIP"`

	// SentSize maps relative time (seconds) to total bytes sent.
	SentSize map[int]int `json:"sentSize"`

	// ReceivedSize maps relative time (seconds) to total bytes received.
	ReceivedSize map[int]int `json:"receivedSize"`
}

// GeoLocation represents geographic information for a specific IP address.
//
// This struct combines the IP address, its resolved location data from MaxMind,
// and the frequency count from the PCAP analysis.
type GeoLocation struct {
	// IP is the IP address that was geo-located.
	IP string `json:"ip"`

	// City is the city name, or "Unknown" if unavailable.
	City string `json:"city"`

	// Country is the country name, or "Unknown" if unavailable.
	Country string `json:"country"`

	// Latitude is the geographic latitude coordinate.
	Latitude float64 `json:"latitude"`

	// Longitude is the geographic longitude coordinate.
	Longitude float64 `json:"longitude"`

	// Count is the number of packets associated with this IP in the analysis.
	Count int `json:"count"`
}

// main initializes and starts the HTTP server with graceful shutdown support.
//
// The server is configured with:
//   - Structured JSON logging via slog
//   - GeoIP database initialization from local GeoLite2 file
//   - CORS-enabled API endpoint at /api/analyze
//   - Static file serving from ./frontend/dist
//   - Graceful shutdown with a 5-second timeout on SIGINT/SIGTERM
func main() {
	// Initialize structured JSON logger for production-ready logging
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Resolve runtime configuration from the environment.
	port := getenvDefault("PORT", DefaultPort)
	maxGeoIPRequests = getenvInt("GEOIP_MAX_LOOKUPS", DefaultMaxGeoIPRequests)

	// Initialize GeoIP database
	initGeoIP()

	mux := http.NewServeMux()

	// TODO: add rate limiting middleware to prevent abuse
	mux.HandleFunc("/api/analyze", enableCORS(handleAnalyze))

	// Serve frontend
	mux.Handle("/", staticFiles(StaticRoot))

	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
		// Timeouts guard against slow-client (Slowloris) attacks and stuck
		// connections. Read/Write limits are generous to accommodate large
		// PCAP uploads (up to 100MB) and the analysis that follows.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       120 * time.Second,
		WriteTimeout:      120 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1 MB
	}

	// Set up channel for graceful shutdown signals
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	// Start server in a goroutine to allow for shutdown handling
	go func() {
		slog.Info("Server starting", "port", port)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Server failed to start", "error", err)
			os.Exit(1)
		}
	}()

	// Block until shutdown signal is received
	<-stop
	slog.Info("Server shutting down...")

	// Close GeoIP reader
	if geoReader != nil {
		geoReader.Close()
	}

	// Create a deadline for graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
	}

	slog.Info("Server exited")
}

// initGeoIP initializes the GeoIP database reader from the local GeoLite2 file.
//
// The function looks for the database in the following order:
//  1. Path specified by GEOIP_DATABASE_PATH environment variable
//  2. Default path: ./data/GeoLite2-City.mmdb
//
// If the database cannot be loaded, the server continues without GeoIP
// functionality and logs a warning.
func initGeoIP() {
	dbPath := os.Getenv("GEOIP_DATABASE_PATH")
	if dbPath == "" {
		dbPath = DefaultGeoIPDBPath
	}

	reader, err := geoip.NewReader(dbPath)
	if err != nil {
		slog.Warn("GeoIP database not available - map features disabled",
			"path", dbPath,
			"error", err,
			"hint", "Download GeoLite2-City.mmdb from maxmind.com and place it in ./data/")
		return
	}

	geoReader = reader
	slog.Info("GeoIP database loaded", "path", dbPath)
}

// getenvDefault returns the value of the environment variable named by key,
// or fallback if the variable is unset or empty.
func getenvDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getenvInt returns the integer value of the environment variable named by key.
// It returns fallback if the variable is unset, empty, or not a valid integer,
// logging a warning in the invalid case.
func getenvInt(key string, fallback int) int {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		slog.Warn("Invalid integer environment variable, using default",
			"key", key, "value", v, "default", fallback)
		return fallback
	}
	return n
}

// enableCORS is a middleware that adds Cross-Origin Resource Sharing headers
// to HTTP responses.
//
// This middleware enables cross-origin requests from any origin (*) for the
// POST method. It handles preflight OPTIONS requests by returning an immediate
// 200 OK response.
//
// Parameters:
//   - next: The handler function to wrap with CORS headers.
//
// Returns:
//   - http.HandlerFunc: A new handler that adds CORS headers before calling next.
//
// Note: In production, consider restricting Access-Control-Allow-Origin to
// specific trusted origins rather than using the wildcard (*).
func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		// Handle preflight requests
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// staticFiles serves the built frontend with the caching, compression and
// security headers a production site needs.
//
// Cache lifetimes follow the filename: Vite writes a content hash into every
// file under /assets/, so those URLs are safe to cache forever, while index.html
// has to be revalidated on each visit or a deploy would never reach anyone.
func staticFiles(root string) http.Handler {
	fileServer := http.FileServer(http.Dir(root))

	return gzipResponses(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("X-Frame-Options", "SAMEORIGIN")

		if strings.HasPrefix(r.URL.Path, hashedAssetPrefix) {
			h.Set("Cache-Control", "public, max-age=31536000, immutable")
		} else if strings.HasSuffix(r.URL.Path, "/") || strings.HasSuffix(r.URL.Path, ".html") {
			h.Set("Cache-Control", "no-cache")
		} else {
			// Everything else (the sample capture, icons, robots.txt) is stable
			// but does replace in place, so cache it for a day.
			h.Set("Cache-Control", "public, max-age=86400")
		}

		fileServer.ServeHTTP(w, r)
	}))
}

// compressibleTypes are the content types worth gzipping. Images, fonts and
// packet captures are already compressed or effectively random, so running them
// through gzip burns CPU for nothing.
var compressibleTypes = []string{"text/", "application/javascript", "application/json", "image/svg+xml", "application/xml", "application/manifest+json"}

// gzipResponses compresses responses for clients that advertise gzip support.
//
// Compression is decided lazily on the first Write, once the content type is
// known: that keeps small files and already-compressed formats uncompressed
// without the handler having to know anything about the response in advance.
func gzipResponses(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Add("Vary", "Accept-Encoding")

		gw := &gzipWriter{ResponseWriter: w}
		defer gw.Close()
		next.ServeHTTP(gw, r)
	})
}

// gzipWriter wraps an http.ResponseWriter and swaps in a gzip stream once it
// can tell the response is worth compressing.
type gzipWriter struct {
	http.ResponseWriter
	gz      *gzip.Writer
	decided bool
}

func (g *gzipWriter) WriteHeader(status int) {
	g.decide(status)
	g.ResponseWriter.WriteHeader(status)
}

func (g *gzipWriter) Write(b []byte) (int, error) {
	if !g.decided {
		g.decide(http.StatusOK)
	}
	if g.gz != nil {
		return g.gz.Write(b)
	}
	return g.ResponseWriter.Write(b)
}

// decide picks compressed or plain for this response, exactly once.
func (g *gzipWriter) decide(status int) {
	if g.decided {
		return
	}
	g.decided = true

	h := g.Header()
	if status != http.StatusOK || h.Get("Content-Encoding") != "" {
		return
	}
	if size, err := strconv.Atoi(h.Get("Content-Length")); err == nil && size < GzipMinBytes {
		return
	}

	contentType := h.Get("Content-Type")
	for _, prefix := range compressibleTypes {
		if strings.HasPrefix(contentType, prefix) {
			h.Set("Content-Encoding", "gzip")
			// The compressed body is a different length, and Go has no way to
			// know it up front while streaming.
			h.Del("Content-Length")
			g.gz = gzip.NewWriter(g.ResponseWriter)
			return
		}
	}
}

func (g *gzipWriter) Close() {
	if g.gz != nil {
		if err := g.gz.Close(); err != nil {
			slog.Warn("Failed to flush gzip response", "error", err)
		}
	}
}

// handleAnalyze processes PCAP file upload requests and returns traffic analysis.
//
// This handler expects a multipart/form-data POST request containing:
//   - "file": The PCAP or PCAPNG file to analyze (required).
//   - "ip": The target IP address to track sent/received traffic (optional;
//     defaults to the busiest host in the capture).
//
// The handler performs the following operations:
//  1. Validates the request method and form data.
//  2. Parses the uploaded PCAP file.
//  3. Resolves the target IP, auto-detecting it when the client omitted one.
//  4. Analyzes traffic patterns relative to the target IP.
//  5. Optionally performs GeoIP lookups for the top N most frequent IPs.
//  6. Returns aggregated statistics as JSON.
//
// Response format: AnalyzeResponse (JSON)
//
// Error responses:
//   - 400 Bad Request: Missing or invalid form data, or an unreadable capture.
//   - 405 Method Not Allowed: Non-POST request.
//   - 413 Request Entity Too Large: Upload above MaxUploadBytes.
//   - 422 Unprocessable Entity: Readable capture with no TCP traffic to analyze.
//   - 500 Internal Server Error: File processing or analysis failure.
func handleAnalyze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Cap the total request body size to bound memory use and reject oversized
	// uploads before they are buffered. MaxBytesReader also surfaces a clear
	// error from ParseMultipartForm once the limit is exceeded.
	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)

	// Parse multipart form, keeping up to 10MB of parts in memory (the rest
	// spills to temporary files); the overall size is bounded by MaxBytesReader.
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		slog.Warn("Failed to parse multipart form", "error", err)
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "File too large (max 100MB)", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "Unable to parse form", http.StatusBadRequest)
		return
	}

	// The target IP is optional: when it is omitted the server analyzes the
	// busiest host in the capture, which is almost always the machine the
	// capture was taken on.
	ip := strings.TrimSpace(r.FormValue("ip"))
	if ip != "" && net.ParseIP(ip) == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	// Extract uploaded file
	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "File is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Read entire file into memory for analysis
	content, err := io.ReadAll(file)
	if err != nil {
		slog.Error("Failed to read file", "error", err)
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	autoDetected := ip == ""
	if autoDetected {
		busiest, err := analyzer.BusiestHost(content)
		if err != nil {
			slog.Warn("Host detection failed", "error", err)
			http.Error(w, UnreadableCaptureMessage, http.StatusBadRequest)
			return
		}
		if busiest == "" {
			http.Error(w, NoTCPTrafficMessage, http.StatusUnprocessableEntity)
			return
		}
		ip = busiest
	}

	slog.Info("Analyzing pcap", "targetIP", ip, "autoDetected", autoDetected, "size", len(content))

	// Perform PCAP analysis
	result, err := analyzer.Analyze(content, ip)
	if err != nil {
		slog.Error("Analysis failed", "error", err)
		http.Error(w, UnreadableCaptureMessage, http.StatusBadRequest)
		return
	}

	// Perform optional GeoIP lookups
	locations, mapError := performGeoIPLookups(result.SentIP)

	// Construct and send response
	resp := AnalyzeResponse{
		TargetIP:     ip,
		AutoDetected: autoDetected,
		Hosts:        analyzer.RankHosts(result.Hosts, MaxHostSuggestions),
		GraphObjects: GraphData{
			SentTime:     result.SentTime,
			ReceivedTime: result.ReceivedTime,
			SentIP:       result.SentIP,
			ReceivedIP:   result.ReceivedIP,
			SentSize:     result.SentSize,
			ReceivedSize: result.ReceivedSize,
		},
		Locations: locations,
		MapError:  mapError,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("Error encoding response", "error", err)
	}
}

// performGeoIPLookups queries the local GeoLite2 database for IP address locations.
//
// This function retrieves geographic information for the most frequently seen
// IP addresses in the analysis results. It limits lookups to maxGeoIPRequests
// (configurable via GEOIP_MAX_LOOKUPS) to prevent excessive processing for
// files with many unique IPs.
//
// Parameters:
//   - sentIPs: Map of IP addresses to their occurrence counts.
//
// Returns:
//   - []GeoLocation: Slice of successfully resolved locations, sorted by count.
//   - string: Error message if GeoIP is unavailable.
//
// If the GeoLite2 database is not loaded, returns an empty slice with an
// error message instructing the user to download the database.
func performGeoIPLookups(sentIPs map[string]int) ([]GeoLocation, string) {
	locations := []GeoLocation{}

	// Check if GeoIP database is available
	if geoReader == nil {
		return locations, "GeoIP database not configured. Download GeoLite2-City.mmdb from maxmind.com"
	}

	// Look up the most frequent destinations first, stopping once the budget is
	// spent. Private addresses resolve to no coordinates and are skipped, so the
	// budget counts results rather than attempts.
	for _, host := range analyzer.RankHosts(sentIPs, 0) {
		if len(locations) >= maxGeoIPRequests {
			break
		}

		loc, err := geoReader.GetLocation(host.IP)
		if err != nil {
			slog.Warn("GeoIP lookup failed", "ip", host.IP, "error", err)
			continue
		}
		if loc.Latitude == 0 && loc.Longitude == 0 {
			continue
		}

		locations = append(locations, GeoLocation{
			IP:        host.IP,
			City:      loc.City,
			Country:   loc.Country,
			Latitude:  loc.Latitude,
			Longitude: loc.Longitude,
			Count:     host.Packets,
		})
	}

	return locations, ""
}
