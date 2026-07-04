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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
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
	fs := http.FileServer(http.Dir("./frontend/dist"))
	mux.Handle("/", fs)

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

// handleAnalyze processes PCAP file upload requests and returns traffic analysis.
//
// This handler expects a multipart/form-data POST request containing:
//   - "file": The PCAP or PCAPNG file to analyze (required).
//   - "ip": The target IP address to track sent/received traffic (required).
//
// The handler performs the following operations:
//  1. Validates the request method and form data.
//  2. Parses the uploaded PCAP file.
//  3. Analyzes traffic patterns relative to the target IP.
//  4. Optionally performs GeoIP lookups for the top N most frequent IPs.
//  5. Returns aggregated statistics as JSON.
//
// Response format: AnalyzeResponse (JSON)
//
// Error responses:
//   - 400 Bad Request: Missing or invalid form data.
//   - 405 Method Not Allowed: Non-POST request.
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

	// Extract and validate target IP
	ip := r.FormValue("ip")
	if ip == "" {
		http.Error(w, "IP is required", http.StatusBadRequest)
		return
	}
	if net.ParseIP(ip) == nil {
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

	slog.Info("Analyzing pcap", "targetIP", ip, "size", len(content))

	// Perform PCAP analysis
	result, err := analyzer.Analyze(content, ip)
	if err != nil {
		slog.Error("Analysis failed", "error", err)
		http.Error(w, fmt.Sprintf("Analysis failed: %v", err), http.StatusInternalServerError)
		return
	}

	// Perform optional GeoIP lookups
	locations, mapError := performGeoIPLookups(result.SentIP)

	// Construct and send response
	resp := AnalyzeResponse{
		GraphObjects: GraphData{
			SentTime:     result.SentTime,
			ReceivedTime: result.ReceivedTime,
			SentIP:       result.SentIP,
			ReceivedIP:   result.ReceivedIP,
			SentSize:     result.SentSize,
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

	// Sort IPs by packet count (descending) to prioritize most frequent
	type ipCount struct {
		IP    string
		Count int
	}
	sortedIPs := make([]ipCount, 0, len(sentIPs))
	for ip, count := range sentIPs {
		sortedIPs = append(sortedIPs, ipCount{IP: ip, Count: count})
	}
	sort.Slice(sortedIPs, func(i, j int) bool {
		return sortedIPs[i].Count > sortedIPs[j].Count
	})

	// Perform lookups for top N IPs
	lookups := 0
	for _, item := range sortedIPs {
		if lookups >= maxGeoIPRequests {
			break
		}

		loc, err := geoReader.GetLocation(item.IP)
		if err != nil {
			slog.Warn("GeoIP lookup failed", "ip", item.IP, "error", err)
			continue
		}

		// Only include results with valid coordinates
		if loc.Latitude != 0 || loc.Longitude != 0 {
			locations = append(locations, GeoLocation{
				IP:        item.IP,
				City:      loc.City,
				Country:   loc.Country,
				Latitude:  loc.Latitude,
				Longitude: loc.Longitude,
				Count:     item.Count,
			})
			lookups++
		}
	}

	return locations, ""
}
