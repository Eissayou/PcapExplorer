// Package geoip provides IP geolocation using the MaxMind GeoLite2 database.
//
// This package uses the free GeoLite2 City database for offline IP geolocation,
// eliminating the need for API calls or a paid MaxMind subscription.
//
// # Database Setup
//
// Before using this package, download the GeoLite2 City database:
//  1. Create a free account at https://www.maxmind.com/en/geolite2/signup
//  2. Download GeoLite2-City.mmdb from your account dashboard
//  3. Place it in the ./data directory (or set GEOIP_DATABASE_PATH)
//
// # Usage Example
//
//	reader, err := geoip.NewReader("./data/GeoLite2-City.mmdb")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer reader.Close()
//
//	loc, err := reader.GetLocation("8.8.8.8")
//	if err != nil {
//	    log.Printf("lookup failed: %v", err)
//	    return
//	}
//
//	fmt.Printf("%s, %s (%.4f, %.4f)\n",
//	    loc.City, loc.Country, loc.Latitude, loc.Longitude)
//
// # Database Updates
//
// MaxMind updates the GeoLite2 database weekly. Consider implementing
// automatic updates using the GeoIP Update program or manual downloads.
package geoip

import (
	"fmt"
	"net"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// DefaultDatabasePath is the default location for the GeoLite2 database file.
const DefaultDatabasePath = "./data/GeoLite2-City.mmdb"

// Location represents geographic information for an IP address.
//
// If the database does not contain information for a particular field,
// that field will be set to "Unknown" (for strings) or 0 (for coordinates).
type Location struct {
	// City is the city name in English, or "Unknown" if unavailable.
	City string `json:"city"`

	// Country is the country name in English, or "Unknown" if unavailable.
	Country string `json:"country"`

	// Latitude is the approximate latitude of the IP's location.
	// A value of 0 may indicate the location is unknown.
	Latitude float64 `json:"latitude"`

	// Longitude is the approximate longitude of the IP's location.
	// A value of 0 may indicate the location is unknown.
	Longitude float64 `json:"longitude"`
}

// geoLite2Record represents the structure of a GeoLite2 City database record.
// This matches the MaxMind MMDB format for city-level data.
type geoLite2Record struct {
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Country struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	Location struct {
		Latitude  float64 `maxminddb:"latitude"`
		Longitude float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// Reader provides thread-safe access to the GeoLite2 database for IP lookups.
//
// Reader is safe for concurrent use by multiple goroutines. The underlying
// database file is memory-mapped for efficient access.
type Reader struct {
	db *maxminddb.Reader
	mu sync.RWMutex
}

// NewReader opens a GeoLite2 database file and returns a Reader for IP lookups.
//
// The database file must be a valid MaxMind DB format file (GeoLite2-City.mmdb).
// The file is memory-mapped, so it must remain accessible while the Reader is open.
//
// Parameters:
//   - databasePath: Path to the GeoLite2-City.mmdb file.
//
// Returns:
//   - *Reader: A reader ready for IP lookups.
//   - error: Non-nil if the database file cannot be opened or is invalid.
//
// The caller must call Close() when done to release resources.
//
// Example:
//
//	reader, err := geoip.NewReader("./data/GeoLite2-City.mmdb")
//	if err != nil {
//	    log.Fatalf("failed to open GeoIP database: %v", err)
//	}
//	defer reader.Close()
func NewReader(databasePath string) (*Reader, error) {
	// TODO: add file watcher for automatic reload when database is updated
	db, err := maxminddb.Open(databasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open GeoLite2 database: %w", err)
	}

	return &Reader{db: db}, nil
}

// Close releases resources associated with the Reader.
//
// After calling Close, the Reader must not be used.
// It is safe to call Close multiple times.
func (r *Reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.db != nil {
		err := r.db.Close()
		r.db = nil
		return err
	}
	return nil
}

// GetLocation looks up the geographic location for an IP address.
//
// This method performs a lookup in the GeoLite2 City database and returns
// the location data. The lookup is thread-safe and can be called from
// multiple goroutines concurrently.
//
// Parameters:
//   - ipStr: The IP address to look up (IPv4 or IPv6 format, e.g., "8.8.8.8").
//
// Returns:
//   - *Location: The geographic location data.
//   - error: Non-nil if the IP is invalid or the lookup fails.
//
// For private/reserved IP addresses (e.g., 192.168.x.x, 10.x.x.x),
// the returned Location will have "Unknown" for City and Country,
// and 0 for coordinates.
//
// Example:
//
//	loc, err := reader.GetLocation("8.8.8.8")
//	if err != nil {
//	    log.Printf("lookup failed: %v", err)
//	    return
//	}
//	fmt.Printf("Location: %s, %s\n", loc.City, loc.Country)
func (r *Reader) GetLocation(ipStr string) (*Location, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if r.db == nil {
		return nil, fmt.Errorf("reader is closed")
	}

	// Parse IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	// Lookup in database
	var record geoLite2Record
	err := r.db.Lookup(ip, &record)
	if err != nil {
		return nil, fmt.Errorf("database lookup failed: %w", err)
	}

	// Build Location with defaults for missing data
	loc := &Location{
		City:      record.City.Names["en"],
		Country:   record.Country.Names["en"],
		Latitude:  record.Location.Latitude,
		Longitude: record.Location.Longitude,
	}

	// Apply default values for missing data
	if loc.City == "" {
		loc.City = "Unknown"
	}
	if loc.Country == "" {
		loc.Country = "Unknown"
	}

	return loc, nil
}
