package geoip

import (
	"testing"
)

func TestNewReader_InvalidPath(t *testing.T) {
	_, err := NewReader("/nonexistent/path.mmdb")
	if err == nil {
		t.Error("expected error for invalid path, got nil")
	}
}

func TestLocation_Struct(t *testing.T) {
	// Test that Location struct can be created and accessed
	loc := Location{
		City:      "San Francisco",
		Country:   "United States",
		Latitude:  37.7749,
		Longitude: -122.4194,
	}

	if loc.City != "San Francisco" {
		t.Errorf("expected City 'San Francisco', got '%s'", loc.City)
	}
	if loc.Country != "United States" {
		t.Errorf("expected Country 'United States', got '%s'", loc.Country)
	}
	if loc.Latitude != 37.7749 {
		t.Errorf("expected Latitude 37.7749, got %f", loc.Latitude)
	}
	if loc.Longitude != -122.4194 {
		t.Errorf("expected Longitude -122.4194, got %f", loc.Longitude)
	}
}

func TestReader_GetLocation_InvalidIP(t *testing.T) {
	// This test requires a valid database file.
	// Skip if database is not available.
	reader, err := NewReader(DefaultDatabasePath)
	if err != nil {
		t.Skip("GeoIP database not available, skipping test")
	}
	defer reader.Close()

	_, err = reader.GetLocation("not-a-valid-ip")
	if err == nil {
		t.Error("expected error for invalid IP, got nil")
	}
}

func TestReader_GetLocation_ValidIP(t *testing.T) {
	// This test requires a valid database file.
	reader, err := NewReader(DefaultDatabasePath)
	if err != nil {
		t.Skip("GeoIP database not available, skipping test")
	}
	defer reader.Close()

	// Test with Google DNS (well-known public IP)
	loc, err := reader.GetLocation("8.8.8.8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should return some location (exact values may vary with DB version)
	if loc.Country == "" {
		t.Error("expected non-empty country")
	}
}

func TestReader_Close_Multiple(t *testing.T) {
	reader, err := NewReader(DefaultDatabasePath)
	if err != nil {
		t.Skip("GeoIP database not available, skipping test")
	}

	// Close should be idempotent
	if err := reader.Close(); err != nil {
		t.Errorf("first Close() failed: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Errorf("second Close() failed: %v", err)
	}
}

func TestReader_GetLocation_AfterClose(t *testing.T) {
	reader, err := NewReader(DefaultDatabasePath)
	if err != nil {
		t.Skip("GeoIP database not available, skipping test")
	}

	reader.Close()

	_, err = reader.GetLocation("8.8.8.8")
	if err == nil {
		t.Error("expected error when using closed reader")
	}
}
