package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func TestIsValidFileID(t *testing.T) {
	tests := []struct {
		name     string
		fileID   string
		expected bool
	}{
		{"Valid file ID", "abc123-def_456", true},
		{"Valid short ID", "a", true},
		{"Valid long ID", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_", true},
		{"Empty ID", "", false},
		{"Too long ID", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", false},
		{"Path traversal attempt 1", "../etc/passwd", false},
		{"Path traversal attempt 2", "..\\windows\\system32", false},
		{"Path traversal attempt 3", "../../secret", false},
		{"Slashes", "file/with/slashes", false},
		{"Spaces", "file with spaces", false},
		{"Special chars", "file$@#!%", false},
		{"SQL injection attempt", "file'; DROP TABLE users;--", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidFileID(tt.fileID)
			if result != tt.expected {
				t.Errorf("isValidFileID(%q) = %v, want %v", tt.fileID, result, tt.expected)
			}
		})
	}
}

func TestIsValidIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		{"Valid IPv4", "192.168.1.1", true},
		{"Valid IPv6", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", true},
		{"Empty IP", "", false},
		{"Space in IP", "192.168.1.1 ", false},
		{"Newline in IP", "192.168.1.1\n", false},
		{"Invalid format", "not-an-ip", false},
		{"X-Forwarded-For with multiple IPs", "203.0.113.195", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidIP(tt.ip)
			if result != tt.expected {
				t.Errorf("isValidIP(%q) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestDownloadFilePathTraversal(t *testing.T) {
	// Setup
	ReadConfig()

	// Test path traversal attempts
	maliciousFileIDs := []string{
		"../etc/passwd",
		"..\\windows\\system32",
		"../../secret",
		"%2e%2e%2fetc%2fpasswd",
	}

	for _, fileID := range maliciousFileIDs {
		t.Run("Path traversal: "+fileID, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/download/"+fileID, nil)
			rr := httptest.NewRecorder()

			// Create a minimal handler to test validation
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				vars := map[string]string{"fileID": fileID}
				r = mux.SetURLVars(r, vars)

				// Test the validation directly
				if !isValidFileID(fileID) {
					handleError(w, "Invalid file ID format: "+fileID, "Invalid file ID", http.StatusBadRequest)
					return
				}
				w.WriteHeader(http.StatusOK)
			})

			handler.ServeHTTP(rr, req)

			// Should return 400 Bad Request, not 404 or 200
			if rr.Code != http.StatusBadRequest {
				t.Errorf("Expected status 400 for fileID %q, got %d", fileID, rr.Code)
			}
		})
	}
}
