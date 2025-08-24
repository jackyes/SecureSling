package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/robfig/cron/v3"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
)

const (
	bufferSize      = 16 * 1024 * 1024 // 16MB buffer size (optimized for modern systems)
	maxFileIDLength = 100
)

var (
	AppConfig    Cfg
	rateLimiters = make(map[string]*rate.Limiter)
	// Template caching for better performance
	uploadTemplate   *template.Template
	downloadTemplate *template.Template
)

type UserCredentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Cfg struct {
	ServerPort           string `yaml:"ServerPort"`
	EnableTLS            bool   `yaml:"EnableTLS"`
	CertPathCrt          string `yaml:"CertPathCrt"`
	CertPathKey          string `yaml:"CertPathKey"`
	MaxUploadSize        int64  `yaml:"MaxUploadSize"`
	MaxExpireHours       int    `yaml:"MaxExpireHours"`
	EnablePassword       bool   `yaml:"EnablePassword"`
	ShowUploadBox        bool   `yaml:"ShowUploadBox"`
	ShowMenuDownloadPage *bool  `yaml:"ShowMenuDownloadPage"`
	UploadDir            string `yaml:"UploadDir"`
	RateLimitPeriod      int    `yaml:"RateLimitPeriod"`
	RateLimitAttempts    int    `yaml:"RateLimitAttempts"`
	RequireHTTPS         *bool  `yaml:"RequireHTTPS"`
	AllowInsecureHTTP    *bool  `yaml:"AllowInsecureHTTP"`
}

// FileInfo stores metadata about uploaded files
type FileInfo struct {
	FileID          string    `json:"file_id"`
	Timestamp       time.Time `json:"timestamp"`
	OneTimeDownload bool      `json:"one_time_download"`
	ExpiryDate      time.Time `json:"expiry_date,omitempty"`
	MaxDownloads    int       `json:"max_downloads,omitempty"`
	Downloads       int       `json:"downloads"`
}

func formatSize(size int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)

	var result string
	switch {
	case size >= TB:
		result = fmt.Sprintf("%.2f TB", float64(size)/TB)
	case size >= GB:
		result = fmt.Sprintf("%.2f GB", float64(size)/GB)
	case size >= MB:
		result = fmt.Sprintf("%.2f MB", float64(size)/MB)
	case size >= KB:
		result = fmt.Sprintf("%.2f KB", float64(size)/KB)
	default:
		result = fmt.Sprintf("%d bytes", size)
	}

	return result
}

func readUserCredentials(filePath string) ([]UserCredentials, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var credentials []UserCredentials
	err = yaml.Unmarshal(data, &credentials)
	if err != nil {
		return nil, err
	}

	return credentials, nil
}

// Middleware to add security headers
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Only set HSTS if TLS is enabled
		if AppConfig.EnableTLS {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}

		next.ServeHTTP(w, r)
	})
}

// Middleware to redirect HTTP to HTTPS
func httpsRedirect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if HTTPS redirection is enabled and required
		requireHTTPS := AppConfig.RequireHTTPS != nil && *AppConfig.RequireHTTPS
		allowInsecure := AppConfig.AllowInsecureHTTP != nil && *AppConfig.AllowInsecureHTTP

		if AppConfig.EnableTLS && requireHTTPS && !allowInsecure && r.TLS == nil {
			// Redirect to HTTPS
			httpsURL := "https://" + r.Host + r.URL.String()
			http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Middleware to add cache headers
func cacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set Cache-Control and Expires headers for static files
		w.Header().Set("Cache-Control", "public, max-age=86400") // 1 day
		w.Header().Set("Expires", time.Now().AddDate(1, 0, 0).Format(http.TimeFormat))

		next.ServeHTTP(w, r)
	})
}

// Validate file ID to prevent path traversal attacks
func isValidFileID(fileID string) bool {
	if fileID == "" || len(fileID) > maxFileIDLength {
		return false
	}
	// Allow dot in fileID (e.g., upload-12345.enc), still prevent path traversal (no slashes)
	validFileIDRegex := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	return validFileIDRegex.MatchString(fileID)
}

// Secure error handling function
func handleError(w http.ResponseWriter, logMessage string, userMessage string, status int) {
	log.Printf("Error: %s", logMessage)
	http.Error(w, userMessage, status)
}

// Get Client ip from X-Forwarded-For header if exist
func getClientIP(r *http.Request) string {
	// Read the IP from the X-Forwarded-For header, if it exists
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		// X-Forwarded-For can contain a comma-separated list of IP addresses
		// Take the first IP address in the list
		parts := strings.Split(forwarded, ",")
		ip := strings.TrimSpace(parts[0])

		// Basic validation to prevent IP spoofing
		if isValidIP(ip) {
			return ip
		}
	}
	// Otherwise, return the remote IP address
	return r.RemoteAddr
}

// Basic IP validation to prevent spoofing
func isValidIP(ip string) bool {
	// Simple validation - check if it looks like an IP address
	// In production, you might want more robust validation
	if ip == "" || strings.Contains(ip, " ") || strings.Contains(ip, "\n") {
		return false
	}

	// Check for IPv4 or IPv6 patterns
	if strings.Contains(ip, ":") || strings.Contains(ip, ".") {
		return true
	}

	return false
}

// basicAuth is a middleware function that implements basic authentication
func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If password authentication is not enabled, skip to the next handler
		if !AppConfig.EnablePassword {
			next.ServeHTTP(w, r)
			return
		}

		// Get the client's IP address
		ip := getClientIP(r)

		// Check to see if there is a rate limiter for this IP address
		limiter, ok := rateLimiters[ip]
		if !ok {
			// Create a new rate limiter for this IP address (for example, 5 attempts per minute)
			limiter = rate.NewLimiter(rate.Every(time.Duration(AppConfig.RateLimitPeriod)*time.Second), AppConfig.RateLimitAttempts)
			rateLimiters[ip] = limiter
		}

		// Consume a token from the rate limiter
		if !limiter.Allow() {
			// If there are no tokens available, return a 429 Too Many Requests error
			http.Error(w, "Too many requests", http.StatusTooManyRequests)
			return
		}

		// Get the Authorization header from the request
		auth := r.Header.Get("Authorization")
		if auth == "" {
			// If the header is empty, return a 401 Unauthorized response with a WWW-Authenticate header
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Split the Authorization header into two parts: the scheme and the credentials
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) != 2 || parts[0] != "Basic" {
			// If the header is malformed, return a 401 Unauthorized response
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Decode the credentials from base64
		payload, _ := base64.StdEncoding.DecodeString(parts[1])
		pair := strings.SplitN(string(payload), ":", 2)

		if len(pair) != 2 || !validateCredentials(pair[0], pair[1]) {
			// If the credentials are invalid, return a 401 Unauthorized response
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// If the credentials are valid, call the next handler in the chain
		next.ServeHTTP(w, r)
	}
}

// validateCredentials checks if the provided username and password are valid
func validateCredentials(username, password string) bool {
	credentialsPath := "config/credentials.yaml"
	if _, err := os.Stat(credentialsPath); os.IsNotExist(err) {
		credentialsPath = "credentials.yaml"
	}

	credentials, err := readUserCredentials(credentialsPath)
	if err != nil {
		log.Printf("Error reading credentials file: %v", err)
		return false
	}

	for _, cred := range credentials {
		if cred.Username == username {
			err := bcrypt.CompareHashAndPassword([]byte(cred.Password), []byte(password))
			return err == nil
		}
	}

	return false
}

// formatDuration formats a duration in hours into a human-readable string
func formatDuration(hours int) string {
	years := hours / (24 * 365)
	remainingHours := hours % (24 * 365)
	months := remainingHours / (24 * 30) // Approximation: 30 days per month
	remainingHours = remainingHours % (24 * 30)
	weeks := remainingHours / (24 * 7)
	remainingHours = remainingHours % (24 * 7)
	days := remainingHours / 24
	remainingHours = remainingHours % 24

	var durationParts []string

	if years > 0 {
		durationParts = append(durationParts, fmt.Sprintf("%d years", years))
	}
	if months > 0 {
		durationParts = append(durationParts, fmt.Sprintf("%d months", months))
	}
	if weeks > 0 {
		durationParts = append(durationParts, fmt.Sprintf("%d weeks", weeks))
	}
	if days > 0 {
		durationParts = append(durationParts, fmt.Sprintf("%d days", days))
	}
	if remainingHours > 0 {
		durationParts = append(durationParts, fmt.Sprintf("%d hours", remainingHours))
	}

	return strings.Join(durationParts, " ")
}

// initTemplates initializes and caches templates for better performance
func initTemplates() error {
	// Load upload template
	tmplPath := filepath.Join("templates", "upload.html")
	tmpl := template.New("").Funcs(template.FuncMap{
		"formatSize": formatSize,
	})

	var err error
	uploadTemplate, err = tmpl.ParseFiles(tmplPath)
	if err != nil {
		return fmt.Errorf("error parsing upload template: %v", err)
	}

	// Load download template
	tmplPath = filepath.Join("templates", "download.html")
	downloadTemplate, err = template.ParseFiles(tmplPath)
	if err != nil {
		return fmt.Errorf("error parsing download template: %v", err)
	}

	return nil
}

// serveUploadPage serves the upload page template
func serveUploadPage(w http.ResponseWriter, r *http.Request) {
	// Calculate the maximum expiry duration as a string
	maxExpireDuration := formatDuration(AppConfig.MaxExpireHours)

	// Create a struct to hold data for the template
	data := struct {
		MaxUploadSize     int64
		MaxExpireDuration string
	}{
		MaxUploadSize:     AppConfig.MaxUploadSize,
		MaxExpireDuration: maxExpireDuration,
	}

	// Execute the cached template with the data
	if err := uploadTemplate.ExecuteTemplate(w, "upload.html", data); err != nil {
		handleError(w, "Error executing template: "+err.Error(), "Internal server error", http.StatusInternalServerError)
	}
}

// validateInput checks if the input data is valid
func validateExpiryDate(expiryDate time.Time) error {
	if expiryDate.Before(time.Now()) {
		return fmt.Errorf("expiry date must be in the future")
	}
	return nil
}

func validateMaxDownloads(maxDownloads int) error {
	if maxDownloads < 0 {
		return fmt.Errorf("max downloads must be non-negative")
	}
	return nil
}

func validateInput(oneTimeDownload bool, expiryDate time.Time, maxDownloads int) error {
	if err := validateExpiryDate(expiryDate); err != nil {
		return err
	}
	if err := validateMaxDownloads(maxDownloads); err != nil {
		return err
	}
	return nil
}

// uploadFile handles the file upload process
func uploadFile(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Starting file upload")
	// Limit file size to AppConfig.MaxUploadSize
	r.Body = http.MaxBytesReader(w, r.Body, AppConfig.MaxUploadSize)

	// Create a multipart reader to read the request body
	reader, err := r.MultipartReader()
	if err != nil {
		handleError(w, "Error reading multipart data: "+err.Error(), "Error processing request", http.StatusInternalServerError)
		return
	}

	// Initialize variables to store file information
	var tempFile *os.File
	var tempFilePath string
	var foundFile bool
	var oneTimeDownload bool
	var expiryDate time.Time
	var maxDownloads int

	// Default expiry date to x hours from now
	expiryDate = time.Now().Add(time.Duration(AppConfig.MaxExpireHours) * time.Hour)

	// Iterate over each part of the multipart request
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break // No more parts to read
		}
		if err != nil {
			handleError(w, "Error reading multipart data: "+err.Error(), "Error processing request", http.StatusInternalServerError)
			return
		}

		// Check if the part is a file
		if part.FormName() == "file" {
			// Create a temporary file to store the uploaded file
			tempFile, err = os.CreateTemp(AppConfig.UploadDir, "upload-*.enc")
			if err != nil {
				handleError(w, "Error creating temporary file: "+err.Error(), "Error processing file", http.StatusInternalServerError)
				return
			}
			tempFilePath = tempFile.Name() // Keep track of the file path
			defer tempFile.Close()

			// Copy the file data from the part to the temporary file
			_, err = io.Copy(tempFile, part)
			if err != nil {
				tempFile.Close()
				os.Remove(tempFilePath) // Clean up the temp file on error
				handleError(w, "Error writing to temporary file: "+err.Error(), "Error processing file", http.StatusInternalServerError)
				return
			}

			foundFile = true
		} else if part.FormName() == "oneTimeDownload" {
			// Read the one-time download flag from the part
			buf := new(bytes.Buffer)
			buf.ReadFrom(part)
			oneTimeDownload = buf.String() == "true"
		} else if part.FormName() == "expiryDate" {
			// Read the expiry date from the part
			buf := new(bytes.Buffer)
			buf.ReadFrom(part)
			expiryDate, err = time.Parse("2006-01-02", buf.String())
			if err != nil {
				tempFile.Close()
				os.Remove(tempFilePath) // Clean up the temp file on error
				handleError(w, "Invalid date format: "+buf.String(), "Invalid date format. Use YYYY-MM-DD.", http.StatusBadRequest)
				return
			}
		} else if part.FormName() == "maxDownloads" {
			// Read the maximum downloads value from the part
			buf := new(bytes.Buffer)
			buf.ReadFrom(part)
			maxDownloads, err = strconv.Atoi(buf.String())
			if err != nil {
				tempFile.Close()
				os.Remove(tempFilePath) // Clean up the temp file on error
				handleError(w, "Invalid max downloads value: "+buf.String(), "Invalid max downloads value", http.StatusBadRequest)
				return
			}
		}
	}

	// Check if a file was uploaded
	if !foundFile {
		handleError(w, "No file uploaded", "No file uploaded", http.StatusBadRequest)
		return
	}

	// Validate input data
	if err := validateInput(oneTimeDownload, expiryDate, maxDownloads); err != nil {
		tempFile.Close()
		os.Remove(tempFilePath) // Clean up the temp file on error
		handleError(w, "Validation error: "+err.Error(), err.Error(), http.StatusBadRequest)
		return
	}

	// Create a FileInfo struct to store file information
	fileInfo := FileInfo{
		FileID:          filepath.Base(tempFile.Name()),
		Timestamp:       time.Now(),
		OneTimeDownload: oneTimeDownload,
		ExpiryDate:      expiryDate,
		MaxDownloads:    maxDownloads,
		Downloads:       0,
	}

	// Save file info to JSON file
	infoFile, err := os.Create(filepath.Join(AppConfig.UploadDir, fileInfo.FileID+".json"))
	if err != nil {
		tempFile.Close()
		os.Remove(tempFilePath) // Clean up the temp file on error
		handleError(w, "Error creating info file: "+err.Error(), "Error processing file", http.StatusInternalServerError)
		return
	}
	defer infoFile.Close()

	err = json.NewEncoder(infoFile).Encode(fileInfo)
	if err != nil {
		tempFile.Close()
		os.Remove(tempFilePath)                                                // Clean up the temp file on error
		os.Remove(filepath.Join(AppConfig.UploadDir, fileInfo.FileID+".json")) // Clean up the JSON file on error
		handleError(w, "Error encoding JSON file: "+err.Error(), "Error processing file", http.StatusInternalServerError)
		return
	}

	// Send response with file info
	jsonResponse, err := json.Marshal(fileInfo)
	if err != nil {
		tempFile.Close()
		os.Remove(tempFilePath)                                                // Clean up the temp file on error
		os.Remove(filepath.Join(AppConfig.UploadDir, fileInfo.FileID+".json")) // Clean up the JSON file on error
		handleError(w, "Error creating JSON response: "+err.Error(), "Error processing file", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(jsonResponse)
	fmt.Println("File uploaded successfully:", fileInfo.FileID)
}

// downloadFile handles the file download process
func downloadFile(w http.ResponseWriter, r *http.Request) {
	// Extract the file ID from the URL path
	vars := mux.Vars(r)
	fileID := vars["fileID"]

	// Validate file ID to prevent path traversal attacks
	if !isValidFileID(fileID) {
		handleError(w, "Invalid file ID format: "+fileID, "Invalid file ID", http.StatusBadRequest)
		return
	}

	// Open and decode file info
	infoFilePath := filepath.Join(AppConfig.UploadDir, fileID+".json")
	infoFile, err := os.Open(infoFilePath)
	if err != nil {
		// If the file is not found, return a 404 error
		handleError(w, "File not found: "+fileID, "File not found", http.StatusNotFound)
		return
	}

	var fileInfo FileInfo
	err = json.NewDecoder(infoFile).Decode(&fileInfo)
	infoFile.Close() // Ensure the file is closed before attempting to delete
	if err != nil {
		// If there's an error decoding the JSON, return a 500 error
		handleError(w, "Error reading file info: "+err.Error(), "Error processing file", http.StatusInternalServerError)
		return
	}

	// Check if the file has expired
	if fileInfo.ExpiryDate.Before(time.Now()) {
		// If the file has expired, delete it and return a 410 error
		deleteFileAndMetadata(filepath.Join(AppConfig.UploadDir, fileID), infoFilePath)
		handleError(w, "File has expired: "+fileID, "File has expired", http.StatusGone)
		return
	}

	// Check if the file has reached the maximum number of downloads
	if fileInfo.MaxDownloads > 0 && fileInfo.Downloads >= fileInfo.MaxDownloads {
		// If the file has reached the maximum number of downloads, return a 410 error
		handleError(w, "File has reached maximum downloads: "+fileID, "File has reached the maximum number of downloads", http.StatusGone)
		return
	}

	// Increment the download count
	fileInfo.Downloads++
	// Update file info with new download count
	infoFile, err = os.Create(infoFilePath)
	if err != nil {
		// If there's an error updating the info file, return a 500 error
		handleError(w, "Error updating info file: "+err.Error(), "Error processing file", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(infoFile).Encode(&fileInfo)
	infoFile.Close()

	// Open the actual file for download
	filePath := filepath.Join(AppConfig.UploadDir, fileID)
	file, err := os.Open(filePath)
	if err != nil {
		// If the file is not found, return a 404 error
		handleError(w, "File not found: "+filePath, "File not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	// Get file stats to set response headers
	fileStat, err := file.Stat()
	if err != nil {
		// If there's an error getting file info, return a 500 error
		handleError(w, "Error getting file info: "+err.Error(), "Error processing file", http.StatusInternalServerError)
		return
	}

	// Set headers and write file to response
	w.Header().Set("Content-Disposition", "attachment; filename="+fileID)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", fileStat.Size()))

	buffer := make([]byte, bufferSize)
	for {
		n, err := file.Read(buffer)
		if err != nil {
			if err == os.ErrClosed || err == io.EOF {
				break
			}
			// If there's an error reading the file, return a 500 error
			handleError(w, "Error reading file: "+err.Error(), "Error processing file", http.StatusInternalServerError)
			return
		}
		if n > 0 {
			w.Write(buffer[:n])
			w.(http.Flusher).Flush()
		}
	}

	// Delete file if it's a one-time download or reached max downloads
	if fileInfo.OneTimeDownload || (fileInfo.MaxDownloads > 0 && fileInfo.Downloads >= fileInfo.MaxDownloads) {
		deleteFileAndMetadata(filePath, infoFilePath)
		fmt.Println("Deleted file:", fileID)
	}
}

// deleteOldFiles scans the uploads directory and deletes expired files
func deleteOldFiles() {
	// Read the contents of the uploads directory
	files, err := os.ReadDir(AppConfig.UploadDir)
	if err != nil {
		fmt.Println("Error reading upload directory:", err)
		return
	}

	// Batch processing for better performance
	const batchSize = 100
	var batchCount int

	for _, file := range files {
		// Check if the file is a JSON file (metadata file)
		if filepath.Ext(file.Name()) == ".json" {
			infoFilePath := filepath.Join(AppConfig.UploadDir, file.Name())

			// Read file content once and parse
			content, err := os.ReadFile(infoFilePath)
			if err != nil {
				fmt.Println("Error reading info file:", err)
				continue
			}

			var fileInfo FileInfo
			if err := json.Unmarshal(content, &fileInfo); err != nil {
				fmt.Println("Error decoding info file:", err)
				continue
			}

			// Check if the file has expired
			if time.Now().After(fileInfo.ExpiryDate) {
				filePath := filepath.Join(AppConfig.UploadDir, fileInfo.FileID)
				deleteFileAndMetadata(filePath, infoFilePath)
				fmt.Println("Deleted expired file:", fileInfo.FileID)

				// Process in batches to avoid overwhelming the system
				batchCount++
				if batchCount >= batchSize {
					time.Sleep(100 * time.Millisecond) // Small delay between batches
					batchCount = 0
				}
			}
		}
	}
}

// deleteFileAndMetadata deletes a file and its associated metadata file
func deleteFileAndMetadata(filePath, infoFilePath string) {
	// Attempt to delete the file
	if err := os.Remove(filePath); err != nil {
		// If there's an error deleting the file, print a message with the file path and error
		fmt.Println("Error deleting file:", filePath, err)
	}
	// Attempt to delete the metadata file
	if err := os.Remove(infoFilePath); err != nil {
		// If there's an error deleting the metadata file, print a message with the file path and error
		fmt.Println("Error deleting metadata file:", infoFilePath, err)
	}
}

// ReadConfig reads the configuration file and populates the AppConfig struct
func ReadConfig() {
	configPath := "./config/config.yaml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		configPath = "./config.yaml"
	}

	// Open the configuration file
	f, err := os.Open(configPath)
	if err != nil {
		// If there's an error, print it and exit
		fmt.Println(err)
		return
	}
	// Defer closing the file until we're done with it
	defer f.Close()

	// Create a new YAML decoder to read the configuration file
	decoder := yaml.NewDecoder(f)
	// Decode the YAML data into the AppConfig struct
	err = decoder.Decode(&AppConfig)
	if err != nil {
		// If there's an error decoding the YAML, print it and exit
		fmt.Println(err)
		return
	}

	// Set default value for UploadDir if it's not specified in the config
	if AppConfig.UploadDir == "" {
		AppConfig.UploadDir = "./uploads"
	}
	// Set default values for rate limiting if they are not specified in the config
	if AppConfig.RateLimitPeriod <= 0 {
		AppConfig.RateLimitPeriod = 60 // Default to 60 seconds
	}
	if AppConfig.RateLimitAttempts <= 0 {
		AppConfig.RateLimitAttempts = 5 // Default to 5 attempts
	}
	if AppConfig.ShowMenuDownloadPage == nil {
		defaultValue := true
		AppConfig.ShowMenuDownloadPage = &defaultValue
	}
	// Set default values for HTTPS settings
	if AppConfig.RequireHTTPS == nil {
		defaultRequireHTTPS := true
		AppConfig.RequireHTTPS = &defaultRequireHTTPS
	}
	if AppConfig.AllowInsecureHTTP == nil {
		defaultAllowInsecure := false
		AppConfig.AllowInsecureHTTP = &defaultAllowInsecure
	}
}

func serveDownloadPage(w http.ResponseWriter, r *http.Request) {
	// Create a struct to hold data for the template
	data := struct {
		ShowUploadBox        bool
		ShowMenuDownloadPage bool
	}{
		ShowUploadBox:        AppConfig.ShowUploadBox,
		ShowMenuDownloadPage: *AppConfig.ShowMenuDownloadPage,
	}

	// Execute the cached template with the data
	if err := downloadTemplate.ExecuteTemplate(w, "download.html", data); err != nil {
		handleError(w, "Error executing template: "+err.Error(), "Internal server error", http.StatusInternalServerError)
	}
}

func main() {
	// Read configuration from file
	ReadConfig()

	// Initialize template caching
	if err := initTemplates(); err != nil {
		fmt.Printf("Error initializing templates: %v\n", err)
		return
	}

	// Ensure the upload directory exists
	if _, err := os.Stat(AppConfig.UploadDir); os.IsNotExist(err) {
		err := os.MkdirAll(AppConfig.UploadDir, os.ModePerm)
		if err != nil {
			fmt.Printf("Error creating upload directory: %v\n", err)
			return
		}
	}

	// Create a new router to handle HTTP requests
	r := mux.NewRouter().StrictSlash(true) // Enable strict slash for better routing

	// Define routes for file upload and download
	// -----------------------------
	// Upload routes
	r.HandleFunc("/upload", basicAuth(uploadFile)).Methods("POST")
	r.HandleFunc("/upload.html", basicAuth(serveUploadPage)).Methods("GET")

	r.HandleFunc("/download.html", serveDownloadPage).Methods("GET")
	// Share download route (same as above, but with /share prefix)
	r.HandleFunc("/share/download.html", serveDownloadPage).Methods("GET")

	// Share upload routes (same as above, but with /share prefix)
	r.HandleFunc("/share/upload", basicAuth(uploadFile)).Methods("POST")
	r.HandleFunc("/share/upload.html", basicAuth(serveUploadPage)).Methods("GET")

	// Download route
	r.HandleFunc("/download/{fileID}", downloadFile).Methods("GET")
	// Share download route (same as above, but with /share prefix)
	r.HandleFunc("/share/download/{fileID}", downloadFile).Methods("GET")

	// Serve static files directly from the root URL path
	// This allows us to serve static assets (e.g. CSS, JS, images) from the /static directory
	// Serve static files with security and caching middleware
	staticHandler := securityHeaders(cacheMiddleware(http.FileServer(http.Dir("./static"))))
	r.PathPrefix("/share/").Handler(http.StripPrefix("/share", staticHandler))
	r.PathPrefix("/").Handler(staticHandler)

	// Schedule deletion of old files every hour using cron
	// This ensures that old files are automatically removed from the system
	c := cron.New()
	c.AddFunc("@hourly", deleteOldFiles)
	c.Start()

	// Apply security headers to all routes
	securedRouter := securityHeaders(r)

	// Apply HTTPS redirection if enabled
	var finalHandler http.Handler = securedRouter
	if AppConfig.EnableTLS && AppConfig.RequireHTTPS != nil && *AppConfig.RequireHTTPS {
		finalHandler = httpsRedirect(securedRouter)
	}

	// Start the server on port AppConfig.ServerPort with optimized settings
	srv := &http.Server{
		Handler: finalHandler,
		Addr:    ":" + AppConfig.ServerPort,
		// Optimized timeouts for better performance and security
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB max header size
	}

	// Print startup message and server status
	fmt.Println("Starting server on port " + AppConfig.ServerPort)
	if AppConfig.EnableTLS {
		fmt.Println("HTTPS enabled")
		// Start the server with TLS enabled
		if err := srv.ListenAndServeTLS(AppConfig.CertPathCrt, AppConfig.CertPathKey); err != nil {
			fmt.Println("Server error:", err)
		}
	} else {
		fmt.Println("HTTPS disabled, using HTTP")
		// Start the server with TLS disabled
		if err := srv.ListenAndServe(); err != nil {
			fmt.Println("Server error:", err)
		}
	}
}
