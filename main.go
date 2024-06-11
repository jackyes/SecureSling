package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
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
	configPath = "./config.yaml"
	bufferSize = 10 * 1024 * 1024 // 10MB buffer size

)

var (
	AppConfig    Cfg
	rateLimiters = make(map[string]*rate.Limiter)
)

type UserCredentials struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Cfg struct {
	ServerPort     string `yaml:"ServerPort"`
	EnableTLS      bool   `yaml:"EnableTLS"`
	CertPathCrt    string `yaml:"CertPathCrt"`
	CertPathKey    string `yaml:"CertPathKey"`
	MaxUploadSize  int64  `yaml:"MaxUploadSize"`
	MaxExpireHours int    `yaml:"MaxExpireHours"`
	UploadPassword string `yaml:"UploadPassword"`
	EnablePassword bool   `yaml:"EnablePassword"`
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

// basicAuth is a middleware function that implements basic authentication
func basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// If password authentication is not enabled, skip to the next handler
		if !AppConfig.EnablePassword {
			next.ServeHTTP(w, r)
			return
		}

		// Get the client's IP address
		ip := r.RemoteAddr

		// Check to see if there is a rate limiter for this IP address
		limiter, ok := rateLimiters[ip]
		if !ok {
			// Create a new rate limiter for this IP address (for example, 5 attempts per minute)
			limiter = rate.NewLimiter(rate.Every(time.Minute/5), 5)
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
	credentials, err := readUserCredentials("credentials.yaml")
	if err != nil {
		fmt.Println("Error reading credentials file:", err)
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

// serveUploadPage serves the upload page template
func serveUploadPage(w http.ResponseWriter, r *http.Request) {
	// Construct the path to the upload.html template
	tmplPath := filepath.Join("templates", "upload.html")

	// Create a new template with a custom function map
	tmpl := template.Must(template.New("").Funcs(template.FuncMap{
		// Register a custom function to format file sizes
		"formatSize": formatSize,
	}).ParseFiles(tmplPath))

	// Calculate the maximum expiry duration as a string
	maxExpireDuration := formatDuration(AppConfig.MaxExpireHours)

	// Create a struct to hold data for the template
	data := struct {
		MaxUploadSize     int64
		MaxExpireDuration string
	}{
		// Set the maximum upload size from the AppConfig
		MaxUploadSize: AppConfig.MaxUploadSize,
		// Set the maximum expiry duration as a string
		MaxExpireDuration: maxExpireDuration,
	}

	// Execute the template with the data
	if err := tmpl.ExecuteTemplate(w, "upload.html", data); err != nil {
		// If there's an error executing the template, return an error response
		http.Error(w, "Error executing template: "+err.Error(), http.StatusInternalServerError)
	}
}

// uploadFile handles the file upload process
func uploadFile(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Starting file upload")
	// Limit file size to AppConfig.MaxUploadSize
	r.Body = http.MaxBytesReader(w, r.Body, AppConfig.MaxUploadSize)

	// Create a multipart reader to read the request body
	reader, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "Error reading multipart data", http.StatusInternalServerError)
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
			break
		}
		if err != nil {
			http.Error(w, "Error reading next part", http.StatusInternalServerError)
			return
		}

		// Check if the part is a file
		if part.FormName() == "file" {
			// Create a temporary file to store the uploaded file
			tempFile, err = os.CreateTemp("uploads", "upload-*.enc")
			if err != nil {
				http.Error(w, "Error creating temporary file", http.StatusInternalServerError)
				return
			}
			tempFilePath = tempFile.Name() // Keep track of the file path
			defer tempFile.Close()

			// Copy the file data from the part to the temporary file
			_, err = io.Copy(tempFile, part)
			if err != nil {
				tempFile.Close()
				os.Remove(tempFilePath) // Clean up the temp file on error
				http.Error(w, "Error writing to temporary file", http.StatusInternalServerError)
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
				http.Error(w, "Invalid date format. Use YYYY-MM-DD.", http.StatusBadRequest)
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
				http.Error(w, "Invalid max downloads value", http.StatusBadRequest)
				return
			}
		}
	}

	if !foundFile {
		http.Error(w, "No file uploaded", http.StatusBadRequest)
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
	infoFile, err := os.Create(filepath.Join("uploads", fileInfo.FileID+".json"))
	if err != nil {
		tempFile.Close()
		os.Remove(tempFilePath) // Clean up the temp file on error
		http.Error(w, "Error creating info file", http.StatusInternalServerError)
		return
	}
	defer infoFile.Close()

	err = json.NewEncoder(infoFile).Encode(fileInfo)
	if err != nil {
		tempFile.Close()
		os.Remove(tempFilePath)                                      // Clean up the temp file on error
		os.Remove(filepath.Join("uploads", fileInfo.FileID+".json")) // Clean up the JSON file on error
		http.Error(w, "Error encoding JSON file", http.StatusInternalServerError)
		return
	}

	// Send response with file info
	jsonResponse, err := json.Marshal(fileInfo)
	if err != nil {
		tempFile.Close()
		os.Remove(tempFilePath)                                      // Clean up the temp file on error
		os.Remove(filepath.Join("uploads", fileInfo.FileID+".json")) // Clean up the JSON file on error
		http.Error(w, "Error creating JSON response", http.StatusInternalServerError)
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

	// Open and decode file info
	infoFilePath := filepath.Join("uploads", fileID+".json")
	infoFile, err := os.Open(infoFilePath)
	if err != nil {
		// If the file is not found, return a 404 error
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	var fileInfo FileInfo
	err = json.NewDecoder(infoFile).Decode(&fileInfo)
	infoFile.Close() // Ensure the file is closed before attempting to delete
	if err != nil {
		// If there's an error decoding the JSON, return a 500 error
		http.Error(w, "Error reading file info", http.StatusInternalServerError)
		return
	}

	// Check if the file has expired
	if fileInfo.ExpiryDate.Before(time.Now()) {
		// If the file has expired, delete it and return a 410 error
		deleteFileAndMetadata(filepath.Join("uploads", fileID), infoFilePath)
		http.Error(w, "File has expired", http.StatusGone)
		return
	}

	// Check if the file has reached the maximum number of downloads
	if fileInfo.MaxDownloads > 0 && fileInfo.Downloads >= fileInfo.MaxDownloads {
		// If the file has reached the maximum number of downloads, return a 410 error
		http.Error(w, "File has reached the maximum number of downloads", http.StatusGone)
		return
	}

	// Increment the download count
	fileInfo.Downloads++
	// Update file info with new download count
	infoFile, err = os.Create(infoFilePath)
	if err != nil {
		// If there's an error updating the info file, return a 500 error
		http.Error(w, "Error updating info file", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(infoFile).Encode(&fileInfo)
	infoFile.Close()

	// Open the actual file for download
	filePath := filepath.Join("uploads", fileID)
	file, err := os.Open(filePath)
	if err != nil {
		// If the file is not found, return a 404 error
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	// Get file stats to set response headers
	fileStat, err := file.Stat()
	if err != nil {
		// If there's an error getting file info, return a 500 error
		http.Error(w, "Error getting file info", http.StatusInternalServerError)
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
			http.Error(w, "Error reading file", http.StatusInternalServerError)
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
	files, err := os.ReadDir("uploads")
	if err != nil {
		// If there's an error reading the directory, print a message and exit
		fmt.Println("Error reading upload directory:", err)
		return
	}

	// Iterate over each file in the directory
	for _, file := range files {
		// Check if the file is a JSON file (metadata file)
		if filepath.Ext(file.Name()) == ".json" {
			// Construct the full path to the metadata file
			infoFilePath := filepath.Join("uploads", file.Name())
			// Open the metadata file
			infoFile, err := os.Open(infoFilePath)
			if err != nil {
				// If there's an error opening the file, print a message and skip to the next file
				fmt.Println("Error opening info file:", err)
				continue
			}

			// Decode the JSON data into a FileInfo struct
			var fileInfo FileInfo
			err = json.NewDecoder(infoFile).Decode(&fileInfo)
			// Ensure the file is closed before attempting to delete
			infoFile.Close()
			if err != nil {
				// If there's an error decoding the JSON, print a message and skip to the next file
				fmt.Println("Error decoding info file:", err)
				continue
			}

			// Check if the file has expired
			if time.Now().After(fileInfo.ExpiryDate) {
				// Construct the full path to the file
				filePath := filepath.Join("uploads", fileInfo.FileID)
				// Delete the file and its metadata
				deleteFileAndMetadata(filePath, infoFilePath)
				fmt.Println("Deleted expired file:", fileInfo.FileID)
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
	// Open the configuration file
	f, err := os.Open(configPath)
	if err != nil {
		// If there's an error, print it and exit
		fmt.Println(err)
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
	}
}

func main() {
	// Read configuration from file
	ReadConfig()

	// Create a new router to handle HTTP requests
	r := mux.NewRouter()

	// Define routes for file upload and download
	// -----------------------------
	// Upload routes
	r.HandleFunc("/upload", basicAuth(uploadFile)).Methods("POST")
	r.HandleFunc("/upload.html", basicAuth(serveUploadPage)).Methods("GET")
	// Share upload routes (same as above, but with /share prefix)
	r.HandleFunc("/share/upload", basicAuth(uploadFile)).Methods("POST")
	r.HandleFunc("/share/upload.html", basicAuth(serveUploadPage)).Methods("GET")

	// Download route
	r.HandleFunc("/download/{fileID}", downloadFile).Methods("GET")
	// Share download route (same as above, but with /share prefix)
	r.HandleFunc("/share/download/{fileID}", downloadFile).Methods("GET")

	// Serve static files directly from the root URL path
	// This allows us to serve static assets (e.g. CSS, JS, images) from the /static directory
	r.PathPrefix("/share/").Handler(http.StripPrefix("/share", http.FileServer(http.Dir("./static"))))
	r.PathPrefix("/").Handler(http.FileServer(http.Dir("./static")))

	// Schedule deletion of old files every hour using cron
	// This ensures that old files are automatically removed from the system
	c := cron.New()
	c.AddFunc("@hourly", deleteOldFiles)
	c.Start()

	// Start the server on port AppConfig.ServerPort
	srv := &http.Server{
		Handler: r,
		Addr:    ":" + AppConfig.ServerPort,
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
