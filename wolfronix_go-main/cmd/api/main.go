package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"wolfronixgo/internal/clientdb"
	"wolfronixgo/internal/fakegen"
	"wolfronixgo/internal/keywrap"
	"wolfronixgo/internal/masking"
	"wolfronixgo/internal/metrics"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

// --- GLOBALS ---
var (
	ServerPrivateKey *rsa.PrivateKey
	ServerPublicKey  *rsa.PublicKey
	db               *sql.DB
	adminAPIKey      string
	metricsStore     *metrics.MetricsStore
	keyWrapStore     *keywrap.KeyWrapStore
	fakeGen          *fakegen.FakeDataGenerator
	// Client DB components (Enterprise mode)
	clientRegistry *clientdb.ClientRegistry
	clientDBConn   *clientdb.ClientDBConnector
)

// --- DATABASE INIT ---
func initDB() {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		os.Getenv("DB_HOST"), os.Getenv("DB_PORT"), os.Getenv("DB_USER"),
		os.Getenv("DB_PASS"), os.Getenv("DB_NAME"))

	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Println("⚠️ DB Driver Error:", err)
		return
	}
	if err = db.Ping(); err != nil {
		log.Printf("⚠️ DB Connection Failed: %v", err)
	} else {
		log.Println("✅ Connected to Client Vault Database!")
	}

	// Create core tables
	if db != nil {
		initCoreTables()

		// Initialize metrics store
		metricsStore, err = metrics.NewMetricsStore(db)
		if err != nil {
			log.Printf("⚠️ Metrics Store Init Failed: %v", err)
		} else {
			log.Println("📊 Metrics System Initialized!")
		}

		// Initialize key wrap store
		keyWrapStore, err = keywrap.NewKeyWrapStore(db)
		if err != nil {
			log.Printf("⚠️ KeyWrap Store Init Failed: %v", err)
		} else {
			log.Println("🔐 Key Wrapping System Initialized!")
		}

		// Initialize client registry (Wolfronix only stores client metadata)
		clientRegistry, err = clientdb.NewClientRegistry(db)
		if err != nil {
			log.Printf("⚠️ Client Registry Init Failed: %v", err)
		} else {
			log.Println("📋 Client Registry Initialized!")
		}

		// Initialize client DB connector (for enterprise mode)
		clientDBConn = clientdb.NewClientDBConnector()
		log.Println("🔌 Client DB Connector Ready!")

		// Initialize fake data generator
		fakeGen = fakegen.NewFakeDataGenerator()
		log.Println("🎭 Fake Data Generator Initialized!")
	}
}

// initCoreTables creates the core database tables for Wolfronix v1.0
// In enterprise mode, file data is stored via Client's API.
// Wolfronix DB only stores: client_registry, user_keys, and metrics.
func initCoreTables() {
	log.Println("🗄️ Enterprise Mode: No local storage tables needed.")
	log.Println("🗄️ Core Database Tables Initialized!")
}

// --- MAIN FUNCTION ---
func main() {
	// 1. Load or Generate Keys
	loadOrGenerateKeys()

	// 1b. Load Admin API Key (required for admin/management endpoints)
	adminAPIKey = os.Getenv("ADMIN_API_KEY")
	if adminAPIKey == "" {
		log.Println("\u26a0\ufe0f  ADMIN_API_KEY not set — admin endpoints will reject all requests")
	}

	// 2. Connect DB
	initDB()

	// 2b. Initialize messaging subsystem
	initMessaging()

	// 3. Router
	r := mux.NewRouter()
	r.Use(corsMiddleware)
	r.Use(apiKeyAuthMiddleware)

	// Health check endpoint
	r.HandleFunc("/health", healthCheckHandler).Methods("GET", "OPTIONS")

	// API Routes
	r.HandleFunc("/api/v1/keys", getKeysHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/keys/{userId}", getUserKeyHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/encrypt", encryptHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/files", listFilesHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/files/{id}/decrypt", decryptStoredHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/files/{id}", deleteStoredFileHandler).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/api/v1/files/{id}/key", getFileKeyPartHandler).Methods("GET", "OPTIONS")

	// === ENTERPRISE CLIENT REGISTRATION ===
	// Register a new client with their API endpoint (Enterprise mode) - ADMIN ONLY
	r.HandleFunc("/api/v1/enterprise/register", requireAdminKey(registerEnterpriseClientHandler)).Methods("POST", "OPTIONS")
	// List registered clients - ADMIN ONLY
	r.HandleFunc("/api/v1/enterprise/clients", requireAdminKey(listEnterpriseClientsHandler)).Methods("GET", "OPTIONS")
	// Get client info - ADMIN ONLY
	r.HandleFunc("/api/v1/enterprise/clients/{clientID}", requireAdminKey(getEnterpriseClientHandler)).Methods("GET", "OPTIONS")
	// Update client endpoint - ADMIN ONLY
	r.HandleFunc("/api/v1/enterprise/clients/{clientID}", requireAdminKey(updateEnterpriseClientHandler)).Methods("PUT", "OPTIONS")
	// Deactivate (revoke) a client - ADMIN ONLY
	r.HandleFunc("/api/v1/enterprise/clients/{clientID}", requireAdminKey(deactivateEnterpriseClientHandler)).Methods("DELETE", "OPTIONS")

	// === ZERO-KNOWLEDGE KEY MANAGEMENT ROUTES ===
	// Registration: Browser sends wrapped private key + public key
	r.HandleFunc("/api/v1/keys/register", registerUserKeysHandler).Methods("POST", "OPTIONS")
	// Login: Fetch wrapped private key for client-side decryption
	r.HandleFunc("/api/v1/keys/login", loginFetchKeysHandler).Methods("POST", "OPTIONS")
	// Get public key for a user (for encrypting data for them)
	r.HandleFunc("/api/v1/keys/public/{clientID}/{userID}", getPublicKeyHandler).Methods("GET", "OPTIONS")

	// Metrics Routes
	r.HandleFunc("/api/v1/metrics/summary", getMetricsSummaryHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/metrics/clients", getAllClientMetricsHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/metrics/client/{clientID}", getClientMetricsHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/metrics/client/{clientID}/stats", getClientStatsHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/metrics/users", addUserHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/metrics/users", removeUserHandler).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/api/v1/metrics/login", recordUserLoginHandler).Methods("POST", "OPTIONS")

	// === MESSAGE ENCRYPTION ROUTES ===
	r.HandleFunc("/api/v1/messages/encrypt", messageEncryptHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/messages/decrypt", messageDecryptHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/messages/batch/encrypt", messageBatchEncryptHandler).Methods("POST", "OPTIONS")

	// === STREAMING ENCRYPTION (WebSocket) ===
	r.HandleFunc("/api/v1/stream", streamHandler).Methods("GET")

	port := ":5001"
	log.Printf("🚀 Wolfronix Cloud Engine Running on %s (HTTPS)", port)

	// 4. Start Server with Graceful Shutdown
	srv := &http.Server{
		Addr:         port,
		Handler:      r,
		ReadTimeout:  30 * time.Minute,
		WriteTimeout: 30 * time.Minute,
		IdleTimeout:  120 * time.Second,
	}

	// Run server in goroutine
	go func() {
		if err := srv.ListenAndServeTLS("server.crt", "server.key"); err != nil && err != http.ErrServerClosed {
			log.Fatal("❌ Server Start Error: ", err)
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("\n⏳ Shutting down gracefully...")

	// Flush metrics before shutdown
	if metricsStore != nil {
		metricsStore.Close()
		log.Println("📊 Metrics flushed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("❌ Forced shutdown: ", err)
	}
	log.Println("✅ Server stopped cleanly")
}

// --- HANDLERS ---

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	// Allow files up to 4 GB (memory threshold 512MB, rest spills to temp disk)
	err := r.ParseMultipartForm(512 << 20)
	uploadDone := time.Now()
	if err != nil {
		log.Printf("❌ Parse form error: %v", err)
		http.Error(w, `{"error": "File too large or parse error"}`, 400)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, `{"error": "File error"}`, 400)
		return
	}
	defer file.Close()

	clientPubKey := r.FormValue("client_public_key")
	if clientPubKey == "" {
		http.Error(w, `{"error": "Missing client_public_key"}`, 400)
		return
	}

	// Get authenticated client ID (enforces caller can only use their own client)
	clientID, authErr := getAuthenticatedClientID(r)
	if authErr != nil {
		http.Error(w, `{"error": "Authentication failed"}`, 403)
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = r.FormValue("user_id")
	}

	// Verify client is registered
	if clientRegistry == nil || clientDBConn == nil {
		http.Error(w, `{"error": "Enterprise mode not initialized"}`, 503)
		return
	}
	config, err := clientRegistry.GetClientConfig(clientID)
	if err != nil {
		http.Error(w, `{"error": "Client not registered. Register via /api/v1/enterprise/register first"}`, 400)
		return
	}

	isDevEnv := r.Header.Get("X-Environment") == "dev" || r.FormValue("environment") == "dev"

	// === LAYER 3: AES-256-GCM AUTHENTICATED ENCRYPTION ===
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Printf("❌ Crypto RNG failure: %v", err)
		http.Error(w, `{"error": "Encryption init failed"}`, 500)
		return
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		http.Error(w, `{"error": "Encryption init failed"}`, 500)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, `{"error": "Encryption init failed"}`, 500)
		return
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		log.Printf("❌ Crypto RNG failure: %v", err)
		http.Error(w, `{"error": "Encryption init failed"}`, 500)
		return
	}

	// Read entire file for authenticated encryption
	plaintext, err := io.ReadAll(file)
	if err != nil {
		log.Printf("❌ Failed to read file: %v", err)
		http.Error(w, `{"error": "Read error"}`, 500)
		return
	}
	totalSize := int64(len(plaintext))
	readDone := time.Now()

	// AES-256-GCM Seal: nonce is prepended to ciphertext+tag
	encryptedData := gcm.Seal(nonce, nonce, plaintext, nil)
	plaintext = nil // Free plaintext memory immediately (saves ~filesize RAM)
	encryptDone := time.Now()

	log.Printf("📦 Encrypted %d bytes with AES-256-GCM in %dms", totalSize, encryptDone.Sub(readDone).Milliseconds())

	// === LAYER 4: DUAL KEY SPLIT ===
	encA := encryptRSA(key[:16], clientPubKey)
	if encA == "" {
		http.Error(w, `{"error": "Invalid Client Key"}`, 400)
		return
	}
	encB := encryptRSA(key[16:], publicKeyToPEM(ServerPublicKey))

	// Create file metadata
	fileMetadata := &clientdb.StoredFile{
		Filename:    header.Filename,
		FileSize:    totalSize,
		KeyPartA:    encA,
		KeyPartB:    encB,
		IV:          base64.StdEncoding.EncodeToString(nonce),
		EncTimeMS:   encryptDone.Sub(readDone).Milliseconds(),
		ClientID:    clientID,
		UserID:      userID,
		StorageType: "blob",
	}

	// Send to client's API
	storeStart := time.Now()
	fileID, err := clientDBConn.StoreFileWithData(config, fileMetadata, encryptedData)
	encryptedData = nil // Free encrypted data memory after storage
	storeDone := time.Now()
	if err != nil {
		log.Printf("❌ Failed to store in Client DB: %v", err)
		if metricsStore != nil {
			metricsStore.RecordError(clientID, userID, "encrypt", "Client API error: "+err.Error())
		}
		http.Error(w, `{"error": "Failed to store in client database"}`, 500)
		return
	}

	log.Printf("📤 Data sent to Client DB (ID: %d) in %dms", fileID, storeDone.Sub(storeStart).Milliseconds())

	// Layer 1: Store fake data in client's dev DB if dev mode
	if isDevEnv && fakeGen != nil {
		fakeData := fakeGen.FakeFileContentWithMarker(int(totalSize), header.Filename)
		clientDBConn.StoreFakeData(config, fileID, "FAKE_"+header.Filename, fakeData)
		log.Printf("🎭 Layer 1: Fake data sent to Client Dev DB (%d bytes)", len(fakeData))
	}

	// Calculate timing breakdown
	totalDuration := time.Since(start).Milliseconds()
	uploadMs := uploadDone.Sub(start).Milliseconds()
	readMs := readDone.Sub(uploadDone).Milliseconds()
	encryptMs := encryptDone.Sub(readDone).Milliseconds()
	storeMs := storeDone.Sub(storeStart).Milliseconds()

	// Record encryption metrics
	if metricsStore != nil {
		metricsStore.RecordEncryption(clientID, userID, totalDuration, 1, totalSize)
	}

	log.Printf("✅ File encrypted: %s (%d bytes) in %dms [upload=%dms encrypt=%dms store=%dms]",
		header.Filename, totalSize, totalDuration, uploadMs, encryptMs, storeMs)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "success",
		"enc_time_ms": totalDuration,
		"file_size":   totalSize,
		"file_id":     fileID,
		"timing": map[string]int64{
			"upload_ms":  uploadMs,
			"read_ms":    readMs,
			"encrypt_ms": encryptMs,
			"store_ms":   storeMs,
		},
	})
}

// The Crash-Proof Encryption Function
func encryptRSA(data []byte, pubPEM string) string {
	// 1. Decode PEM Block
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		log.Println("❌ RSA Error: PEM decode failed (Key might be empty or corrupt)")
		return ""
	}

	var pub *rsa.PublicKey
	var err error

	// 2. Try PKCS#1 (Traditional RSA)
	pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		// 3. Try PKIX (Web/JS Standard)
		var pubInterface interface{}
		pubInterface, err = x509.ParsePKIXPublicKey(block.Bytes)
		if err == nil {
			var ok bool
			pub, ok = pubInterface.(*rsa.PublicKey)
			if !ok {
				log.Println("❌ RSA Error: Key is not RSA")
				return ""
			}
		}
	}

	// 4. Final Nil Check (Stops the Panic)
	if pub == nil {
		log.Println("❌ RSA Error: Could not parse Public Key (Format invalid)")
		return ""
	}

	// 5. Encrypt with RSA-OAEP (SHA-256)
	out, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)
	if err != nil {
		log.Println("❌ RSA-OAEP Encryption Failed:", err)
		return ""
	}

	return base64.StdEncoding.EncodeToString(out)
}

func listFilesHandler(w http.ResponseWriter, r *http.Request) {
	clientID, err := getAuthenticatedClientID(r)
	if err != nil {
		http.Error(w, `{"error": "Authentication failed"}`, 403)
		return
	}
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = r.URL.Query().Get("user_id")
	}

	if userID == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{})
		return
	}

	if clientRegistry == nil || clientDBConn == nil {
		http.Error(w, `{"error": "Enterprise mode not initialized"}`, 503)
		return
	}

	config, err := clientRegistry.GetClientConfig(clientID)
	if err != nil {
		http.Error(w, `{"error": "Client not registered"}`, 400)
		return
	}

	clientFiles, err := clientDBConn.ListFiles(config, userID)
	if err != nil {
		log.Printf("⚠️ Failed to list files from Client API: %v", err)
		http.Error(w, `{"error": "Failed to fetch files"}`, 500)
		return
	}

	var files []map[string]interface{}
	for _, f := range clientFiles {
		files = append(files, map[string]interface{}{
			"id":         f.ID,
			"name":       f.Filename,
			"date":       f.CreatedAt,
			"size":       fmt.Sprintf("%.2f MB", float64(f.FileSize)/1024/1024),
			"size_bytes": f.FileSize,
			"enc_time":   fmt.Sprintf("%d ms", f.EncTimeMS),
		})
	}

	if files == nil {
		files = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

func decryptStoredHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, `{"error": "Invalid file ID"}`, 400)
		return
	}

	// Parse request body for decryption keys
	var decryptReq struct {
		DecryptedKeyA string `json:"decrypted_key_a"` // base64-encoded 16-byte key half (decrypted client-side)
		ClientID      string `json:"client_id"`
		UserID        string `json:"user_id"`
		UserRole      string `json:"user_role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&decryptReq); err != nil {
		http.Error(w, `{"error": "Invalid JSON request body"}`, 400)
		return
	}

	// Get client ID - REQUIRED in enterprise mode (verified by middleware)
	clientID, err := getAuthenticatedClientID(r)
	if err != nil {
		http.Error(w, `{"error": "Authentication failed"}`, 403)
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = decryptReq.UserID
	}

	userRole := r.Header.Get("X-User-Role")
	if userRole == "" {
		userRole = decryptReq.UserRole
	}
	if userRole == "" {
		userRole = "guest"
	}

	// Verify client is registered
	if clientRegistry == nil || clientDBConn == nil {
		http.Error(w, `{"error": "Enterprise mode not initialized"}`, 503)
		return
	}

	config, err := clientRegistry.GetClientConfig(clientID)
	if err != nil {
		http.Error(w, `{"error": "Client not registered"}`, 400)
		return
	}

	// Fetch file metadata from client's API
	fetchMetaStart := time.Now()
	fileMeta, err := clientDBConn.GetFileMetadata(config, int64(id), userID)
	if err != nil {
		if metricsStore != nil {
			metricsStore.RecordError(clientID, userID, "decrypt", "File not found: "+err.Error())
		}
		http.Error(w, `{"error": "File not found"}`, 404)
		return
	}
	fetchMetaDone := time.Now()

	// Fetch encrypted data from client's API
	encData, err := clientDBConn.GetFileData(config, int64(id), userID)
	fetchDataDone := time.Now()
	if err != nil {
		if metricsStore != nil {
			metricsStore.RecordError(clientID, userID, "decrypt", "Failed to fetch data: "+err.Error())
		}
		http.Error(w, `{"error": "Failed to fetch encrypted data"}`, 500)
		return
	}

	// === UNLOCK DUAL KEYS ===
	var keyA []byte
	keyA, err = base64.StdEncoding.DecodeString(decryptReq.DecryptedKeyA)
	if err != nil || len(keyA) != 16 {
		http.Error(w, `{"error": "decrypted_key_a is required (base64-encoded 16-byte key half)"}`, 400)
		return
	}
	keyB := decryptRSA(fileMeta.KeyPartB, privateKeyToPEM(ServerPrivateKey))

	if keyA == nil || keyB == nil {
		if metricsStore != nil {
			metricsStore.RecordError(clientID, userID, "decrypt", "Key mismatch")
		}
		http.Error(w, `{"error": "Decryption Failed (Key Mismatch)"}`, 403)
		return
	}

	// === LAYER 3: AES-256-GCM AUTHENTICATED DECRYPTION ===
	fullKey := make([]byte, 32)
	copy(fullKey[:16], keyA)
	copy(fullKey[16:], keyB)
	block, err := aes.NewCipher(fullKey)
	if err != nil {
		http.Error(w, `{"error": "Decryption init failed"}`, 500)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, `{"error": "Decryption init failed"}`, 500)
		return
	}
	nonceSize := gcm.NonceSize()
	if len(encData) < nonceSize {
		http.Error(w, `{"error": "Encrypted data corrupted"}`, 400)
		return
	}
	gcmNonce, ciphertext := encData[:nonceSize], encData[nonceSize:]
	decData, err := gcm.Open(nil, gcmNonce, ciphertext, nil)
	encData = nil // Free encrypted data memory
	decryptDone := time.Now()
	if err != nil {
		if metricsStore != nil {
			metricsStore.RecordError(clientID, userID, "decrypt", "Integrity check failed: "+err.Error())
		}
		http.Error(w, `{"error": "Decryption failed - data integrity check failed"}`, 403)
		return
	}

	// === LAYER 2: DYNAMIC RBAC MASKING ===
	contentType := http.DetectContentType(decData)

	// Fallback: if DetectContentType returned generic octet-stream, infer from filename extension
	if contentType == "application/octet-stream" {
		ext := strings.ToLower(filepath.Ext(fileMeta.Filename))
		mimeByExt := map[string]string{
			".mp4": "video/mp4", ".webm": "video/webm", ".ogg": "video/ogg", ".mov": "video/quicktime",
			".avi": "video/x-msvideo", ".mkv": "video/x-matroska", ".flv": "video/x-flv",
			".mp3": "audio/mpeg", ".wav": "audio/wav", ".flac": "audio/flac", ".m4a": "audio/mp4",
			".aac": "audio/aac",
			".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".gif": "image/gif",
			".webp": "image/webp", ".svg": "image/svg+xml", ".bmp": "image/bmp", ".ico": "image/x-icon",
			".pdf":  "application/pdf",
			".json": "application/json", ".xml": "application/xml",
			".html": "text/html", ".css": "text/css", ".js": "text/javascript",
			".txt": "text/plain", ".csv": "text/csv", ".md": "text/markdown",
			".zip": "application/zip", ".gz": "application/gzip",
			".doc": "application/msword", ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
			".xls": "application/vnd.ms-excel", ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
		}
		if m, ok := mimeByExt[ext]; ok {
			contentType = m
		}
	}

	isTextFile := strings.HasPrefix(contentType, "text/") ||
		strings.HasSuffix(strings.ToLower(fileMeta.Filename), ".txt") ||
		strings.HasSuffix(strings.ToLower(fileMeta.Filename), ".csv") ||
		strings.HasSuffix(strings.ToLower(fileMeta.Filename), ".json")

	if isTextFile {
		maskedContent := masking.MaskAllSensitiveInText(string(decData), masking.Role(userRole))
		decData = []byte(maskedContent)
		log.Printf("\xf0\x9f\x94\x92 Layer 2: Applied RBAC masking for role '%s' on file '%s'", userRole, fileMeta.Filename)
	}

	// Record decryption metrics
	duration := time.Since(start).Milliseconds()
	fetchMetaMs := fetchMetaDone.Sub(fetchMetaStart).Milliseconds()
	fetchDataMs := fetchDataDone.Sub(fetchMetaDone).Milliseconds()
	decryptMs := decryptDone.Sub(fetchDataDone).Milliseconds()
	if metricsStore != nil {
		metricsStore.RecordDecryption(clientID, userID, duration, 1, int64(len(decData)))
	}

	// Set response headers (sanitize filename to prevent header injection)
	safeFilename := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, fileMeta.Filename)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, safeFilename))
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Original-Filename", safeFilename)
	w.Header().Set("X-Masking-Applied", userRole)
	w.Header().Set("X-Timing-Total-Ms", strconv.FormatInt(duration, 10))
	w.Header().Set("X-Timing-Fetch-Meta-Ms", strconv.FormatInt(fetchMetaMs, 10))
	w.Header().Set("X-Timing-Fetch-Data-Ms", strconv.FormatInt(fetchDataMs, 10))
	w.Header().Set("X-Timing-Decrypt-Ms", strconv.FormatInt(decryptMs, 10))
	w.Header().Set("Access-Control-Expose-Headers", "Content-Disposition, X-Original-Filename, X-Masking-Applied, X-Timing-Total-Ms, X-Timing-Fetch-Meta-Ms, X-Timing-Fetch-Data-Ms, X-Timing-Decrypt-Ms")
	w.Write(decData)

	log.Printf("\xe2\x9c\x85 Decrypted %d bytes: %s [enterprise]", len(decData), fileMeta.Filename)
}

func deleteStoredFileHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, `{"error": "Invalid file ID"}`, 400)
		return
	}

	clientID, err := getAuthenticatedClientID(r)
	if err != nil {
		http.Error(w, `{"error": "Authentication failed"}`, 403)
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = r.URL.Query().Get("user_id")
	}

	if clientRegistry == nil || clientDBConn == nil {
		http.Error(w, `{"error": "Enterprise mode not initialized"}`, 503)
		return
	}

	config, err2 := clientRegistry.GetClientConfig(clientID)
	if err2 != nil {
		http.Error(w, `{"error": "Client not registered"}`, 400)
		return
	}

	err2 = clientDBConn.DeleteFile(config, int64(id), userID)
	if err2 != nil {
		log.Printf("⚠️ Failed to delete file %d: %v", id, err2)
		http.Error(w, `{"error": "Failed to delete file"}`, 500)
		return
	}

	if metricsStore != nil {
		metricsStore.RecordEncryption(clientID, userID, 0, -1, 0)
	}

	log.Printf("🗑️ File %d deleted by user %s [enterprise]", id, userID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "File deleted successfully",
	})
}

// getFileKeyPartHandler returns the encrypted key_part_a for client-side decryption
// The client decrypts this locally with their private key, then sends the result
// to the decrypt endpoint as decrypted_key_a (private key never leaves the client)
func getFileKeyPartHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, err := strconv.Atoi(vars["id"])
	if err != nil {
		http.Error(w, `{"error": "Invalid file ID"}`, 400)
		return
	}

	clientID, clientErr := getAuthenticatedClientID(r)
	if clientErr != nil {
		http.Error(w, `{"error": "Authentication failed"}`, 403)
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = r.URL.Query().Get("user_id")
	}

	if clientRegistry == nil || clientDBConn == nil {
		http.Error(w, `{"error": "Enterprise mode not initialized"}`, 503)
		return
	}

	config, err := clientRegistry.GetClientConfig(clientID)
	if err != nil {
		http.Error(w, `{"error": "Client not registered"}`, 400)
		return
	}

	fileMeta, err := clientDBConn.GetFileMetadata(config, int64(id), userID)
	if err != nil {
		http.Error(w, `{"error": "File not found"}`, 404)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"file_id":    vars["id"],
		"key_part_a": fileMeta.KeyPartA,
		"message":    "Decrypt key_part_a locally with your private key, then send the 16-byte result base64-encoded as decrypted_key_a to the decrypt endpoint",
	})
}

// --- UTILS ---

func getKeysHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"public_key": publicKeyToPEM(ServerPublicKey)})
}

func getUserKeyHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	targetUserID := vars["userId"]
	if targetUserID == "" {
		http.Error(w, `{"error": "User ID is required"}`, 400)
		return
	}

	clientID, clientErr := getAuthenticatedClientID(r)
	if clientErr != nil {
		http.Error(w, `{"error": "Authentication failed"}`, 403)
		return
	}

	if clientRegistry == nil || clientDBConn == nil {
		http.Error(w, `{"error": "Enterprise mode not initialized"}`, 503)
		return
	}

	config, err := clientRegistry.GetClientConfig(clientID)
	if err != nil {
		http.Error(w, `{"error": "Client not registered"}`, 400)
		return
	}

	publicKeyPEM, err := clientDBConn.GetUserPublicKey(config, targetUserID)
	if err != nil {
		log.Printf("⚠️ Failed to get public key for user %s: %v", targetUserID, err)
		http.Error(w, `{"error": "User key not found"}`, 404)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"user_id":    targetUserID,
		"public_key": publicKeyPEM,
	})
}

func registerClientHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		http.Error(w, `{"error": "Key generation failed"}`, 500)
		return
	}
	json.NewEncoder(w).Encode(map[string]string{"api_key": hex.EncodeToString(keyBytes)})
}

// === ENTERPRISE CLIENT MANAGEMENT ===

// registerEnterpriseClientHandler registers a client with their API endpoint
// Supports managed connectors via db_type + db_config (auto-routed inside Docker)
// or custom_api mode with explicit api_endpoint
func registerEnterpriseClientHandler(w http.ResponseWriter, r *http.Request) {
	if clientRegistry == nil {
		http.Error(w, "Client registry not initialized", 503)
		return
	}

	var req struct {
		ClientID    string `json:"client_id"`
		ClientName  string `json:"client_name"`
		APIEndpoint string `json:"api_endpoint"` // Client's storage API URL (optional if db_type is managed)
		APIKey      string `json:"api_key"`      // Key to call client's API (optional if db_type is managed)
		DBType      string `json:"db_type"`      // supabase, mongodb, mysql, firebase, postgresql, custom_api
		DBConfig    string `json:"db_config"`    // JSON string with DB credentials
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", 400)
		return
	}

	if req.ClientID == "" || req.ClientName == "" {
		http.Error(w, `{"error": "client_id and client_name are required"}`, 400)
		return
	}

	// Validate db_type
	validDBTypes := map[string]bool{
		clientdb.DBTypeSupabase:   true,
		clientdb.DBTypeMongoDB:    true,
		clientdb.DBTypeMySQL:      true,
		clientdb.DBTypeFirebase:   true,
		clientdb.DBTypePostgreSQL: true,
		clientdb.DBTypeCustomAPI:  true,
		"":                        true, // backward compat — treated as custom_api
	}

	if !validDBTypes[req.DBType] {
		http.Error(w, `{"error": "Invalid db_type. Must be: supabase, mongodb, mysql, firebase, postgresql, or custom_api"}`, 400)
		return
	}

	// For managed connectors, db_config is required; api_endpoint is auto-set
	isManaged := req.DBType != "" && req.DBType != clientdb.DBTypeCustomAPI
	if isManaged {
		if req.DBConfig == "" {
			http.Error(w, `{"error": "db_config is required for managed connector types"}`, 400)
			return
		}
		// Validate db_config is valid JSON
		var configCheck map[string]interface{}
		if err := json.Unmarshal([]byte(req.DBConfig), &configCheck); err != nil {
			http.Error(w, `{"error": "db_config must be valid JSON"}`, 400)
			return
		}
	} else {
		// custom_api or empty → require api_endpoint
		if req.APIEndpoint == "" {
			http.Error(w, `{"error": "api_endpoint is required for custom_api db_type"}`, 400)
			return
		}
		// Validate api_endpoint to prevent SSRF
		parsedURL, err := url.Parse(req.APIEndpoint)
		if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
			http.Error(w, `{"error": "api_endpoint must be a valid http/https URL"}`, 400)
			return
		}
	}

	// Generate Wolfronix API key for this client (cryptographically random)
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		http.Error(w, `{"error": "Key generation failed"}`, 500)
		return
	}
	wolfronixKey := hex.EncodeToString(keyBytes)

	// Default db_type to custom_api for backward compat
	dbType := req.DBType
	if dbType == "" {
		dbType = clientdb.DBTypeCustomAPI
	}

	client := &clientdb.RegisteredClient{
		ClientID:     req.ClientID,
		ClientName:   req.ClientName,
		APIEndpoint:  req.APIEndpoint,
		APIKey:       req.APIKey,
		WolfronixKey: wolfronixKey,
		DBType:       dbType,
		DBConfig:     req.DBConfig,
	}

	if err := clientRegistry.RegisterClient(client); err != nil {
		log.Printf("❌ Failed to register client: %v", err)
		http.Error(w, "Failed to register client", 500)
		return
	}

	// Build response
	resp := map[string]interface{}{
		"status":        "success",
		"client_id":     client.ClientID,
		"wolfronix_key": wolfronixKey,
		"db_type":       dbType,
	}
	if isManaged {
		resp["message"] = "Client registered with managed " + dbType + " connector. Use wolfronix_key for API calls."
		resp["connector"] = "auto-routed (internal Docker network)"
	} else {
		resp["message"] = "Client registered. Use wolfronix_key for API calls."
		resp["api_endpoint"] = client.APIEndpoint
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
	log.Printf("✅ Enterprise client registered: %s (db_type=%s)", client.ClientID, dbType)
}

// listEnterpriseClientsHandler lists all registered enterprise clients
func listEnterpriseClientsHandler(w http.ResponseWriter, r *http.Request) {
	if clientRegistry == nil {
		http.Error(w, "Client registry not initialized", 503)
		return
	}

	clients, err := clientRegistry.ListClients()
	if err != nil {
		http.Error(w, "Failed to list clients", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"clients": clients,
		"count":   len(clients),
	})
}

// getEnterpriseClientHandler gets details for a specific client
func getEnterpriseClientHandler(w http.ResponseWriter, r *http.Request) {
	if clientRegistry == nil {
		http.Error(w, "Client registry not initialized", 503)
		return
	}

	vars := mux.Vars(r)
	clientID := vars["clientID"]

	client, err := clientRegistry.GetClient(clientID)
	if err != nil {
		http.Error(w, "Client not found", 404)
		return
	}

	// Don't expose API keys
	client.APIKey = ""

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(client)
}

// updateEnterpriseClientHandler updates a client's configuration
func updateEnterpriseClientHandler(w http.ResponseWriter, r *http.Request) {
	if clientRegistry == nil {
		http.Error(w, "Client registry not initialized", 503)
		return
	}

	vars := mux.Vars(r)
	clientID := vars["clientID"]

	var req struct {
		APIEndpoint string `json:"api_endpoint"`
		DBType      string `json:"db_type"`
		DBConfig    string `json:"db_config"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", 400)
		return
	}

	if req.APIEndpoint != "" {
		// Validate api_endpoint to prevent SSRF (same validation as register handler)
		parsedURL, err := url.Parse(req.APIEndpoint)
		if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
			http.Error(w, `{"error": "api_endpoint must be a valid http/https URL"}`, 400)
			return
		}

		if err := clientRegistry.UpdateClientEndpoint(clientID, req.APIEndpoint); err != nil {
			http.Error(w, "Failed to update client", 500)
			return
		}
	}

	// Update db_type / db_config if provided
	if req.DBType != "" || req.DBConfig != "" {
		validDBTypes := map[string]bool{
			clientdb.DBTypeSupabase: true, clientdb.DBTypeMongoDB: true,
			clientdb.DBTypeMySQL: true, clientdb.DBTypeFirebase: true,
			clientdb.DBTypePostgreSQL: true, clientdb.DBTypeCustomAPI: true,
		}
		if req.DBType != "" && !validDBTypes[req.DBType] {
			http.Error(w, `{"error": "Invalid db_type"}`, 400)
			return
		}
		if req.DBConfig != "" {
			var configCheck map[string]interface{}
			if err := json.Unmarshal([]byte(req.DBConfig), &configCheck); err != nil {
				http.Error(w, `{"error": "db_config must be valid JSON"}`, 400)
				return
			}
		}
		if err := clientRegistry.UpdateClientConfig(clientID, req.DBType, req.DBConfig); err != nil {
			http.Error(w, "Failed to update client config", 500)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Client updated",
	})
}

// deactivateEnterpriseClientHandler deactivates a client (revokes their access)
// DELETE /api/v1/enterprise/clients/{clientID}
func deactivateEnterpriseClientHandler(w http.ResponseWriter, r *http.Request) {
	if clientRegistry == nil {
		http.Error(w, "Client registry not initialized", 503)
		return
	}

	vars := mux.Vars(r)
	clientID := vars["clientID"]

	if err := clientRegistry.DeactivateClient(clientID); err != nil {
		log.Printf("❌ Failed to deactivate client %s: %v", clientID, err)
		http.Error(w, `{"error": "Failed to deactivate client"}`, 500)
		return
	}

	log.Printf("🚫 Enterprise client deactivated: %s", clientID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Client deactivated. Their API key will no longer work.",
	})
}

func loadOrGenerateKeys() {
	// Try loading existing key
	privBytes, err := os.ReadFile("server.key")
	var block *pem.Block
	if err == nil && len(privBytes) > 0 {
		block, _ = pem.Decode(privBytes)
	}

	if block != nil {
		// Handle both PKCS#1 and PKCS#8 formats
		if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			ServerPrivateKey = k
		} else if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			ServerPrivateKey = k.(*rsa.PrivateKey)
		}
	}

	// If missing or invalid, generate FRESH pair
	if ServerPrivateKey == nil {
		log.Println("⚙️  Generating Fresh 2048-bit RSA Keys & Self-Signed Certs...")
		var err error
		ServerPrivateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatal("❌ Failed to generate RSA keys: ", err)
		}

		// Save Private Key
		keyOut, err := os.Create("server.key")
		if err != nil {
			log.Fatal("❌ Failed to create server.key: ", err)
		}
		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ServerPrivateKey)})
		keyOut.Close()

		// Generate Cert with SANs for modern TLS clients
		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{Organization: []string{"Wolfronix Secure"}},
			DNSNames:     []string{"localhost", "wolfronix", "wolfronix-engine"},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &ServerPrivateKey.PublicKey, ServerPrivateKey)
		if err != nil {
			log.Fatal("❌ Failed to create certificate: ", err)
		}

		// Save Cert
		certOut, err := os.Create("server.crt")
		if err != nil {
			log.Fatal("❌ Failed to create server.crt: ", err)
		}
		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
		certOut.Close()
	}
	ServerPublicKey = &ServerPrivateKey.PublicKey
	log.Println("🔑 Crypto System Initialized.")
}

func decryptRSA(b64 string, privPEM string) []byte {
	data, _ := base64.StdEncoding.DecodeString(b64)
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil
	}

	// Handle PKCS#1 vs PKCS#8 for Private Key too
	var priv *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		priv = k
	} else if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		priv = k.(*rsa.PrivateKey)
	}

	if priv == nil {
		return nil
	}

	out, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, data, nil)
	if err != nil {
		log.Printf("\u274c RSA-OAEP Decryption Failed: %v", err)
		return nil
	}
	return out
}

func publicKeyToPEM(pub *rsa.PublicKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(pub)}))
}

func privateKeyToPEM(priv *rsa.PrivateKey) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)}))
}

// Health check handler for monitoring
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	status := "healthy"
	dbStatus := "connected"

	// Check database connection
	if db == nil {
		dbStatus = "not initialized"
	} else if err := db.Ping(); err != nil {
		dbStatus = "disconnected"
		status = "degraded"
	}

	response := map[string]interface{}{
		"status":    status,
		"service":   "wolfronix",
		"version":   "2.4.1",
		"database":  dbStatus,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	if status == "healthy" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	json.NewEncoder(w).Encode(response)
}

func corsMiddleware(next http.Handler) http.Handler {
	allowedOrigins := getAllowedOrigins()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// Wildcard: allow all origins
		allowAll := len(allowedOrigins) == 1 && allowedOrigins[0] == "*"
		allowed := allowAll
		if !allowAll {
			for _, o := range allowedOrigins {
				if strings.TrimSpace(o) == origin {
					allowed = true
					break
				}
			}
		}
		if allowed && origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Client-ID, X-User-ID, X-User-Role, X-Wolfronix-Key, X-Environment")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Disposition, X-Masking-Applied")
		w.Header().Set("Vary", "Origin")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// getAllowedOrigins returns configured CORS origins from ALLOWED_ORIGINS env var
func getAllowedOrigins() []string {
	origins := os.Getenv("ALLOWED_ORIGINS")
	if origins == "" {
		return []string{
			"http://localhost:5500", "https://localhost:5500",
			"http://localhost:3000", "https://localhost:3000",
			"http://127.0.0.1:5500", "https://127.0.0.1:5500",
		}
	}
	return strings.Split(origins, ",")
}

// getAuthenticatedClientID returns the client ID that was verified by apiKeyAuthMiddleware.
// It rejects requests where the caller-supplied X-Client-ID doesn't match the authenticated identity.
// This prevents client impersonation (e.g., client A using client B's X-Client-ID).
func getAuthenticatedClientID(r *http.Request) (string, error) {
	authenticatedID := r.Header.Get("X-Authenticated-Client-ID")
	if authenticatedID == "" {
		return "", errors.New("not authenticated")
	}

	// Check all sources where handlers read client ID
	suppliedID := r.Header.Get("X-Client-ID")
	if suppliedID == "" {
		suppliedID = r.FormValue("client_id")
	}
	if suppliedID == "" {
		suppliedID = r.URL.Query().Get("client_id")
	}

	// If caller explicitly supplied a client ID, it MUST match the authenticated one
	if suppliedID != "" && suppliedID != authenticatedID {
		return "", fmt.Errorf("client ID mismatch: authenticated as %q but requested %q", authenticatedID, suppliedID)
	}

	return authenticatedID, nil
}

// apiKeyAuthMiddleware validates X-Wolfronix-Key header for all API endpoints
func apiKeyAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for health check and public key endpoint
		if r.URL.Path == "/health" || r.URL.Path == "/api/v1/keys" {
			next.ServeHTTP(w, r)
			return
		}
		// Admin endpoints use X-Admin-Key (handled by requireAdminKey wrapper)
		if r.URL.Path == "/api/v1/enterprise/register" || r.URL.Path == "/admin/clients" ||
			strings.HasPrefix(r.URL.Path, "/api/v1/enterprise/clients") {
			next.ServeHTTP(w, r)
			return
		}
		// Skip OPTIONS preflight
		if r.Method == "OPTIONS" {
			next.ServeHTTP(w, r)
			return
		}

		wolfronixKey := r.Header.Get("X-Wolfronix-Key")
		if wolfronixKey == "" {
			// Fallback to query param (for WebSocket — browsers can't set custom headers)
			wolfronixKey = r.URL.Query().Get("wolfronix_key")
		}
		if wolfronixKey == "" {
			http.Error(w, `{"error": "Missing X-Wolfronix-Key authentication header"}`, 401)
			return
		}

		if clientRegistry == nil {
			http.Error(w, `{"error": "Auth system not initialized"}`, 503)
			return
		}

		client, err := clientRegistry.GetClientByWolfronixKey(wolfronixKey)
		if err != nil {
			http.Error(w, `{"error": "Invalid API key"}`, 403)
			return
		}

		// Set authenticated client ID for downstream handlers
		r.Header.Set("X-Authenticated-Client-ID", client.ClientID)
		next.ServeHTTP(w, r)
	})
}

// requireAdminKey wraps a handler to require ADMIN_API_KEY via X-Admin-Key header.
// Admin endpoints skip the normal wolfronix-key auth (handled before apiKeyAuthMiddleware).
func requireAdminKey(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "OPTIONS" {
			handler(w, r)
			return
		}
		key := r.Header.Get("X-Admin-Key")
		if adminAPIKey == "" {
			http.Error(w, `{"error": "Admin endpoint not configured (ADMIN_API_KEY not set)"}`, 503)
			return
		}
		if subtle.ConstantTimeCompare([]byte(key), []byte(adminAPIKey)) != 1 {
			http.Error(w, `{"error": "Invalid or missing X-Admin-Key"}`, 403)
			return
		}
		handler(w, r)
	}
}

// --- METRICS HANDLERS ---

func getMetricsSummaryHandler(w http.ResponseWriter, r *http.Request) {
	if metricsStore == nil {
		http.Error(w, `{"error": "metrics not initialized"}`, http.StatusServiceUnavailable)
		return
	}

	summary, err := metricsStore.GetMetricsSummary()
	if err != nil {
		http.Error(w, `{"error": "failed to fetch summary"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summary)
}

func getAllClientMetricsHandler(w http.ResponseWriter, r *http.Request) {
	if metricsStore == nil {
		http.Error(w, `{"error": "metrics not initialized"}`, http.StatusServiceUnavailable)
		return
	}

	clientMetrics, err := metricsStore.GetAllClientMetrics()
	if err != nil {
		http.Error(w, `{"error": "failed to fetch metrics"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"clients": clientMetrics,
		"count":   len(clientMetrics),
	})
}

func getClientMetricsHandler(w http.ResponseWriter, r *http.Request) {
	if metricsStore == nil {
		http.Error(w, `{"error": "metrics not initialized"}`, http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	clientID := vars["clientID"]
	if clientID == "" {
		clientID = r.URL.Query().Get("client_id")
	}

	if clientID == "" {
		http.Error(w, `{"error": "client_id is required"}`, http.StatusBadRequest)
		return
	}

	clientMetrics, err := metricsStore.GetClientMetrics(clientID)
	if err != nil {
		http.Error(w, `{"error": "failed to fetch metrics"}`, http.StatusInternalServerError)
		return
	}

	if clientMetrics == nil {
		http.Error(w, `{"error": "client not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(clientMetrics)
}

func getClientStatsHandler(w http.ResponseWriter, r *http.Request) {
	if metricsStore == nil {
		http.Error(w, `{"error": "metrics not initialized"}`, http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	clientID := vars["clientID"]
	if clientID == "" {
		clientID = r.URL.Query().Get("client_id")
	}

	if clientID == "" {
		http.Error(w, `{"error": "client_id is required"}`, http.StatusBadRequest)
		return
	}

	// Parse time range
	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")

	var from, to time.Time
	var err error

	if fromStr != "" {
		from, err = time.Parse("2006-01-02", fromStr)
		if err != nil {
			from, err = time.Parse(time.RFC3339, fromStr)
			if err != nil {
				http.Error(w, `{"error": "invalid from date format"}`, http.StatusBadRequest)
				return
			}
		}
	} else {
		from = time.Now().AddDate(0, 0, -30)
	}

	if toStr != "" {
		to, err = time.Parse("2006-01-02", toStr)
		if err != nil {
			to, err = time.Parse(time.RFC3339, toStr)
			if err != nil {
				http.Error(w, `{"error": "invalid to date format"}`, http.StatusBadRequest)
				return
			}
		}
	} else {
		to = time.Now()
	}

	stats, err := metricsStore.GetClientStats(clientID, from, to)
	if err != nil {
		http.Error(w, `{"error": "failed to fetch stats"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(stats)
}

func addUserHandler(w http.ResponseWriter, r *http.Request) {
	if metricsStore == nil {
		http.Error(w, `{"error": "metrics not initialized"}`, http.StatusServiceUnavailable)
		return
	}

	var req struct {
		ClientID string `json:"client_id"`
		UserID   string `json:"user_id"`
		Role     string `json:"role"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.ClientID == "" || req.UserID == "" {
		http.Error(w, `{"error": "client_id and user_id are required"}`, http.StatusBadRequest)
		return
	}

	if req.Role == "" {
		req.Role = "guest"
	}

	if err := metricsStore.AddUser(req.ClientID, req.UserID, req.Role); err != nil {
		http.Error(w, `{"error": "failed to add user"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "success",
		"client_id": req.ClientID,
		"user_id":   req.UserID,
		"role":      req.Role,
	})
}

func removeUserHandler(w http.ResponseWriter, r *http.Request) {
	if metricsStore == nil {
		http.Error(w, `{"error": "metrics not initialized"}`, http.StatusServiceUnavailable)
		return
	}

	var req struct {
		ClientID string `json:"client_id"`
		UserID   string `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.ClientID == "" || req.UserID == "" {
		http.Error(w, `{"error": "client_id and user_id are required"}`, http.StatusBadRequest)
		return
	}

	if err := metricsStore.RemoveUser(req.ClientID, req.UserID); err != nil {
		http.Error(w, `{"error": "failed to remove user"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "success",
		"client_id": req.ClientID,
		"user_id":   req.UserID,
	})
}

func recordUserLoginHandler(w http.ResponseWriter, r *http.Request) {
	if metricsStore == nil {
		http.Error(w, `{"error": "metrics not initialized"}`, http.StatusServiceUnavailable)
		return
	}

	var req struct {
		ClientID string `json:"client_id"`
		UserID   string `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.ClientID == "" || req.UserID == "" {
		http.Error(w, `{"error": "client_id and user_id are required"}`, http.StatusBadRequest)
		return
	}

	if err := metricsStore.RecordUserLogin(req.ClientID, req.UserID); err != nil {
		http.Error(w, `{"error": "failed to record login"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "success",
	})
}

// === ZERO-KNOWLEDGE KEY MANAGEMENT HANDLERS ===

// registerUserKeysHandler handles user registration with key wrapping
// POST /api/v1/keys/register
// Browser generates RSA keys, wraps private key with password, sends both to server
func registerUserKeysHandler(w http.ResponseWriter, r *http.Request) {
	if keyWrapStore == nil {
		http.Error(w, `{"error": "key management not initialized"}`, http.StatusServiceUnavailable)
		return
	}

	var req struct {
		ClientID            string `json:"client_id"`
		UserID              string `json:"user_id"`
		PublicKeyPEM        string `json:"public_key_pem"`
		EncryptedPrivateKey string `json:"encrypted_private_key"` // Already wrapped by browser
		Salt                string `json:"salt"`                  // Salt used for wrapping
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.ClientID == "" || req.UserID == "" || req.PublicKeyPEM == "" || req.EncryptedPrivateKey == "" || req.Salt == "" {
		http.Error(w, `{"error": "client_id, user_id, public_key_pem, encrypted_private_key, and salt are required"}`, http.StatusBadRequest)
		return
	}

	// Store the wrapped key (we never see the raw private key!)
	err := keyWrapStore.StoreWrappedKey(req.ClientID, req.UserID, req.PublicKeyPEM, req.EncryptedPrivateKey, req.Salt)
	if err != nil {
		log.Printf("❌ Failed to store wrapped key: %v", err)
		http.Error(w, `{"error": "failed to store keys"}`, http.StatusInternalServerError)
		return
	}

	log.Printf("🔐 Zero-Knowledge: Stored wrapped keys for user %s (client: %s)", req.UserID, req.ClientID)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":    "success",
		"message":   "Keys registered successfully. Private key is encrypted and can only be unlocked with your password.",
		"client_id": req.ClientID,
		"user_id":   req.UserID,
	})
}

// loginFetchKeysHandler retrieves the wrapped private key for client-side decryption
// POST /api/v1/keys/login
// Returns the encrypted private key - only the user's password can unlock it
func loginFetchKeysHandler(w http.ResponseWriter, r *http.Request) {
	if keyWrapStore == nil {
		http.Error(w, `{"error": "key management not initialized"}`, http.StatusServiceUnavailable)
		return
	}

	var req struct {
		ClientID string `json:"client_id"`
		UserID   string `json:"user_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "invalid request body"}`, http.StatusBadRequest)
		return
	}

	if req.ClientID == "" || req.UserID == "" {
		http.Error(w, `{"error": "client_id and user_id are required"}`, http.StatusBadRequest)
		return
	}

	// Fetch the wrapped key
	wrappedKey, err := keyWrapStore.GetWrappedKey(req.ClientID, req.UserID)
	if err != nil {
		log.Printf("❌ Failed to fetch wrapped key: %v", err)
		http.Error(w, `{"error": "failed to fetch keys"}`, http.StatusInternalServerError)
		return
	}

	if wrappedKey == nil {
		http.Error(w, `{"error": "user not found"}`, http.StatusNotFound)
		return
	}

	// Record login in metrics
	if metricsStore != nil {
		metricsStore.RecordUserLogin(req.ClientID, req.UserID)
	}

	log.Printf("🔓 Zero-Knowledge: Sent wrapped keys to user %s for client-side decryption", req.UserID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":                "success",
		"message":               "Decrypt the private key locally using your password",
		"public_key_pem":        wrappedKey.PublicKeyPEM,
		"encrypted_private_key": wrappedKey.EncryptedPrivKey,
		"salt":                  wrappedKey.Salt,
	})
}

// getPublicKeyHandler retrieves a user's public key (for encrypting data for them)
// GET /api/v1/keys/public/{clientID}/{userID}
func getPublicKeyHandler(w http.ResponseWriter, r *http.Request) {
	if keyWrapStore == nil {
		http.Error(w, `{"error": "key management not initialized"}`, http.StatusServiceUnavailable)
		return
	}

	vars := mux.Vars(r)
	clientID := vars["clientID"]
	userID := vars["userID"]

	if clientID == "" || userID == "" {
		http.Error(w, `{"error": "client_id and user_id are required"}`, http.StatusBadRequest)
		return
	}

	publicKey, err := keyWrapStore.GetPublicKey(clientID, userID)
	if err != nil {
		http.Error(w, `{"error": "user not found"}`, http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"client_id":      clientID,
		"user_id":        userID,
		"public_key_pem": publicKey,
	})
}
