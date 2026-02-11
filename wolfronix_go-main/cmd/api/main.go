package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"wolfronixgo/internal/clientdb"
	"wolfronixgo/internal/fakegen"
	"wolfronixgo/internal/keywrap"
	"wolfronixgo/internal/masking"
	"wolfronixgo/internal/metrics"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

// Chunk size for streaming (64KB - optimal for disk I/O)
const CHUNK_SIZE = 64 * 1024

// --- GLOBALS ---
var (
	ServerPrivateKey *rsa.PrivateKey
	ServerPublicKey  *rsa.PublicKey
	db               *sql.DB
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

	// 2. Connect DB
	initDB()

	// 3. Router
	r := mux.NewRouter()
	r.Use(corsMiddleware)

	// Health check endpoint
	r.HandleFunc("/health", healthCheckHandler).Methods("GET", "OPTIONS")

	// API Routes
	r.HandleFunc("/api/v1/keys", getKeysHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/encrypt", encryptHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/files", listFilesHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/files/{id}/decrypt", decryptStoredHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/files/{id}", deleteStoredFileHandler).Methods("DELETE", "OPTIONS")
	r.HandleFunc("/admin/clients", registerClientHandler).Methods("POST", "OPTIONS")

	// === ENTERPRISE CLIENT REGISTRATION ===
	// Register a new client with their API endpoint (Enterprise mode)
	r.HandleFunc("/api/v1/enterprise/register", registerEnterpriseClientHandler).Methods("POST", "OPTIONS")
	// List registered clients
	r.HandleFunc("/api/v1/enterprise/clients", listEnterpriseClientsHandler).Methods("GET", "OPTIONS")
	// Get client info
	r.HandleFunc("/api/v1/enterprise/clients/{clientID}", getEnterpriseClientHandler).Methods("GET", "OPTIONS")
	// Update client endpoint
	r.HandleFunc("/api/v1/enterprise/clients/{clientID}", updateEnterpriseClientHandler).Methods("PUT", "OPTIONS")

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

	port := ":5001"
	log.Printf("🚀 Wolfronix Cloud Engine Running on %s (HTTPS)", port)

	// 4. Start Server (HTTPS)
	err := http.ListenAndServeTLS(port, "server.crt", "server.key", r)
	if err != nil {
		log.Fatal("❌ Server Start Error: ", err)
	}
}

// --- HANDLERS ---

func encryptHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	err := r.ParseMultipartForm(32 << 20)
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

	// Get client ID - REQUIRED in enterprise mode
	clientID := r.Header.Get("X-Client-ID")
	if clientID == "" {
		clientID = r.FormValue("client_id")
	}
	if clientID == "" {
		http.Error(w, `{"error": "X-Client-ID header is required"}`, 400)
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

	// === LAYER 3: GENERATE AES-256 KEY & IV ===
	key := make([]byte, 32)
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)

	block, err := aes.NewCipher(key)
	if err != nil {
		http.Error(w, `{"error": "Encryption init failed"}`, 500)
		return
	}
	stream := cipher.NewCTR(block, iv)

	// Create temp file for encryption
	tmpFile, err := os.CreateTemp("", "wolfronix-enc-*")
	if err != nil {
		log.Printf("❌ Failed to create temp file: %v", err)
		http.Error(w, `{"error": "Temp file creation failed"}`, 500)
		return
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	// === CHUNKED STREAMING ENCRYPTION ===
	var totalSize int64 = 0
	buffer := make([]byte, CHUNK_SIZE)
	encBuffer := make([]byte, CHUNK_SIZE)
	writer := bufio.NewWriter(tmpFile)

	for {
		n, err := file.Read(buffer)
		if n > 0 {
			stream.XORKeyStream(encBuffer[:n], buffer[:n])
			_, writeErr := writer.Write(encBuffer[:n])
			if writeErr != nil {
				tmpFile.Close()
				http.Error(w, `{"error": "Write error"}`, 500)
				return
			}
			totalSize += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			tmpFile.Close()
			http.Error(w, `{"error": "Read error"}`, 500)
			return
		}
	}
	writer.Flush()
	tmpFile.Close()

	log.Printf("📦 Encrypted %d bytes in chunks", totalSize)

	// === LAYER 4: DUAL KEY SPLIT ===
	encA := encryptRSA(key[:16], clientPubKey)
	if encA == "" {
		http.Error(w, `{"error": "Invalid Client Key"}`, 400)
		return
	}
	encB := encryptRSA(key[16:], publicKeyToPEM(ServerPublicKey))

	duration := time.Since(start).Milliseconds()

	// Read encrypted data for upload to client API
	encryptedData, err := os.ReadFile(tmpPath)
	if err != nil {
		log.Printf("❌ Failed to read temp encrypted file: %v", err)
		http.Error(w, `{"error": "Failed to read encrypted data"}`, 500)
		return
	}

	// Create file metadata
	fileMetadata := &clientdb.StoredFile{
		Filename:    header.Filename,
		FileSize:    totalSize,
		KeyPartA:    encA,
		KeyPartB:    encB,
		IV:          base64.StdEncoding.EncodeToString(iv),
		EncTimeMS:   duration,
		ClientID:    clientID,
		UserID:      userID,
		StorageType: "blob",
	}

	// Send to client's API
	fileID, err := clientDBConn.StoreFileWithData(config, fileMetadata, encryptedData)
	if err != nil {
		log.Printf("❌ Failed to store in Client DB: %v", err)
		if metricsStore != nil {
			metricsStore.RecordError(clientID, userID, "encrypt", "Client API error: "+err.Error())
		}
		http.Error(w, `{"error": "Failed to store in client database"}`, 500)
		return
	}

	log.Printf("📤 Data sent to Client DB (ID: %d)", fileID)

	// Layer 1: Store fake data in client's dev DB if dev mode
	if isDevEnv && fakeGen != nil {
		fakeData := fakeGen.FakeFileContentWithMarker(int(totalSize), header.Filename)
		clientDBConn.StoreFakeData(config, fileID, "FAKE_"+header.Filename, fakeData)
		log.Printf("🎭 Layer 1: Fake data sent to Client Dev DB (%d bytes)", len(fakeData))
	}

	// Record encryption metrics
	if metricsStore != nil {
		metricsStore.RecordEncryption(clientID, userID, duration, 1, totalSize)
	}

	log.Printf("✅ File encrypted: %s (%d bytes) in %dms [enterprise]", header.Filename, totalSize, duration)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "success",
		"enc_time_ms": duration,
		"file_size":   totalSize,
		"file_id":     fileID,
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

	// 5. Encrypt
	out, err := rsa.EncryptPKCS1v15(rand.Reader, pub, data)
	if err != nil {
		log.Println("❌ RSA Encryption Failed:", err)
		return ""
	}

	return base64.StdEncoding.EncodeToString(out)
}

func listFilesHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.Header.Get("X-Client-ID")
	if clientID == "" {
		clientID = r.URL.Query().Get("client_id")
	}
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = r.URL.Query().Get("user_id")
	}

	if clientID == "" {
		http.Error(w, `{"error": "X-Client-ID is required"}`, 400)
		return
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
	id, _ := strconv.Atoi(vars["id"])

	privKeyStr := r.Header.Get("X-Private-Key")
	if privKeyStr == "" {
		privKeyStr = r.FormValue("client_private_key")
	}

	// Get client ID - REQUIRED in enterprise mode
	clientID := r.Header.Get("X-Client-ID")
	if clientID == "" {
		clientID = r.FormValue("client_id")
	}
	if clientID == "" {
		http.Error(w, `{"error": "X-Client-ID is required"}`, 400)
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = r.FormValue("user_id")
	}

	userRole := r.Header.Get("X-User-Role")
	if userRole == "" {
		userRole = r.FormValue("user_role")
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
	fileMeta, err := clientDBConn.GetFileMetadata(config, int64(id), userID)
	if err != nil {
		if metricsStore != nil {
			metricsStore.RecordError(clientID, userID, "decrypt", "File not found: "+err.Error())
		}
		http.Error(w, `{"error": "File not found"}`, 404)
		return
	}

	// Fetch encrypted data from client's API
	encData, err := clientDBConn.GetFileData(config, int64(id), userID)
	if err != nil {
		if metricsStore != nil {
			metricsStore.RecordError(clientID, userID, "decrypt", "Failed to fetch data: "+err.Error())
		}
		http.Error(w, `{"error": "Failed to fetch encrypted data"}`, 500)
		return
	}

	// === LAYER 4: UNLOCK DUAL KEYS ===
	keyA := decryptRSA(fileMeta.KeyPartA, privKeyStr)
	keyB := decryptRSA(fileMeta.KeyPartB, privateKeyToPEM(ServerPrivateKey))

	if keyA == nil || keyB == nil {
		if metricsStore != nil {
			metricsStore.RecordError(clientID, userID, "decrypt", "Key mismatch")
		}
		http.Error(w, `{"error": "Decryption Failed (Key Mismatch)"}`, 403)
		return
	}

	// === LAYER 3: AES DECRYPTION ===
	fullKey := append(keyA, keyB...)
	iv, _ := base64.StdEncoding.DecodeString(fileMeta.IV)
	block, _ := aes.NewCipher(fullKey)
	stream := cipher.NewCTR(block, iv)

	decData := make([]byte, len(encData))
	stream.XORKeyStream(decData, encData)

	// === LAYER 2: DYNAMIC RBAC MASKING ===
	contentType := http.DetectContentType(decData)
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
	if metricsStore != nil {
		metricsStore.RecordDecryption(clientID, userID, duration, 1, int64(len(decData)))
	}

	// Set response headers
	w.Header().Set("Content-Disposition", "attachment; filename="+fileMeta.Filename)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Masking-Applied", userRole)
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

	clientID := r.Header.Get("X-Client-ID")
	if clientID == "" {
		clientID = r.URL.Query().Get("client_id")
	}
	if clientID == "" {
		http.Error(w, `{"error": "X-Client-ID is required"}`, 400)
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

	err = clientDBConn.DeleteFile(config, int64(id), userID)
	if err != nil {
		log.Printf("⚠️ Failed to delete file %d: %v", id, err)
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

// --- UTILS ---

func getKeysHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"public_key": publicKeyToPEM(ServerPublicKey)})
}

func registerClientHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	hash := sha256.Sum256([]byte(req.Name + time.Now().String()))
	json.NewEncoder(w).Encode(map[string]string{"api_key": hex.EncodeToString(hash[:])})
}

// === ENTERPRISE CLIENT MANAGEMENT ===

// registerEnterpriseClientHandler registers a client with their API endpoint
func registerEnterpriseClientHandler(w http.ResponseWriter, r *http.Request) {
	if clientRegistry == nil {
		http.Error(w, "Client registry not initialized", 503)
		return
	}

	var req struct {
		ClientID    string `json:"client_id"`
		ClientName  string `json:"client_name"`
		APIEndpoint string `json:"api_endpoint"` // Client's storage API URL
		APIKey      string `json:"api_key"`      // Key to call client's API
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", 400)
		return
	}

	if req.ClientID == "" || req.ClientName == "" || req.APIEndpoint == "" {
		http.Error(w, "client_id, client_name, and api_endpoint are required", 400)
		return
	}

	// Generate Wolfronix API key for this client
	hash := sha256.Sum256([]byte(req.ClientID + req.ClientName + time.Now().String()))
	wolfronixKey := hex.EncodeToString(hash[:])

	client := &clientdb.RegisteredClient{
		ClientID:     req.ClientID,
		ClientName:   req.ClientName,
		APIEndpoint:  req.APIEndpoint,
		APIKey:       req.APIKey,
		WolfronixKey: wolfronixKey,
	}

	if err := clientRegistry.RegisterClient(client); err != nil {
		log.Printf("❌ Failed to register client: %v", err)
		http.Error(w, "Failed to register client", 500)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        "success",
		"client_id":     client.ClientID,
		"wolfronix_key": wolfronixKey,
		"message":       "Client registered. Use wolfronix_key for API calls.",
	})
	log.Printf("✅ Enterprise client registered: %s → %s", client.ClientID, client.APIEndpoint)
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
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", 400)
		return
	}

	if req.APIEndpoint != "" {
		if err := clientRegistry.UpdateClientEndpoint(clientID, req.APIEndpoint); err != nil {
			http.Error(w, "Failed to update client", 500)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "success",
		"message": "Client updated",
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
		ServerPrivateKey, _ = rsa.GenerateKey(rand.Reader, 2048)

		// Save Private Key
		keyOut, _ := os.Create("server.key")
		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(ServerPrivateKey)})
		keyOut.Close()

		// Generate Cert
		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{Organization: []string{"Wolfronix Secure"}},
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		}
		derBytes, _ := x509.CreateCertificate(rand.Reader, &template, &template, &ServerPrivateKey.PublicKey, ServerPrivateKey)

		// Save Cert
		certOut, _ := os.Create("server.crt")
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

	out, _ := rsa.DecryptPKCS1v15(rand.Reader, priv, data)
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
		"version":   "1.0.0",
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Access-Control-Expose-Headers", "Content-Disposition, X-Masking-Applied")
		if r.Method == "OPTIONS" {
			return
		}
		next.ServeHTTP(w, r)
	})
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
