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
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"wolfronixgo/internal/fakegen"
	"wolfronixgo/internal/keywrap"
	"wolfronixgo/internal/masking"
	"wolfronixgo/internal/metrics"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

// Chunk size for streaming (64KB - optimal for disk I/O)
const CHUNK_SIZE = 64 * 1024

// Storage directory for encrypted files
const ENCRYPTED_FILES_DIR = "/root/data/encrypted_files"

// --- GLOBALS ---
var (
	ServerPrivateKey *rsa.PrivateKey
	ServerPublicKey  *rsa.PublicKey
	db               *sql.DB
	metricsStore     *metrics.MetricsStore
	keyWrapStore     *keywrap.KeyWrapStore
	fakeGen          *fakegen.FakeDataGenerator
	// Streaming tokens for large file access (token -> decryption info)
	streamTokens     = make(map[string]*StreamToken)
	streamTokenMutex = &sync.Mutex{}
)

// StreamToken holds temporary decryption info for streaming
type StreamToken struct {
	FileID    int
	AESKey    []byte
	IV        []byte
	FilePath  string
	Filename  string
	FileSize  int64
	ClientID  string
	UserID    string
	ExpiresAt time.Time
}

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

		// Initialize fake data generator
		fakeGen = fakegen.NewFakeDataGenerator()
		log.Println("🎭 Fake Data Generator Initialized!")
	}
}

// initCoreTables creates the core database tables for Wolfronix v1.0
func initCoreTables() {
	// Create encrypted files directory
	if err := os.MkdirAll(ENCRYPTED_FILES_DIR, 0755); err != nil {
		log.Printf("⚠️ Failed to create encrypted files directory: %v", err)
	} else {
		log.Printf("📁 Encrypted files directory ready: %s", ENCRYPTED_FILES_DIR)
	}

	// Secure Storage (Production) table - now with file_path for chunked streaming
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS secure_storage (
			id SERIAL PRIMARY KEY,
			filename VARCHAR(255) NOT NULL,
			encrypted_data BYTEA,
			file_path VARCHAR(512),
			file_size BIGINT DEFAULT 0,
			key_part_a TEXT NOT NULL,
			key_part_b TEXT NOT NULL,
			iv VARCHAR(64) NOT NULL,
			enc_time_ms INT DEFAULT 0,
			client_id VARCHAR(255),
			user_id VARCHAR(255),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		log.Printf("⚠️ secure_storage table: %v", err)
	}

	// Add missing columns to secure_storage (for upgrades)
	db.Exec(`ALTER TABLE secure_storage ADD COLUMN IF NOT EXISTS client_id VARCHAR(255)`)
	db.Exec(`ALTER TABLE secure_storage ADD COLUMN IF NOT EXISTS user_id VARCHAR(255)`)
	db.Exec(`ALTER TABLE secure_storage ADD COLUMN IF NOT EXISTS file_path VARCHAR(512)`)
	db.Exec(`ALTER TABLE secure_storage ADD COLUMN IF NOT EXISTS file_size BIGINT DEFAULT 0`)
	// Remove NOT NULL constraint from encrypted_data for chunked storage
	db.Exec(`ALTER TABLE secure_storage ALTER COLUMN encrypted_data DROP NOT NULL`)

	// Dev Storage (Layer 1) table for fake data
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS dev_storage (
			id SERIAL PRIMARY KEY,
			prod_file_id INT,
			filename VARCHAR(255) NOT NULL,
			fake_data BYTEA NOT NULL,
			client_id VARCHAR(255),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		log.Printf("⚠️ dev_storage table: %v", err)
	}

	// Create indexes
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_secure_storage_client ON secure_storage(client_id)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_dev_storage_client ON dev_storage(client_id)`)

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

	// API Routes
	r.HandleFunc("/api/v1/keys", getKeysHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/encrypt", encryptHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/files", listFilesHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/files/{id}/decrypt", decryptStoredHandler).Methods("POST", "OPTIONS")
	// Streaming endpoints for large files
	r.HandleFunc("/api/v1/files/{id}/stream-token", createStreamTokenHandler).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/stream/{token}", streamFileHandler).Methods("GET", "OPTIONS")
	r.HandleFunc("/admin/clients", registerClientHandler).Methods("POST", "OPTIONS")

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
	// Start Server Timer
	start := time.Now()

	// Use small memory buffer, large files go to temp disk
	// maxMemory = 32MB in RAM, rest goes to temp files
	err := r.ParseMultipartForm(32 << 20)
	if err != nil {
		log.Printf("❌ Parse form error: %v", err)
		http.Error(w, "File too large or parse error", 400)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "File error", 400)
		return
	}
	defer file.Close()

	clientPubKey := r.FormValue("client_public_key")
	if clientPubKey == "" {
		http.Error(w, "Missing Public Key", 400)
		return
	}

	// Get client ID from header or form
	clientID := r.Header.Get("X-Client-ID")
	if clientID == "" {
		clientID = r.FormValue("client_id")
	}
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = r.FormValue("user_id")
	}

	// Check if this is for dev environment (Layer 1)
	isDevEnv := r.Header.Get("X-Environment") == "dev" || r.FormValue("environment") == "dev"

	// === LAYER 3: GENERATE AES-256 KEY & IV ===
	key := make([]byte, 32)
	rand.Read(key)
	iv := make([]byte, 16)
	rand.Read(iv)

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		http.Error(w, "Encryption init failed", 500)
		return
	}
	stream := cipher.NewCTR(block, iv)

	// Generate unique filename for encrypted file
	encryptedFileName := fmt.Sprintf("%d_%s.enc", time.Now().UnixNano(), header.Filename)
	encryptedFilePath := filepath.Join(ENCRYPTED_FILES_DIR, encryptedFileName)

	// Create encrypted file
	encFile, err := os.Create(encryptedFilePath)
	if err != nil {
		log.Printf("❌ Failed to create encrypted file: %v", err)
		http.Error(w, "Storage error", 500)
		return
	}
	defer encFile.Close()

	// === CHUNKED STREAMING ENCRYPTION ===
	// Read input in chunks, encrypt, write to output file
	var totalSize int64 = 0
	buffer := make([]byte, CHUNK_SIZE)
	encBuffer := make([]byte, CHUNK_SIZE)
	writer := bufio.NewWriter(encFile)

	for {
		n, err := file.Read(buffer)
		if n > 0 {
			// Encrypt chunk in-place
			stream.XORKeyStream(encBuffer[:n], buffer[:n])
			// Write encrypted chunk
			_, writeErr := writer.Write(encBuffer[:n])
			if writeErr != nil {
				os.Remove(encryptedFilePath)
				http.Error(w, "Write error", 500)
				return
			}
			totalSize += int64(n)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			os.Remove(encryptedFilePath)
			http.Error(w, "Read error", 500)
			return
		}
	}
	writer.Flush()

	log.Printf("📦 Encrypted %d bytes in chunks → %s", totalSize, encryptedFilePath)

	// === LAYER 1: STATIC MASKING (For Dev Environment) ===
	if isDevEnv && fakeGen != nil {
		fakeData := fakeGen.FakeFileContentWithMarker(int(totalSize), header.Filename)
		log.Printf("🎭 Layer 1: Generated fake data for dev environment (%d bytes)", len(fakeData))
		// Store fake data separately (not the actual encrypted data)
		if db != nil {
			db.Exec(`INSERT INTO dev_storage (prod_file_id, filename, fake_data, client_id, created_at) VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)`,
				0, "FAKE_"+header.Filename, fakeData, clientID)
		}
	}

	// === LAYER 4: DUAL KEY SPLIT ===
	// Share A: Encrypted with USER's public key (only user can unlock)
	encA := encryptRSA(key[:16], clientPubKey)
	if encA == "" {
		os.Remove(encryptedFilePath)
		http.Error(w, "Invalid Client Key", 400)
		return
	}
	// Share B: Encrypted with SERVER's public key (only server can unlock)
	encB := encryptRSA(key[16:], publicKeyToPEM(ServerPublicKey))

	// Calculate Duration
	duration := time.Since(start).Milliseconds()

	// Save metadata to DB (file content is on disk, not in DB)
	var prodFileID int64
	if db != nil {
		err := db.QueryRow(`INSERT INTO secure_storage (filename, file_path, file_size, key_part_a, key_part_b, iv, enc_time_ms, client_id, user_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
			header.Filename, encryptedFilePath, totalSize, encA, encB, base64.StdEncoding.EncodeToString(iv), duration, clientID, userID).Scan(&prodFileID)

		if err != nil {
			log.Println("❌ DB Write Error:", err)
			os.Remove(encryptedFilePath)
			if metricsStore != nil && clientID != "" {
				metricsStore.RecordError(clientID, userID, "encrypt", err.Error())
			}
			http.Error(w, "Database Error", 500)
			return
		}

		// Update dev_storage with prod_file_id if dev mode
		if isDevEnv {
			db.Exec(`UPDATE dev_storage SET prod_file_id = $1 WHERE filename = $2 AND client_id = $3`,
				prodFileID, "FAKE_"+header.Filename, clientID)
		}
	}

	// Record encryption metrics
	if metricsStore != nil && clientID != "" {
		metricsStore.RecordEncryption(clientID, userID, duration, 1, totalSize)
	}

	log.Printf("✅ File encrypted: %s (%d bytes) in %dms [Chunked Streaming]", header.Filename, totalSize, duration)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":      "success",
		"enc_time_ms": duration,
		"file_size":   totalSize,
		"method":      "chunked_streaming",
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
	if db == nil {
		http.Error(w, "DB Down", 503)
		return
	}

	// Get user_id from header or query param for filtering
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = r.URL.Query().Get("user_id")
	}

	// Require user_id for file listing (user isolation)
	if userID == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]interface{}{})
		return
	}

	// Fetch files filtered by user_id
	rows, err := db.Query(`
		SELECT id, filename, created_at, 
			COALESCE(file_size, OCTET_LENGTH(encrypted_data), 0) as size,
			enc_time_ms,
			CASE WHEN file_path IS NOT NULL AND file_path != '' THEN 'chunked' ELSE 'legacy' END as storage_type
		FROM secure_storage 
		WHERE user_id = $1
		ORDER BY id DESC
	`, userID)
	if err != nil {
		json.NewEncoder(w).Encode([]string{})
		return
	}
	defer rows.Close()

	var files []map[string]interface{}
	for rows.Next() {
		var id int
		var size int64
		var encTime int
		var name, storageType string
		var date time.Time

		rows.Scan(&id, &name, &date, &size, &encTime, &storageType)

		files = append(files, map[string]interface{}{
			"id":           id,
			"name":         name,
			"date":         date.Format("2006-01-02 15:04"),
			"size":         fmt.Sprintf("%.2f MB", float64(size)/1024/1024),
			"size_bytes":   size,
			"enc_time":     fmt.Sprintf("%d ms", encTime),
			"storage_type": storageType,
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(files)
}

func decryptStoredHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	vars := mux.Vars(r)
	id, _ := strconv.Atoi(vars["id"])

	// === SECURE HEADER: Get private key from header (preferred) or form ===
	privKeyStr := r.Header.Get("X-Private-Key")
	if privKeyStr == "" {
		privKeyStr = r.FormValue("client_private_key")
	}

	// Get client ID from header or form
	clientID := r.Header.Get("X-Client-ID")
	if clientID == "" {
		clientID = r.FormValue("client_id")
	}
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = r.FormValue("user_id")
	}

	// Get user role for Layer 2 RBAC masking
	userRole := r.Header.Get("X-User-Role")
	if userRole == "" {
		userRole = r.FormValue("user_role")
	}
	if userRole == "" {
		userRole = "guest" // Default to most restrictive
	}

	var name, encA, encB, ivStr string
	var filePath sql.NullString
	var fileSize sql.NullInt64
	var encData []byte
	var fileOwner sql.NullString

	// Retrieve metadata with ownership check
	err := db.QueryRow("SELECT filename, file_path, file_size, encrypted_data, key_part_a, key_part_b, iv, user_id FROM secure_storage WHERE id=$1", id).
		Scan(&name, &filePath, &fileSize, &encData, &encA, &encB, &ivStr, &fileOwner)

	if err != nil {
		if metricsStore != nil && clientID != "" {
			metricsStore.RecordError(clientID, userID, "decrypt", "File not found")
		}
		http.Error(w, "File Not Found", 404)
		return
	}

	// Verify file ownership - user can only decrypt their own files
	if fileOwner.Valid && fileOwner.String != "" && userID != "" && fileOwner.String != userID {
		if metricsStore != nil && clientID != "" {
			metricsStore.RecordError(clientID, userID, "decrypt", "Access denied - not file owner")
		}
		http.Error(w, "Access Denied", 403)
		return
	}

	// === LAYER 4: UNLOCK DUAL KEYS ===
	// Unlock Share A using USER's private key (sent from browser)
	keyA := decryptRSA(encA, privKeyStr)
	// Unlock Share B using SERVER's private key (held securely)
	keyB := decryptRSA(encB, privateKeyToPEM(ServerPrivateKey))

	if keyA == nil || keyB == nil {
		if metricsStore != nil && clientID != "" {
			metricsStore.RecordError(clientID, userID, "decrypt", "Key mismatch")
		}
		http.Error(w, "Decryption Failed (Key Mismatch)", 403)
		return
	}

	// === LAYER 3: AES DECRYPTION ===
	fullKey := append(keyA, keyB...)
	iv, _ := base64.StdEncoding.DecodeString(ivStr)
	block, _ := aes.NewCipher(fullKey)
	stream := cipher.NewCTR(block, iv)

	// Set response headers
	w.Header().Set("Content-Disposition", "attachment; filename="+name)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Masking-Applied", userRole)

	// Check if using file-based storage (chunked) or legacy BYTEA storage
	if filePath.Valid && filePath.String != "" {
		// === CHUNKED STREAMING DECRYPTION ===
		encFile, err := os.Open(filePath.String)
		if err != nil {
			log.Printf("❌ Failed to open encrypted file: %v", err)
			http.Error(w, "File read error", 500)
			return
		}
		defer encFile.Close()

		// Stream decrypt in chunks
		buffer := make([]byte, CHUNK_SIZE)
		decBuffer := make([]byte, CHUNK_SIZE)
		var totalDecrypted int64 = 0

		// Check if text file for RBAC masking (for small text files only)
		isTextFile := strings.HasPrefix(http.DetectContentType([]byte(name)), "text/") ||
			strings.HasSuffix(strings.ToLower(name), ".txt") ||
			strings.HasSuffix(strings.ToLower(name), ".csv") ||
			strings.HasSuffix(strings.ToLower(name), ".json")

		// For large files or non-text, stream directly
		if !isTextFile || (fileSize.Valid && fileSize.Int64 > 10*1024*1024) {
			// Direct streaming for binary/large files
			for {
				n, err := encFile.Read(buffer)
				if n > 0 {
					stream.XORKeyStream(decBuffer[:n], buffer[:n])
					w.Write(decBuffer[:n])
					totalDecrypted += int64(n)
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					log.Printf("❌ Stream read error: %v", err)
					break
				}
			}
		} else {
			// For small text files, buffer for RBAC masking
			var decData []byte
			for {
				n, err := encFile.Read(buffer)
				if n > 0 {
					stream.XORKeyStream(decBuffer[:n], buffer[:n])
					decData = append(decData, decBuffer[:n]...)
					totalDecrypted += int64(n)
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					break
				}
			}
			// Apply RBAC masking
			maskedContent := masking.MaskAllSensitiveInText(string(decData), masking.Role(userRole))
			w.Write([]byte(maskedContent))
			log.Printf("🔒 Layer 2: Applied RBAC masking for role '%s' on file '%s'", userRole, name)
		}

		log.Printf("✅ Decrypted %d bytes via chunked streaming: %s", totalDecrypted, name)

		// Record metrics
		duration := time.Since(start).Milliseconds()
		if metricsStore != nil && clientID != "" {
			metricsStore.RecordDecryption(clientID, userID, duration, 1, totalDecrypted)
		}

	} else {
		// === LEGACY: In-memory decryption for old BYTEA-stored files ===
		decData := make([]byte, len(encData))
		stream.XORKeyStream(decData, encData)

		// === LAYER 2: DYNAMIC RBAC MASKING ===
		contentType := http.DetectContentType(decData)
		if strings.HasPrefix(contentType, "text/") || strings.Contains(name, ".txt") ||
			strings.Contains(name, ".csv") || strings.Contains(name, ".json") {
			maskedContent := masking.MaskAllSensitiveInText(string(decData), masking.Role(userRole))
			decData = []byte(maskedContent)
			log.Printf("🔒 Layer 2: Applied RBAC masking for role '%s' on file '%s'", userRole, name)
		}

		// Record decryption metrics
		duration := time.Since(start).Milliseconds()
		if metricsStore != nil && clientID != "" {
			metricsStore.RecordDecryption(clientID, userID, duration, 1, int64(len(decData)))
		}

		w.Write(decData)
	}
}

// === STREAMING HANDLERS FOR LARGE FILES ===

// createStreamTokenHandler - Creates a temporary token for streaming large files
func createStreamTokenHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, _ := strconv.Atoi(vars["id"])

	privKeyStr := r.FormValue("client_private_key")
	if privKeyStr == "" {
		http.Error(w, "Missing private key", 400)
		return
	}

	// Get client ID and user ID for metrics tracking
	clientID := r.Header.Get("X-Client-ID")
	if clientID == "" {
		clientID = r.FormValue("client_id")
	}
	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = r.FormValue("user_id")
	}

	// Get file metadata with ownership check
	var name, encA, encB, ivStr string
	var filePath sql.NullString
	var fileSize sql.NullInt64
	var fileOwner sql.NullString

	err := db.QueryRow("SELECT filename, file_path, file_size, key_part_a, key_part_b, iv, user_id FROM secure_storage WHERE id=$1", id).
		Scan(&name, &filePath, &fileSize, &encA, &encB, &ivStr, &fileOwner)

	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}

	// Verify file ownership - user can only stream their own files
	if fileOwner.Valid && fileOwner.String != "" && userID != "" && fileOwner.String != userID {
		http.Error(w, "Access Denied", 403)
		return
	}

	// Verify keys and decrypt AES key
	keyA := decryptRSA(encA, privKeyStr)
	keyB := decryptRSA(encB, privateKeyToPEM(ServerPrivateKey))

	if keyA == nil || keyB == nil {
		http.Error(w, "Key verification failed", 403)
		return
	}

	fullKey := append(keyA, keyB...)
	iv, _ := base64.StdEncoding.DecodeString(ivStr)

	// Generate token
	tokenBytes := make([]byte, 32)
	rand.Read(tokenBytes)
	token := hex.EncodeToString(tokenBytes)

	// Store token with expiration (5 minutes)
	streamTokenMutex.Lock()
	streamTokens[token] = &StreamToken{
		FileID:    id,
		AESKey:    fullKey,
		IV:        iv,
		FilePath:  filePath.String,
		Filename:  name,
		FileSize:  fileSize.Int64,
		ClientID:  clientID,
		UserID:    userID,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}
	streamTokenMutex.Unlock()

	// Clean up expired tokens periodically
	go cleanupExpiredTokens()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"token":     token,
		"filename":  name,
		"file_size": fileSize.Int64,
		"expires":   300, // seconds
	})
	log.Printf("🎫 Created stream token for file %d (%s)", id, name)
}

// streamFileHandler - Streams decrypted file using token (GET request, no auth needed)
func streamFileHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	vars := mux.Vars(r)
	token := vars["token"]

	// Get token info
	streamTokenMutex.Lock()
	tokenInfo, exists := streamTokens[token]
	streamTokenMutex.Unlock()

	if !exists || time.Now().After(tokenInfo.ExpiresAt) {
		http.Error(w, "Invalid or expired token", 403)
		return
	}

	// Open encrypted file
	encFile, err := os.Open(tokenInfo.FilePath)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	defer encFile.Close()

	// Get file info for Content-Length
	fileInfo, _ := encFile.Stat()
	fileSize := fileInfo.Size()

	// Set headers for streaming
	ext := strings.ToLower(filepath.Ext(tokenInfo.Filename))
	contentType := getMimeTypeGo(ext)

	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Length", strconv.FormatInt(fileSize, 10))
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Disposition", "inline; filename="+tokenInfo.Filename)

	var bytesStreamed int64 = 0

	// Handle Range requests for video seeking
	rangeHeader := r.Header.Get("Range")
	if rangeHeader != "" {
		// Parse range header: "bytes=start-end"
		var rangeStart, rangeEnd int64
		fmt.Sscanf(rangeHeader, "bytes=%d-%d", &rangeStart, &rangeEnd)
		if rangeEnd == 0 || rangeEnd >= fileSize {
			rangeEnd = fileSize - 1
		}

		// Seek to position (note: we need to decrypt from start due to CTR mode)
		// For simplicity, we'll stream from start but seek in output
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", rangeStart, rangeEnd, fileSize))
		w.Header().Set("Content-Length", strconv.FormatInt(rangeEnd-rangeStart+1, 10))
		w.WriteHeader(http.StatusPartialContent)

		// Stream with range support
		bytesStreamed = streamDecryptedRange(w, encFile, tokenInfo.AESKey, tokenInfo.IV, rangeStart, rangeEnd)
	} else {
		// Full file streaming
		block, _ := aes.NewCipher(tokenInfo.AESKey)
		stream := cipher.NewCTR(block, tokenInfo.IV)

		buffer := make([]byte, CHUNK_SIZE)
		decBuffer := make([]byte, CHUNK_SIZE)

		for {
			n, err := encFile.Read(buffer)
			if n > 0 {
				stream.XORKeyStream(decBuffer[:n], buffer[:n])
				w.Write(decBuffer[:n])
				bytesStreamed += int64(n)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				log.Printf("Stream error: %v", err)
				break
			}
		}
	}

	// Record decryption metrics for streaming
	duration := time.Since(start).Milliseconds()
	if metricsStore != nil && tokenInfo.ClientID != "" {
		metricsStore.RecordDecryption(tokenInfo.ClientID, tokenInfo.UserID, duration, 1, bytesStreamed)
		log.Printf("📊 Recorded stream decryption metrics: %d bytes in %dms", bytesStreamed, duration)
	}

	log.Printf("📺 Streamed file: %s (%d bytes)", tokenInfo.Filename, bytesStreamed)
}

// streamDecryptedRange streams a specific byte range of the decrypted file
// Returns the number of bytes written
func streamDecryptedRange(w http.ResponseWriter, encFile *os.File, aesKey, iv []byte, start, end int64) int64 {
	block, _ := aes.NewCipher(aesKey)
	stream := cipher.NewCTR(block, iv)

	buffer := make([]byte, CHUNK_SIZE)
	decBuffer := make([]byte, CHUNK_SIZE)
	var position int64 = 0
	var bytesWritten int64 = 0

	for {
		n, err := encFile.Read(buffer)
		if n > 0 {
			stream.XORKeyStream(decBuffer[:n], buffer[:n])

			// Calculate what portion of this chunk to write
			chunkEnd := position + int64(n)

			if chunkEnd > start && position <= end {
				// Calculate slice boundaries
				writeStart := int64(0)
				writeEnd := int64(n)

				if position < start {
					writeStart = start - position
				}
				if chunkEnd > end+1 {
					writeEnd = end + 1 - position
				}

				written, _ := w.Write(decBuffer[writeStart:writeEnd])
				bytesWritten += int64(written)
				if f, ok := w.(http.Flusher); ok {
					f.Flush()
				}
			}

			position = chunkEnd
			if position > end {
				break
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
	}
	return bytesWritten
}

func cleanupExpiredTokens() {
	streamTokenMutex.Lock()
	defer streamTokenMutex.Unlock()

	now := time.Now()
	for token, info := range streamTokens {
		if now.After(info.ExpiresAt) {
			delete(streamTokens, token)
		}
	}
}

func getMimeTypeGo(ext string) string {
	mimeTypes := map[string]string{
		".mp4":  "video/mp4",
		".webm": "video/webm",
		".mov":  "video/quicktime",
		".avi":  "video/x-msvideo",
		".mkv":  "video/x-matroska",
		".mp3":  "audio/mpeg",
		".wav":  "audio/wav",
		".ogg":  "audio/ogg",
		".jpg":  "image/jpeg",
		".jpeg": "image/jpeg",
		".png":  "image/png",
		".gif":  "image/gif",
		".webp": "image/webp",
		".pdf":  "application/pdf",
		".txt":  "text/plain",
		".json": "application/json",
	}
	if mime, ok := mimeTypes[ext]; ok {
		return mime
	}
	return "application/octet-stream"
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
