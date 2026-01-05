package main

import (
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
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	_ "github.com/lib/pq"
)

// --- GLOBALS ---
var (
	ServerPrivateKey *rsa.PrivateKey
	ServerPublicKey  *rsa.PublicKey
	db               *sql.DB
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
	r.HandleFunc("/admin/clients", registerClientHandler).Methods("POST", "OPTIONS")

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

    r.ParseMultipartForm(500 << 20)
    file, header, err := r.FormFile("file")
    if err != nil { http.Error(w, "File error", 400); return }
    defer file.Close()

    clientPubKey := r.FormValue("client_public_key")
    if clientPubKey == "" { http.Error(w, "Missing Public Key", 400); return }

    data, _ := ioutil.ReadAll(file)
    
    // AES Encryption
    key := make([]byte, 32); rand.Read(key)
    iv := make([]byte, 16); rand.Read(iv)
    block, _ := aes.NewCipher(key)
    stream := cipher.NewCTR(block, iv)
    encData := make([]byte, len(data))
    stream.XORKeyStream(encData, data)

    // RSA Encryption
    encA := encryptRSA(key[:16], clientPubKey)
    if encA == "" { http.Error(w, "Invalid Client Key", 400); return }
    encB := encryptRSA(key[16:], publicKeyToPEM(ServerPublicKey))

    // Calculate Duration
    duration := time.Since(start).Milliseconds()

    // Save to DB (Including Time!)
    if db != nil {
        _, err := db.Exec(`INSERT INTO secure_storage (filename, encrypted_data, key_part_a, key_part_b, iv, enc_time_ms) VALUES ($1, $2, $3, $4, $5, $6)`,
            header.Filename, encData, encA, encB, base64.StdEncoding.EncodeToString(iv), duration)
        
        if err != nil {
            log.Println("❌ DB Write Error:", err)
            http.Error(w, "Database Error", 500); return
        }
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "status": "success", 
        "enc_time_ms": duration,
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
    if db == nil { http.Error(w, "DB Down", 503); return }

    // Fetch enc_time_ms too
    rows, err := db.Query("SELECT id, filename, created_at, OCTET_LENGTH(encrypted_data), enc_time_ms FROM secure_storage ORDER BY id DESC")
    if err != nil { json.NewEncoder(w).Encode([]string{}); return }
    defer rows.Close()

    var files []map[string]interface{}
    for rows.Next() {
        var id, size, encTime int
        var name string
        var date time.Time
        
        // Scan new column
        rows.Scan(&id, &name, &date, &size, &encTime)
        
        files = append(files, map[string]interface{}{
            "id": id, 
            "name": name, 
            "date": date.Format("2006-01-02 15:04"),
            "size": fmt.Sprintf("%.2f MB", float64(size)/1024/1024),
            "enc_time": fmt.Sprintf("%d ms", encTime), // Format for JSON
        })
    }
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(files)
}

func decryptStoredHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id, _ := strconv.Atoi(vars["id"])
	privKeyStr := r.FormValue("client_private_key")

	var name, encA, encB, ivStr string
	var encData []byte
	// Retrieve
	err := db.QueryRow("SELECT filename, encrypted_data, key_part_a, key_part_b, iv FROM secure_storage WHERE id=$1", id).
		Scan(&name, &encData, &encA, &encB, &ivStr)
	
	if err != nil { http.Error(w, "File Not Found", 404); return }

	// Decrypt Keys
	keyA := decryptRSA(encA, privKeyStr)
	keyB := decryptRSA(encB, privateKeyToPEM(ServerPrivateKey))
	
	if keyA == nil || keyB == nil { 
		http.Error(w, "Decryption Failed (Key Mismatch)", 403)
		return 
	}

	// Decrypt Data
	fullKey := append(keyA, keyB...)
	iv, _ := base64.StdEncoding.DecodeString(ivStr)
	block, _ := aes.NewCipher(fullKey)
	stream := cipher.NewCTR(block, iv)
	decData := make([]byte, len(encData))
	stream.XORKeyStream(decData, encData)

	w.Header().Set("Content-Disposition", "attachment; filename="+name)
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(decData)
}

// --- UTILS ---

func getKeysHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"public_key": publicKeyToPEM(ServerPublicKey)})
}

func registerClientHandler(w http.ResponseWriter, r *http.Request) {
	var req struct { Name string `json:"name"` }
	json.NewDecoder(r.Body).Decode(&req)
	hash := sha256.Sum256([]byte(req.Name + time.Now().String()))
	json.NewEncoder(w).Encode(map[string]string{"api_key": hex.EncodeToString(hash[:])})
}

func loadOrGenerateKeys() {
	// Try loading existing key
	privBytes, err := ioutil.ReadFile("server.key")
	var block *pem.Block
	if err == nil && len(privBytes) > 0 { block, _ = pem.Decode(privBytes) }

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
			Subject: pkix.Name{Organization: []string{"Wolfronix Secure"}},
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(365 * 24 * time.Hour),
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
	if block == nil { return nil }
	
	// Handle PKCS#1 vs PKCS#8 for Private Key too
	var priv *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		priv = k
	} else if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		priv = k.(*rsa.PrivateKey)
	}

	if priv == nil { return nil }
	
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
		if r.Method == "OPTIONS" { return }
		next.ServeHTTP(w, r)
	})
}
