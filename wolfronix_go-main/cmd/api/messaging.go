package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ============================================================================
// Message & Stream Types
// ============================================================================

// --- Single Message Encrypt/Decrypt ---

type MessageEncryptRequest struct {
	Message  string `json:"message"`
	UserID   string `json:"user_id"`
	UserRole string `json:"user_role"`
	Layer    int    `json:"layer"` // 3 = AES-256-GCM only, 4 = AES + dual-key split (default: 4)
}

type MessageEncryptResponse struct {
	EncryptedMessage string `json:"encrypted_message"` // base64
	Nonce            string `json:"nonce"`             // base64
	KeyPartA         string `json:"key_part_a"`        // base64 — client's half (L4) or full key (L3)
	MessageTag       string `json:"message_tag"`       // tag for server's key_part_b lookup (L4 only)
	Timestamp        int64  `json:"timestamp"`
}

type MessageDecryptRequest struct {
	EncryptedMessage string `json:"encrypted_message"` // base64
	Nonce            string `json:"nonce"`             // base64
	KeyPartA         string `json:"key_part_a"`        // base64
	MessageTag       string `json:"message_tag"`       // for L4 key_part_b retrieval (empty = L3)
	UserID           string `json:"user_id"`
	UserRole         string `json:"user_role"`
}

type MessageDecryptResponse struct {
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
}

// --- Batch Message Encrypt ---

type BatchEncryptRequest struct {
	Messages []BatchMessageItem `json:"messages"`
	UserID   string             `json:"user_id"`
	Layer    int                `json:"layer"`
}

type BatchMessageItem struct {
	ID      string `json:"id"`      // caller's reference ID
	Message string `json:"message"` // plaintext
}

type BatchEncryptResponse struct {
	Results   []BatchEncryptResult `json:"results"`
	KeyPartA  string               `json:"key_part_a"` // shared across batch
	BatchTag  string               `json:"batch_tag"`  // shared key_part_b reference
	Timestamp int64                `json:"timestamp"`
}

type BatchEncryptResult struct {
	ID               string `json:"id"`
	EncryptedMessage string `json:"encrypted_message"` // base64
	Nonce            string `json:"nonce"`             // base64 — unique per message
	Seq              int    `json:"seq"`
}

// ============================================================================
// Ephemeral Message Key Store
// ============================================================================
//
// In-memory store for message key_part_b halves.
// Keys auto-expire after messageKeyTTL.
//
// Production: Replace with Redis for multi-instance deployments.

type messageKeyEntry struct {
	keyPartB  []byte
	clientID  string
	userID    string
	createdAt time.Time
}

var (
	messageKeyStore   = make(map[string]*messageKeyEntry)
	messageKeyMu      sync.RWMutex
	messageKeyTTL     = 24 * time.Hour
	messageCleanupInt = 15 * time.Minute
)

// initMessaging starts background cleanup for expired message keys.
// Call from main() during startup.
func initMessaging() {
	go func() {
		ticker := time.NewTicker(messageCleanupInt)
		defer ticker.Stop()
		for range ticker.C {
			messageKeyMu.Lock()
			cutoff := time.Now().Add(-messageKeyTTL)
			expired := 0
			for tag, entry := range messageKeyStore {
				if entry.createdAt.Before(cutoff) {
					delete(messageKeyStore, tag)
					expired++
				}
			}
			messageKeyMu.Unlock()
			if expired > 0 {
				log.Printf("🧹 Cleaned up %d expired message keys", expired)
			}
		}
	}()
	log.Println("✅ Message encryption subsystem initialized (key TTL:", messageKeyTTL, ")")
}

// ============================================================================
// Crypto Helpers (message-specific)
// ============================================================================

func aesGCMEncrypt(key, plaintext []byte) (ciphertext, nonce []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nonce, nil
}

func aesGCMDecrypt(key, nonce, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// ============================================================================
// Message Encrypt Handler
// ============================================================================

// POST /api/v1/messages/encrypt
//
// Encrypts a text message using AES-256-GCM with the Wolfronix dual-key split.
// Returns the encrypted payload + client's key half inline (no file storage).
func messageEncryptHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	clientID, err := getAuthenticatedClientID(r)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, 403)
		return
	}

	var req MessageEncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid JSON body"}`, 400)
		return
	}

	if req.Message == "" {
		http.Error(w, `{"error": "message is required"}`, 400)
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = req.UserID
	}
	if userID == "" {
		http.Error(w, `{"error": "user_id is required"}`, 400)
		return
	}

	layer := req.Layer
	if layer == 0 {
		layer = 4 // default: maximum security
	}
	if layer < 3 || layer > 4 {
		http.Error(w, `{"error": "layer must be 3 or 4"}`, 400)
		return
	}

	// Generate AES-256 key
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		http.Error(w, `{"error": "Key generation failed"}`, 500)
		return
	}

	// Encrypt with AES-256-GCM
	ciphertext, nonce, err := aesGCMEncrypt(aesKey, []byte(req.Message))
	if err != nil {
		http.Error(w, `{"error": "Encryption failed"}`, 500)
		return
	}

	resp := MessageEncryptResponse{
		EncryptedMessage: base64.StdEncoding.EncodeToString(ciphertext),
		Nonce:            base64.StdEncoding.EncodeToString(nonce),
		Timestamp:        time.Now().Unix(),
	}

	if layer == 4 {
		// Dual-key split: 16 bytes to client, 16 bytes stored server-side
		keyPartA := make([]byte, 16)
		keyPartB := make([]byte, 16)
		copy(keyPartA, aesKey[:16])
		copy(keyPartB, aesKey[16:])

		tagBytes := make([]byte, 16)
		rand.Read(tagBytes)
		tag := fmt.Sprintf("msg-%x", tagBytes)

		messageKeyMu.Lock()
		messageKeyStore[tag] = &messageKeyEntry{
			keyPartB:  keyPartB,
			clientID:  clientID,
			userID:    userID,
			createdAt: time.Now(),
		}
		messageKeyMu.Unlock()

		resp.KeyPartA = base64.StdEncoding.EncodeToString(keyPartA)
		resp.MessageTag = tag
	} else {
		// Layer 3: full key returned to client (no split)
		resp.KeyPartA = base64.StdEncoding.EncodeToString(aesKey)
	}

	if metricsStore != nil {
		metricsStore.RecordEncryption(clientID, userID, time.Since(start).Milliseconds(), 1, int64(len(req.Message)))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ============================================================================
// Message Decrypt Handler
// ============================================================================

// POST /api/v1/messages/decrypt
//
// Decrypts a message previously encrypted by messageEncryptHandler.
// Client provides key_part_a + message_tag; server provides key_part_b.
func messageDecryptHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	clientID, err := getAuthenticatedClientID(r)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, 403)
		return
	}

	var req MessageDecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid JSON body"}`, 400)
		return
	}

	if req.EncryptedMessage == "" || req.Nonce == "" || req.KeyPartA == "" {
		http.Error(w, `{"error": "encrypted_message, nonce, and key_part_a are required"}`, 400)
		return
	}

	ciphertext, err := base64.StdEncoding.DecodeString(req.EncryptedMessage)
	if err != nil {
		http.Error(w, `{"error": "Invalid encrypted_message encoding"}`, 400)
		return
	}
	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		http.Error(w, `{"error": "Invalid nonce encoding"}`, 400)
		return
	}
	keyPartA, err := base64.StdEncoding.DecodeString(req.KeyPartA)
	if err != nil {
		http.Error(w, `{"error": "Invalid key_part_a encoding"}`, 400)
		return
	}

	var aesKey []byte

	if req.MessageTag != "" {
		// Layer 4: reconstruct key from two halves
		messageKeyMu.RLock()
		entry, exists := messageKeyStore[req.MessageTag]
		messageKeyMu.RUnlock()

		if !exists {
			http.Error(w, `{"error": "Message key not found or expired"}`, 404)
			return
		}
		if entry.clientID != clientID {
			http.Error(w, `{"error": "Access denied"}`, 403)
			return
		}
		if len(keyPartA) != 16 {
			http.Error(w, `{"error": "Invalid key_part_a length for Layer 4 (expected 16 bytes)"}`, 400)
			return
		}

		aesKey = make([]byte, 32)
		copy(aesKey[:16], keyPartA)
		copy(aesKey[16:], entry.keyPartB)
	} else {
		// Layer 3: full key provided by client
		if len(keyPartA) != 32 {
			http.Error(w, `{"error": "Invalid key length for Layer 3 (expected 32 bytes)"}`, 400)
			return
		}
		aesKey = keyPartA
	}

	plaintext, err := aesGCMDecrypt(aesKey, nonce, ciphertext)
	if err != nil {
		http.Error(w, `{"error": "Decryption failed - invalid key or corrupted data"}`, 400)
		return
	}

	if metricsStore != nil {
		metricsStore.RecordDecryption(clientID, req.UserID, time.Since(start).Milliseconds(), 1, int64(len(plaintext)))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(MessageDecryptResponse{
		Message:   string(plaintext),
		Timestamp: time.Now().Unix(),
	})
}

// ============================================================================
// Batch Message Encrypt Handler
// ============================================================================

// POST /api/v1/messages/batch/encrypt
//
// Encrypts multiple messages with a single AES key (different nonce per message).
// Efficient for chat apps that need to encrypt N messages in one round-trip.
func messageBatchEncryptHandler(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	clientID, err := getAuthenticatedClientID(r)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, 403)
		return
	}

	var req BatchEncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error": "Invalid JSON body"}`, 400)
		return
	}

	if len(req.Messages) == 0 {
		http.Error(w, `{"error": "messages array is required and must not be empty"}`, 400)
		return
	}
	if len(req.Messages) > 100 {
		http.Error(w, `{"error": "Maximum 100 messages per batch"}`, 400)
		return
	}

	userID := r.Header.Get("X-User-ID")
	if userID == "" {
		userID = req.UserID
	}

	layer := req.Layer
	if layer == 0 {
		layer = 4
	}

	// Single AES key for the batch
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		http.Error(w, `{"error": "Key generation failed"}`, 500)
		return
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		http.Error(w, `{"error": "Encryption failed"}`, 500)
		return
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		http.Error(w, `{"error": "Encryption failed"}`, 500)
		return
	}

	// Generate random 4-byte prefix for nonces (ensures uniqueness across batches)
	noncePrefix := make([]byte, 4)
	rand.Read(noncePrefix)

	results := make([]BatchEncryptResult, len(req.Messages))
	for i, msg := range req.Messages {
		// Nonce = 4 random bytes (shared) + 8 byte counter (unique per message)
		nonce := make([]byte, gcm.NonceSize()) // 12 bytes
		copy(nonce[:4], noncePrefix)
		binary.BigEndian.PutUint64(nonce[4:], uint64(i))

		ciphertext := gcm.Seal(nil, nonce, []byte(msg.Message), nil)

		results[i] = BatchEncryptResult{
			ID:               msg.ID,
			EncryptedMessage: base64.StdEncoding.EncodeToString(ciphertext),
			Nonce:            base64.StdEncoding.EncodeToString(nonce),
			Seq:              i,
		}
	}

	resp := BatchEncryptResponse{
		Results:   results,
		Timestamp: time.Now().Unix(),
	}

	if layer == 4 {
		tagBytes := make([]byte, 16)
		rand.Read(tagBytes)
		tag := fmt.Sprintf("batch-%x", tagBytes)

		keyPartB := make([]byte, 16)
		copy(keyPartB, aesKey[16:])

		messageKeyMu.Lock()
		messageKeyStore[tag] = &messageKeyEntry{
			keyPartB:  keyPartB,
			clientID:  clientID,
			userID:    userID,
			createdAt: time.Now(),
		}
		messageKeyMu.Unlock()

		resp.KeyPartA = base64.StdEncoding.EncodeToString(aesKey[:16])
		resp.BatchTag = tag
	} else {
		resp.KeyPartA = base64.StdEncoding.EncodeToString(aesKey)
	}

	if metricsStore != nil {
		totalSize := int64(0)
		for _, m := range req.Messages {
			totalSize += int64(len(m.Message))
		}
		metricsStore.RecordEncryption(clientID, userID, time.Since(start).Milliseconds(), len(req.Messages), totalSize)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ============================================================================
// WebSocket Streaming Encryption
// ============================================================================
//
// Protocol:
//   1. Client opens WebSocket to /api/v1/stream
//   2. Client sends init message: {"type":"init","direction":"encrypt"|"decrypt", ...}
//   3. Server responds: {"type":"init_ack","key_part_a":"...","stream_tag":"..."}
//   4. Client sends data chunks: {"type":"data","data":"<base64>"}
//   5. Server responds with encrypted/decrypted chunks: {"type":"data","data":"<base64>","seq":N}
//   6. Client sends end: {"type":"end"}
//   7. Server responds: {"type":"end_ack","chunks_processed":N}
//
// Each chunk is encrypted with AES-256-GCM using counter-based nonces
// (4 zero bytes + 8-byte big-endian counter), guaranteeing nonce uniqueness.

var wsUpgrader = websocket.Upgrader{
	ReadBufferSize:  65536, // 64KB chunks
	WriteBufferSize: 65536,
	CheckOrigin: func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		if origin == "" {
			return true
		}
		allowed := getAllowedOrigins()
		for _, a := range allowed {
			if a == "*" || a == origin {
				return true
			}
		}
		return false
	},
}

func streamHandler(w http.ResponseWriter, r *http.Request) {
	clientID, err := getAuthenticatedClientID(r)
	if err != nil {
		http.Error(w, `{"error": "`+err.Error()+`"}`, 403)
		return
	}

	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("⚠️ WebSocket upgrade failed for client %s: %v", clientID, err)
		return
	}
	defer conn.Close()

	// Set connection limits
	conn.SetReadLimit(1 << 20) // 1MB max message size
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	conn.SetPongHandler(func(string) error {
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	// --- Step 1: Read init message ---
	var initMsg struct {
		Type      string `json:"type"`       // must be "init"
		Direction string `json:"direction"`  // "encrypt" or "decrypt"
		KeyPartA  string `json:"key_part_a"` // required for decrypt
		StreamTag string `json:"stream_tag"` // required for decrypt
	}
	if err := conn.ReadJSON(&initMsg); err != nil {
		writeWSError(conn, "Expected JSON init message")
		return
	}
	if initMsg.Type != "init" {
		writeWSError(conn, "First message must have type 'init'")
		return
	}

	var gcmCipher cipher.AEAD
	direction := initMsg.Direction

	switch direction {
	case "encrypt":
		// Generate new AES key for this stream session
		aesKey := make([]byte, 32)
		rand.Read(aesKey)

		block, err := aes.NewCipher(aesKey)
		if err != nil {
			writeWSError(conn, "Encryption setup failed")
			return
		}
		gcmCipher, err = cipher.NewGCM(block)
		if err != nil {
			writeWSError(conn, "Encryption setup failed")
			return
		}

		// Store key_part_b, send key_part_a to client
		tagBytes := make([]byte, 16)
		rand.Read(tagBytes)
		streamTag := fmt.Sprintf("stream-%x", tagBytes)

		keyPartB := make([]byte, 16)
		copy(keyPartB, aesKey[16:])

		messageKeyMu.Lock()
		messageKeyStore[streamTag] = &messageKeyEntry{
			keyPartB:  keyPartB,
			clientID:  clientID,
			createdAt: time.Now(),
		}
		messageKeyMu.Unlock()

		conn.WriteJSON(map[string]string{
			"type":       "init_ack",
			"key_part_a": base64.StdEncoding.EncodeToString(aesKey[:16]),
			"stream_tag": streamTag,
		})

	case "decrypt":
		keyPartA, err := base64.StdEncoding.DecodeString(initMsg.KeyPartA)
		if err != nil || len(keyPartA) != 16 {
			writeWSError(conn, "Invalid key_part_a")
			return
		}

		messageKeyMu.RLock()
		entry, exists := messageKeyStore[initMsg.StreamTag]
		messageKeyMu.RUnlock()

		if !exists || entry.clientID != clientID {
			writeWSError(conn, "Stream key not found or access denied")
			return
		}

		aesKey := make([]byte, 32)
		copy(aesKey[:16], keyPartA)
		copy(aesKey[16:], entry.keyPartB)

		block, err := aes.NewCipher(aesKey)
		if err != nil {
			writeWSError(conn, "Decryption setup failed")
			return
		}
		gcmCipher, err = cipher.NewGCM(block)
		if err != nil {
			writeWSError(conn, "Decryption setup failed")
			return
		}

		conn.WriteJSON(map[string]string{"type": "init_ack"})

	default:
		writeWSError(conn, "direction must be 'encrypt' or 'decrypt'")
		return
	}

	// --- Step 2: Process data chunks ---
	var seqCounter uint64
	sessionStart := time.Now()

	for {
		// Refresh read deadline for each message
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		var chunkMsg struct {
			Type string `json:"type"` // "data" or "end"
			Data string `json:"data"` // base64-encoded chunk
		}
		if err := conn.ReadJSON(&chunkMsg); err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				break
			}
			if !strings.Contains(err.Error(), "timeout") {
				log.Printf("⚠️ Stream read error for client %s: %v", clientID, err)
			}
			break
		}

		if chunkMsg.Type == "end" {
			conn.WriteJSON(map[string]interface{}{
				"type":             "end_ack",
				"chunks_processed": seqCounter,
			})
			break
		}

		if chunkMsg.Type != "data" {
			writeWSError(conn, "Expected 'data' or 'end' message type")
			continue
		}

		chunkData, err := base64.StdEncoding.DecodeString(chunkMsg.Data)
		if err != nil {
			writeWSError(conn, "Invalid chunk data encoding")
			continue
		}

		// Counter-based nonce: 4 zero bytes + 8-byte big-endian counter
		nonce := make([]byte, gcmCipher.NonceSize()) // 12 bytes
		binary.BigEndian.PutUint64(nonce[4:], seqCounter)

		var result []byte
		if direction == "encrypt" {
			result = gcmCipher.Seal(nil, nonce, chunkData, nil)
		} else {
			result, err = gcmCipher.Open(nil, nonce, chunkData, nil)
			if err != nil {
				writeWSError(conn, "Chunk decryption failed — invalid data or wrong sequence")
				continue
			}
		}

		conn.WriteJSON(map[string]interface{}{
			"type": "data",
			"data": base64.StdEncoding.EncodeToString(result),
			"seq":  seqCounter,
		})
		seqCounter++
	}

	if metricsStore != nil {
		metricsStore.RecordEncryption(clientID, "", time.Since(sessionStart).Milliseconds(), int(seqCounter), 0)
	}
	log.Printf("📡 Stream session complete: client=%s direction=%s chunks=%d duration=%v",
		clientID, direction, seqCounter, time.Since(sessionStart).Round(time.Millisecond))
}

// writeWSError sends a JSON error message over WebSocket.
func writeWSError(conn *websocket.Conn, msg string) {
	conn.WriteJSON(map[string]string{"type": "error", "error": msg})
}
