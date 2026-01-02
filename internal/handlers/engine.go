package handlers

import (
	"encoding/base64"
	"fmt"
	"wolfronixgo/internal/config"
	"wolfronixgo/internal/crypto"
	"wolfronixgo/internal/database"

	"github.com/gofiber/fiber/v2"
)

// --- A. KEY GENERATION (Unchanged) ---
func GenerateKeys(c *fiber.Ctx) error {
	priv, pub := crypto.GenerateRSAKeys()
	logAudit(c, "KEY_GEN", "SUCCESS")
	return c.JSON(fiber.Map{"public_key": pub, "private_key": priv})
}

// --- B. STREAMING ENCRYPTION (Fixed) ---
func EncryptData(c *fiber.Ctx) error {
	// 1. Get File Stream
	fileHeader, err := c.FormFile("file")
	if err != nil { return c.Status(400).JSON(fiber.Map{"error": "File required (multipart/form-data)"}) }
	
	file, err := fileHeader.Open()
	if err != nil { return c.SendStatus(500) }
	// defer file.Close() // WARNING: Do NOT close here. SetBodyStream needs it open! 
	// Fiber will close it automatically when the stream finishes.

	// 2. Get Client Public Key
	clientPub := c.FormValue("client_public_key")
	if clientPub == "" { return c.Status(400).JSON(fiber.Map{"error": "client_public_key required"}) }

	// 3. Generate Crypto Material
	aesKey, _ := crypto.GenerateAESKey()
	iv, _ := crypto.GenerateIV()

	// 4. Split & Lock Keys
	partA := aesKey[:16]
	partB := aesKey[16:]
	encPartA, _ := crypto.EncryptRSA(partA, clientPub)
	encPartB, _ := crypto.EncryptRSA(partB, config.Global.MasterPublicKey)

	// 5. Set Headers
	c.Set("X-Encrypted-Part-A", encPartA)
	c.Set("X-Encrypted-Part-B", encPartB)
	c.Set("X-IV", base64.StdEncoding.EncodeToString(iv))
	c.Set("Content-Type", "application/octet-stream")
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"enc_%s\"", fileHeader.Filename))

	logAudit(c, "ENCRYPT_STREAM", "SUCCESS")
	
	// 6. Start Streaming (Simpler Method)
	streamer, _ := crypto.NewAESStreamReader(file, aesKey, iv)
	
	// SetBodyStream(reader, size). -1 means "Unknown Size" (Chunked Streaming)
	c.Context().SetBodyStream(streamer, -1)

	return nil
}

// --- C. STREAMING DECRYPTION (Fixed) ---
func DecryptData(c *fiber.Ctx) error {
	// 1. Get File Stream
	fileHeader, err := c.FormFile("file")
	if err != nil { return c.Status(400).JSON(fiber.Map{"error": "Encrypted file required"}) }
	
	file, err := fileHeader.Open()
	if err != nil { return c.SendStatus(500) }
	// Do NOT close 'file' manually here either.

	// 2. Get Metadata
	encPartA := c.FormValue("encrypted_part_a")
	encPartB := c.FormValue("encrypted_part_b")
	ivB64 := c.FormValue("iv")
	clientPriv := c.FormValue("client_private_key")

	if encPartA == "" || encPartB == "" || ivB64 == "" || clientPriv == "" {
		return c.Status(400).JSON(fiber.Map{"error": "Missing metadata fields"})
	}

	// 3. Unlock Keys
	keyA, err := crypto.DecryptRSA(encPartA, clientPriv)
	if err != nil { return c.Status(400).JSON(fiber.Map{"error": "Client Key Failed"}) }

	keyB, err := crypto.DecryptRSA(encPartB, config.Global.MasterPrivateKey)
	if err != nil { return c.Status(500).JSON(fiber.Map{"error": "Server Key Failed"}) }

	aesKey := append(keyA, keyB...)
	iv, err := base64.StdEncoding.DecodeString(ivB64)
	if err != nil { return c.Status(400).JSON(fiber.Map{"error": "Bad IV"}) }

	// 4. Stream Back
	c.Set("Content-Type", "application/octet-stream")
	c.Set("Content-Disposition", "attachment; filename=\"decrypted_file\"")

	logAudit(c, "DECRYPT_STREAM", "SUCCESS")

	// 5. Start Streaming
	streamer, _ := crypto.NewAESStreamDecryptor(file, aesKey, iv)
	c.Context().SetBodyStream(streamer, -1)

	return nil
}

// LOGGING (Fixed)
func logAudit(c *fiber.Ctx, action, status string) {
	apiKey, _ := c.Locals("api_key").(string)
	ip := c.IP()
	go func(key, userIP string) {
		database.DB.Create(&database.AuditLog{
			ClientAPIKey: key,
			Action:       action,
			IPAddress:    userIP,
			Status:       status,
			// time.Now() is implicit in DB creation if missing, but better to add package if explicit
		})
	}(apiKey, ip)
}
