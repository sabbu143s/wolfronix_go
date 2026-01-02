package config

import (
	"crypto/sha256"
	"log"
	"os"
	"time"

	"wolfronixgo/internal/crypto"
	"wolfronixgo/internal/database"
)

type Config struct {
	ServerPort       string
	DBPath           string
	VaultPassword    []byte // The Key to unlock the DB
	MasterPublicKey  string
	MasterPrivateKey string
}

var Global *Config

func Load() {
	pass := getEnv("VAULT_PASSWORD", "DefaultInsecurePassword123!") // Change this in production!
	
	// Hash password to make it 32 bytes (AES-256 requirement)
	hash := sha256.Sum256([]byte(pass))

	Global = &Config{
		ServerPort:    getEnv("SERVER_PORT", "5001"),
		DBPath:        getEnv("DB_PATH", "wolfronix.db"),
		VaultPassword: hash[:], 
	}
}

func InitializeMasterKeys() {
	var keyRecord database.ServerMasterKey
	result := database.DB.First(&keyRecord)

	if result.Error != nil {
		log.Println("⚡ Initial Setup: Generating & Encrypting Master Keys...")
		priv, pub := crypto.GenerateRSAKeys()
		
		// 🔒 ENCRYPT BEFORE SAVING TO DB (Fix for Drawback 1)
		encPriv, _ := crypto.EncryptAESGCM(priv, Global.VaultPassword)
		encPub, _ := crypto.EncryptAESGCM(pub, Global.VaultPassword)

		keyRecord = database.ServerMasterKey{
			PublicKeyPEM:  encPub,
			PrivateKeyPEM: encPriv,
			CreatedAt:     time.Now(),
		}
		database.DB.Create(&keyRecord)
		
		// Cache Decrypted versions in RAM
		Global.MasterPrivateKey = priv
		Global.MasterPublicKey = pub
	} else {
		log.Println("🔓 Unlocking Master Keys from Database...")
		
		// 🔓 DECRYPT FROM DB TO RAM
		decPriv, err1 := crypto.DecryptAESGCM(keyRecord.PrivateKeyPEM, Global.VaultPassword)
		decPub, err2 := crypto.DecryptAESGCM(keyRecord.PublicKeyPEM, Global.VaultPassword)

		if err1 != nil || err2 != nil {
			log.Fatal("❌ FATAL: Wrong Vault Password! Cannot unlock database.")
		}

		Global.MasterPrivateKey = decPriv
		Global.MasterPublicKey = decPub
	}
	exportBackup(Global.MasterPrivateKey, Global.MasterPublicKey)
}

func getEnv(key, fallback string) string {
	if v, exists := os.LookupEnv(key); exists { return v }
	return fallback
}

// Saves keys to a text file so you can print/store them safely
func exportBackup(priv, pub string) {
    f, _ := os.Create("master_key_backup.txt")
    defer f.Close()
    f.WriteString("=== WOLFRONIX MASTER KEY BACKUP ===\n")
    f.WriteString("DO NOT SHARE THIS FILE. KEEP IT SAFE.\n\n")
    f.WriteString("PRIVATE KEY:\n" + priv + "\n\n")
    f.WriteString("PUBLIC KEY:\n" + pub + "\n")
    log.Println("💾 Master Key Backup saved to 'master_key_backup.txt'")
}
