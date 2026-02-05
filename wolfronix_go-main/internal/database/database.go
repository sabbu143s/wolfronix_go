package database

import (
	"log"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var DB *gorm.DB

// 1. SUBSCRIBERS
type Client struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Name      string    `json:"name"`
	APIKey    string    `gorm:"unique;not null;index" json:"api_key"` // Indexed for speed
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
}

// 2. AUDIT TRAIL
type AuditLog struct {
	ID           uint      `gorm:"primaryKey"`
	ClientAPIKey string    `gorm:"index"` // Indexed for faster lookups
	Action       string    `json:"action"`
	IPAddress    string    `json:"ip_address"`
	Status       string    `json:"status"`
	Timestamp    time.Time `json:"timestamp"`
}

// 3. PERSISTENT MASTER KEYS (New!)
type ServerMasterKey struct {
	ID             uint   `gorm:"primaryKey"`
	PublicKeyPEM   string `gorm:"type:text"`
	PrivateKeyPEM  string `gorm:"type:text"`
	CreatedAt      time.Time
}

func Connect(dbPath string) {
	var err error
	DB, err = gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
	if err != nil {
		log.Fatal("❌ Database Connection Failed:", err)
	}
}

func AutoMigrate() {
	DB.AutoMigrate(&Client{}, &AuditLog{}, &ServerMasterKey{})
}
