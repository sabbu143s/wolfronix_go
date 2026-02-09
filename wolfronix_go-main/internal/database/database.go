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

	// Subscription & Quota Fields
	Plan            string    `json:"plan"`             // STARTER, PRO, ENTERPRISE
	APICallsLimit   int64     `json:"api_calls_limit"`  // Max API calls per month
	APICallsUsed    int64     `json:"api_calls_used"`   // Current month API calls
	SeatsLimit      int       `json:"seats_limit"`      // Max user seats
	SeatsUsed       int       `json:"seats_used"`       // Current seats used
	UsageResetDate  time.Time `json:"usage_reset_date"` // When to reset monthly usage
	SubscriptionEnd time.Time `json:"subscription_end"` // When subscription expires
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
	ID            uint   `gorm:"primaryKey"`
	PublicKeyPEM  string `gorm:"type:text"`
	PrivateKeyPEM string `gorm:"type:text"`
	CreatedAt     time.Time
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
