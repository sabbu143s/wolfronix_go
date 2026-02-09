// seed_test_client.go
// Run this to create a test client in the Wolfronix Engine database
// Usage: go run scripts/seed_test_client.go

package main

import (
	"fmt"
	"log"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Client model (must match database.go)
type Client struct {
	ID              uint      `gorm:"primaryKey" json:"id"`
	Name            string    `json:"name"`
	APIKey          string    `gorm:"unique;not null;index" json:"api_key"`
	IsActive        bool      `json:"is_active"`
	CreatedAt       time.Time `json:"created_at"`
	Plan            string    `json:"plan"`
	APICallsLimit   int64     `json:"api_calls_limit"`
	APICallsUsed    int64     `json:"api_calls_used"`
	SeatsLimit      int       `json:"seats_limit"`
	SeatsUsed       int       `json:"seats_used"`
	UsageResetDate  time.Time `json:"usage_reset_date"`
	SubscriptionEnd time.Time `json:"subscription_end"`
}

func main() {
	// Connect to the SQLite database
	db, err := gorm.Open(sqlite.Open("wolfronix_data/wolfronix.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("❌ Failed to connect to database:", err)
	}

	// Auto-migrate to ensure table exists
	db.AutoMigrate(&Client{})

	// ===== TEST CLIENT DATA =====
	// This is the key you'll use in X-Wolfronix-Key header
	testAPIKey := "wfx_test_client_12345678"

	testClient := Client{
		Name:            "Test Client (TC)",
		APIKey:          testAPIKey,
		IsActive:        true,
		CreatedAt:       time.Now(),
		Plan:            "PRO",
		APICallsLimit:   100000, // 100k API calls
		APICallsUsed:    0,      // Start fresh
		SeatsLimit:      10,
		SeatsUsed:       1,
		UsageResetDate:  time.Now().AddDate(0, 1, 0), // Reset in 1 month
		SubscriptionEnd: time.Now().AddDate(1, 0, 0), // Expires in 1 year
	}

	// Check if test client already exists
	var existingClient Client
	result := db.Where("api_key = ?", testAPIKey).First(&existingClient)

	if result.Error == nil {
		// Update existing
		db.Model(&existingClient).Updates(testClient)
		fmt.Println("✅ Test Client UPDATED in database!")
	} else {
		// Create new
		db.Create(&testClient)
		fmt.Println("✅ Test Client CREATED in database!")
	}

	// Print summary
	fmt.Println("")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("                    TEST CLIENT DETAILS                     ")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("  Name:           %s\n", testClient.Name)
	fmt.Printf("  API Key:        %s\n", testClient.APIKey)
	fmt.Printf("  Plan:           %s\n", testClient.Plan)
	fmt.Printf("  API Calls:      %d / %d\n", testClient.APICallsUsed, testClient.APICallsLimit)
	fmt.Printf("  Status:         Active\n")
	fmt.Printf("  Expires:        %s\n", testClient.SubscriptionEnd.Format("2006-01-02"))
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("")
	fmt.Println("📋 Use this header in your API requests:")
	fmt.Printf("   X-Wolfronix-Key: %s\n", testClient.APIKey)
	fmt.Println("")
}
