// seed_test_client.go
// Registers a test enterprise client via the Wolfronix API
// Usage: go run scripts/seed_test_client.go
//
// Requires a running Wolfronix engine at https://localhost:5001

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

func main() {
	// Skip TLS verify for self-signed certs in dev
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	baseURL := "https://localhost:5001"

	payload := map[string]string{
		"client_id":    "test-client-01",
		"client_name":  "Test Client (TC)",
		"api_endpoint": "http://localhost:8080/wolfronix",
		"api_key":      "client-storage-api-key",
	}

	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", baseURL+"/api/v1/enterprise/register", bytes.NewReader(body))
	if err != nil {
		log.Fatal("❌ Failed to create request:", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal("❌ Failed to connect to Wolfronix engine:", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		log.Fatalf("❌ Registration failed (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var result map[string]interface{}
	json.Unmarshal(respBody, &result)

	fmt.Println("")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("                    TEST CLIENT REGISTERED                  ")
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Printf("  Client ID:      %s\n", payload["client_id"])
	fmt.Printf("  Client Name:    %s\n", payload["client_name"])
	fmt.Printf("  API Endpoint:   %s\n", payload["api_endpoint"])
	if wfxKey, ok := result["wolfronix_key"]; ok {
		fmt.Printf("  Wolfronix Key:  %v\n", wfxKey)
	}
	fmt.Println("═══════════════════════════════════════════════════════════")
	fmt.Println("")
	fmt.Println("📋 Use this header in your API requests:")
	if wfxKey, ok := result["wolfronix_key"]; ok {
		fmt.Printf("   X-Wolfronix-Key: %v\n", wfxKey)
	}
	fmt.Println("")
}
