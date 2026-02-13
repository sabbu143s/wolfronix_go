package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
)

// Wolfronix v2.3 Test Suite
// Tests the core API endpoints with proper authentication headers.
//
// Required env vars:
//   WOLFRONIX_URL     - Base URL (default: https://localhost:5001)
//   X_WOLFRONIX_KEY   - API key for authentication
//   X_CLIENT_ID       - Client ID (default: test_client_001)

var (
	testBaseURL  string
	wolfronixKey string
	clientID     string
)

func init() {
	testBaseURL = os.Getenv("WOLFRONIX_URL")
	if testBaseURL == "" {
		testBaseURL = "https://localhost:5001"
	}
	wolfronixKey = os.Getenv("X_WOLFRONIX_KEY")
	if wolfronixKey == "" {
		wolfronixKey = "test-key"
	}
	clientID = os.Getenv("X_CLIENT_ID")
	if clientID == "" {
		clientID = "test_client_001"
	}
}

func main() {
	// Skip TLS verification for self-signed certs
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	fmt.Print("=== Wolfronix v2.3 Test Suite (Enterprise Mode) ===\n\n")

	// Test 1: Health Check
	fmt.Println("1️⃣  Testing GET /health...")
	if err := testHealth(); err != nil {
		fmt.Printf("   ❌ Failed: %v\n", err)
		return
	}
	fmt.Println("   ✅ Health check passed")

	// Test 2: Get Public Keys
	fmt.Println("\n2️⃣  Testing POST /api/v1/keys...")
	pubKey, err := getPublicKey()
	if err != nil {
		fmt.Printf("   ❌ Failed: %v\n", err)
		return
	}
	fmt.Printf("   ✅ Got public key (%d bytes)\n", len(pubKey))

	// Test 3: Encrypt a file
	fmt.Println("\n3️⃣  Testing POST /api/v1/encrypt...")
	fileID, err := encryptFile("sample_data.txt", pubKey)
	if err != nil {
		fmt.Printf("   ❌ Failed: %v\n", err)
		return
	}
	fmt.Printf("   ✅ File encrypted! ID: %s\n", fileID)

	// Test 4: List files
	fmt.Println("\n4️⃣  Testing GET /api/v1/files...")
	files, err := listFiles()
	if err != nil {
		fmt.Printf("   ❌ Failed: %v\n", err)
		return
	}
	fmt.Printf("   ✅ Found %d file(s)\n", len(files))

	// Test 5: Decrypt a file
	fmt.Println("\n5️⃣  Testing POST /api/v1/decrypt...")
	if fileID != "" {
		err := decryptFile(fileID)
		if err != nil {
			fmt.Printf("   ❌ Failed: %v\n", err)
		} else {
			fmt.Println("   ✅ File decrypted successfully")
		}
	} else {
		fmt.Println("   ⏭️  Skipped (no file ID)")
	}

	// Test 6: Metrics
	fmt.Println("\n6️⃣  Testing GET /api/v1/metrics/summary...")
	metrics, err := getMetrics()
	if err != nil {
		fmt.Printf("   ❌ Failed: %v\n", err)
		return
	}
	fmt.Printf("   ✅ Metrics: %v\n", metrics)

	fmt.Println("\n=== All Tests Passed! ===")
}

// newRequest creates an http.Request with standard Wolfronix auth headers
func newRequest(method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Wolfronix-Key", wolfronixKey)
	req.Header.Set("X-Client-ID", clientID)
	req.Header.Set("X-User-ID", "test_user_001")
	return req, nil
}

func testHealth() error {
	resp, err := http.Get(testBaseURL + "/health")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}

	version, _ := result["version"].(string)
	fmt.Printf("   ℹ️  Engine version: %s\n", version)
	return nil
}

func getPublicKey() (string, error) {
	req, err := newRequest("POST", testBaseURL+"/api/v1/keys", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result["public_key"], nil
}

func encryptFile(filename, pubKey string) (string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return "", err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", filepath.Base(filename))
	if err != nil {
		return "", err
	}
	io.Copy(part, file)

	writer.WriteField("client_public_key", pubKey)
	writer.WriteField("client_id", clientID)
	writer.Close()

	req, err := newRequest("POST", testBaseURL+"/api/v1/encrypt", body)
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Environment", "dev")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("response: %s", string(respBody))
	}

	// API returns "file_id" field
	if id, ok := result["file_id"].(string); ok {
		return id, nil
	}
	return fmt.Sprintf("%v", result), nil
}

func listFiles() ([]interface{}, error) {
	req, err := newRequest("GET", testBaseURL+"/api/v1/files", nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) == "null" {
		return []interface{}{}, nil
	}

	var result []interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func decryptFile(fileID string) error {
	payload := map[string]string{"file_id": fileID}
	jsonBody, _ := json.Marshal(payload)

	req, err := newRequest("POST", testBaseURL+"/api/v1/decrypt", bytes.NewReader(jsonBody))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

func getMetrics() (map[string]interface{}, error) {
	req, err := newRequest("GET", testBaseURL+"/api/v1/metrics/summary", nil)
	if err != nil {
		return nil, err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}
