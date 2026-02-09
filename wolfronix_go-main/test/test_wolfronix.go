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

const baseURL = "https://localhost:9443"

func main() {
	// Skip TLS verification for self-signed certs
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	fmt.Print("=== Wolfronix v1.0 Test Suite ===\n\n")

	// Test 1: Get Public Keys
	fmt.Println("1️⃣ Testing GET /api/v1/keys...")
	pubKey, err := getPublicKey()
	if err != nil {
		fmt.Printf("   ❌ Failed: %v\n", err)
		return
	}
	fmt.Printf("   ✅ Got public key (%d bytes)\n\n", len(pubKey))

	// Test 2: Encrypt a file
	fmt.Println("2️⃣ Testing POST /api/v1/encrypt...")
	fileID, err := encryptFile("sample_data.txt", pubKey, "test_client_001")
	if err != nil {
		fmt.Printf("   ❌ Failed: %v\n", err)
		return
	}
	fmt.Printf("   ✅ File encrypted! ID: %s\n\n", fileID)

	// Test 3: List files
	fmt.Println("3️⃣ Testing GET /api/v1/files...")
	files, err := listFiles()
	if err != nil {
		fmt.Printf("   ❌ Failed: %v\n", err)
		return
	}
	fmt.Printf("   ✅ Found %d file(s)\n\n", len(files))

	// Test 4: Metrics
	fmt.Println("4️⃣ Testing GET /api/v1/metrics/summary...")
	metrics, err := getMetrics()
	if err != nil {
		fmt.Printf("   ❌ Failed: %v\n", err)
		return
	}
	fmt.Printf("   ✅ Metrics: %v\n\n", metrics)

	fmt.Println("=== All Tests Passed! ===")
}

func getPublicKey() (string, error) {
	resp, err := http.Post(baseURL+"/api/v1/keys", "application/json", nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}
	return result["public_key"], nil
}

func encryptFile(filename, pubKey, clientID string) (string, error) {
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

	req, _ := http.NewRequest("POST", baseURL+"/api/v1/encrypt", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Environment", "dev") // Enable Layer 1 fake data

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	var result map[string]interface{}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("response: %s", string(respBody))
	}

	if id, ok := result["id"].(string); ok {
		return id, nil
	}
	return fmt.Sprintf("%v", result), nil
}

func listFiles() ([]interface{}, error) {
	resp, err := http.Get(baseURL + "/api/v1/files")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result []interface{}
	body, _ := io.ReadAll(resp.Body)
	if string(body) == "null" {
		return []interface{}{}, nil
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func getMetrics() (map[string]interface{}, error) {
	resp, err := http.Get(baseURL + "/api/v1/metrics/summary")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}
