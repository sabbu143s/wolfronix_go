package clientdb

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"time"
)

// maxResponseSize limits how much data we read from client API responses
// to prevent OOM attacks from malicious endpoints. (10 MB for metadata, 512 MB for file data)
const (
	maxResponseSize     = 10 * 1024 * 1024  // 10 MB
	maxFileResponseSize = 512 * 1024 * 1024 // 512 MB
)

// ClientDBConnector handles communication with client's database API
type ClientDBConnector struct {
	httpClient *http.Client
}

// ClientConfig holds the API configuration for a specific client
type ClientConfig struct {
	ClientID    string
	APIEndpoint string // e.g., "https://client-app.com/api/storage"
	APIKey      string
	Timeout     time.Duration
}

// StoredFile represents file metadata stored in client's DB
type StoredFile struct {
	ID          int64  `json:"id"`
	Filename    string `json:"filename"`
	FilePath    string `json:"file_path,omitempty"` // Optional: if client stores path
	FileSize    int64  `json:"file_size"`
	KeyPartA    string `json:"key_part_a"`
	KeyPartB    string `json:"key_part_b"`
	IV          string `json:"iv"`
	EncTimeMS   int64  `json:"enc_time_ms"`
	ClientID    string `json:"client_id"`
	UserID      string `json:"user_id"`
	CreatedAt   string `json:"created_at,omitempty"`
	StorageType string `json:"storage_type,omitempty"` // "blob" or "file_ref"
}

// StoredKey represents user's wrapped key stored in client's DB
type StoredKey struct {
	UserID              string `json:"user_id"`
	ClientID            string `json:"client_id"`
	PublicKeyPEM        string `json:"public_key_pem"`
	EncryptedPrivateKey string `json:"encrypted_private_key"`
	Salt                string `json:"salt"`
}

// NewClientDBConnector creates a new connector instance
func NewClientDBConnector() *ClientDBConnector {
	return &ClientDBConnector{
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// === FILE STORAGE OPERATIONS ===

// StoreFileMetadata sends file metadata to client's DB API
// The client's API should implement: POST /wolfronix/files
func (c *ClientDBConnector) StoreFileMetadata(config *ClientConfig, file *StoredFile) (int64, error) {
	url := fmt.Sprintf("%s/wolfronix/files", config.APIEndpoint)

	jsonData, err := json.Marshal(file)
	if err != nil {
		return 0, fmt.Errorf("failed to marshal file data: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Wolfronix-API-Key", config.APIKey)
	req.Header.Set("X-Client-ID", config.ClientID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return 0, fmt.Errorf("client API error (status %d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode response: %w", err)
	}

	log.Printf("📤 Stored file metadata in Client DB: ID=%d", result.ID)
	return result.ID, nil
}

// StoreFileWithData sends both metadata and encrypted file data to client's DB
// The client's API should implement: POST /wolfronix/files/upload (multipart)
func (c *ClientDBConnector) StoreFileWithData(config *ClientConfig, file *StoredFile, encryptedData []byte) (int64, error) {
	url := fmt.Sprintf("%s/wolfronix/files/upload", config.APIEndpoint)

	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add metadata as JSON field
	metadataJSON, _ := json.Marshal(file)
	writer.WriteField("metadata", string(metadataJSON))

	// Add encrypted file data
	part, err := writer.CreateFormFile("encrypted_data", file.Filename+".enc")
	if err != nil {
		return 0, fmt.Errorf("failed to create form file: %w", err)
	}
	part.Write(encryptedData)
	writer.Close()

	req, err := http.NewRequest("POST", url, &buf)
	if err != nil {
		return 0, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-Wolfronix-API-Key", config.APIKey)
	req.Header.Set("X-Client-ID", config.ClientID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return 0, fmt.Errorf("client API error (status %d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode response: %w", err)
	}

	log.Printf("📤 Stored encrypted file in Client DB: ID=%d, Size=%d bytes", result.ID, len(encryptedData))
	return result.ID, nil
}

// GetFileMetadata retrieves file metadata from client's DB
// The client's API should implement: GET /wolfronix/files/{id}
func (c *ClientDBConnector) GetFileMetadata(config *ClientConfig, fileID int64, userID string) (*StoredFile, error) {
	url := fmt.Sprintf("%s/wolfronix/files/%d", config.APIEndpoint, fileID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Wolfronix-API-Key", config.APIKey)
	req.Header.Set("X-Client-ID", config.ClientID)
	req.Header.Set("X-User-ID", userID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("file not found")
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, errors.New("access denied")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return nil, fmt.Errorf("client API error (status %d): %s", resp.StatusCode, string(body))
	}

	var file StoredFile
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&file); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &file, nil
}

// GetFileData retrieves the encrypted file data from client's DB
// The client's API should implement: GET /wolfronix/files/{id}/data
func (c *ClientDBConnector) GetFileData(config *ClientConfig, fileID int64, userID string) ([]byte, error) {
	url := fmt.Sprintf("%s/wolfronix/files/%d/data", config.APIEndpoint, fileID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Wolfronix-API-Key", config.APIKey)
	req.Header.Set("X-Client-ID", config.ClientID)
	req.Header.Set("X-User-ID", userID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("file not found")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return nil, fmt.Errorf("client API error (status %d): %s", resp.StatusCode, string(body))
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxFileResponseSize))
}

// ListFiles retrieves list of files for a user from client's DB
// The client's API should implement: GET /wolfronix/files?user_id={userID}
func (c *ClientDBConnector) ListFiles(config *ClientConfig, userID string) ([]StoredFile, error) {
	listURL := fmt.Sprintf("%s/wolfronix/files?user_id=%s", config.APIEndpoint, url.QueryEscape(userID))

	req, err := http.NewRequest("GET", listURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Wolfronix-API-Key", config.APIKey)
	req.Header.Set("X-Client-ID", config.ClientID)
	req.Header.Set("X-User-ID", userID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return nil, fmt.Errorf("client API error (status %d): %s", resp.StatusCode, string(body))
	}

	var files []StoredFile
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&files); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return files, nil
}

// DeleteFile deletes a file from client's DB
// The client's API should implement: DELETE /wolfronix/files/{id}
func (c *ClientDBConnector) DeleteFile(config *ClientConfig, fileID int64, userID string) error {
	url := fmt.Sprintf("%s/wolfronix/files/%d", config.APIEndpoint, fileID)

	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Wolfronix-API-Key", config.APIKey)
	req.Header.Set("X-Client-ID", config.ClientID)
	req.Header.Set("X-User-ID", userID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return fmt.Errorf("client API error (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}

// === USER KEY STORAGE OPERATIONS ===

// StoreUserKey stores a user's wrapped key in client's DB
// The client's API should implement: POST /wolfronix/keys
func (c *ClientDBConnector) StoreUserKey(config *ClientConfig, key *StoredKey) error {
	url := fmt.Sprintf("%s/wolfronix/keys", config.APIEndpoint)

	jsonData, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to marshal key data: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Wolfronix-API-Key", config.APIKey)
	req.Header.Set("X-Client-ID", config.ClientID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return fmt.Errorf("client API error (status %d): %s", resp.StatusCode, string(body))
	}

	log.Printf("🔑 Stored user key in Client DB: user_id=%s", key.UserID)
	return nil
}

// GetUserKey retrieves a user's wrapped key from client's DB
// The client's API should implement: GET /wolfronix/keys/{userID}
func (c *ClientDBConnector) GetUserKey(config *ClientConfig, userID string) (*StoredKey, error) {
	keyURL := fmt.Sprintf("%s/wolfronix/keys/%s", config.APIEndpoint, url.PathEscape(userID))

	req, err := http.NewRequest("GET", keyURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Wolfronix-API-Key", config.APIKey)
	req.Header.Set("X-Client-ID", config.ClientID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("user key not found")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return nil, fmt.Errorf("client API error (status %d): %s", resp.StatusCode, string(body))
	}

	var key StoredKey
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&key); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &key, nil
}

// GetUserPublicKey retrieves only the public key for a user
// The client's API should implement: GET /wolfronix/keys/{userID}/public
func (c *ClientDBConnector) GetUserPublicKey(config *ClientConfig, userID string) (string, error) {
	pubKeyURL := fmt.Sprintf("%s/wolfronix/keys/%s/public", config.APIEndpoint, url.PathEscape(userID))

	req, err := http.NewRequest("GET", pubKeyURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Wolfronix-API-Key", config.APIKey)
	req.Header.Set("X-Client-ID", config.ClientID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return "", errors.New("user not found")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return "", fmt.Errorf("client API error (status %d): %s", resp.StatusCode, string(body))
	}

	var result struct {
		PublicKeyPEM string `json:"public_key_pem"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseSize)).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result.PublicKeyPEM, nil
}

// === DEV/TEST DATA OPERATIONS (Layer 1) ===

// StoreFakeData stores fake/masked data in client's dev DB
// The client's API should implement: POST /wolfronix/dev/files
func (c *ClientDBConnector) StoreFakeData(config *ClientConfig, prodFileID int64, filename string, fakeData []byte) error {
	url := fmt.Sprintf("%s/wolfronix/dev/files", config.APIEndpoint)

	payload := map[string]interface{}{
		"prod_file_id": prodFileID,
		"filename":     filename,
		"fake_data":    fakeData,
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal fake data: %w", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Wolfronix-API-Key", config.APIKey)
	req.Header.Set("X-Client-ID", config.ClientID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		return fmt.Errorf("client API error (status %d): %s", resp.StatusCode, string(body))
	}

	log.Printf("🎭 Stored fake data in Client Dev DB: %s", filename)
	return nil
}
