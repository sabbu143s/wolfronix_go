package storage

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// DatabaseType represents supported database types
type DatabaseType string

const (
	DBTypePostgreSQL DatabaseType = "postgresql"
	DBTypeMySQL      DatabaseType = "mysql"
	DBTypeMongoDB    DatabaseType = "mongodb"
	DBTypeMSSQL      DatabaseType = "mssql"
	DBTypeOracle     DatabaseType = "oracle"
	DBTypeRedis      DatabaseType = "redis"
	DBTypeElastic    DatabaseType = "elasticsearch"
	DBTypeFirebase   DatabaseType = "firebase"
	DBTypeDynamoDB   DatabaseType = "dynamodb"
	DBTypeCustomAPI  DatabaseType = "custom_api"
)

// ClientDBConfig holds configuration for connecting to client databases via API
type ClientDBConfig struct {
	Name        string            `json:"name"`         // Friendly name for the connection
	Type        DatabaseType      `json:"type"`         // Database type
	APIEndpoint string            `json:"api_endpoint"` // REST API endpoint URL
	APIKey      string            `json:"api_key"`      // API authentication key
	Headers     map[string]string `json:"headers"`      // Custom headers for API calls
	Timeout     time.Duration     `json:"timeout"`      // Request timeout
	RetryCount  int               `json:"retry_count"`  // Number of retries on failure
	Enabled     bool              `json:"enabled"`      // Whether this connection is active
}

// DataPayload represents data to be sent to client database
type DataPayload struct {
	RecordID    string                 `json:"record_id"`
	TableName   string                 `json:"table_name"`
	Operation   string                 `json:"operation"` // INSERT, UPDATE, DELETE, QUERY
	Data        map[string]interface{} `json:"data"`
	MaskedData  map[string]interface{} `json:"masked_data,omitempty"`
	Metadata    map[string]string      `json:"metadata,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
	ClientID    string                 `json:"client_id"`
	EncryptedBy string                 `json:"encrypted_by,omitempty"`
}

// APIResponse represents response from client database API
type APIResponse struct {
	Success   bool                   `json:"success"`
	Message   string                 `json:"message"`
	Data      map[string]interface{} `json:"data,omitempty"`
	RecordID  string                 `json:"record_id,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
}

// DatabaseConnector interface for all database connections via API
type DatabaseConnector interface {
	Connect() error
	Disconnect() error
	Send(payload DataPayload) (*APIResponse, error)
	Query(query map[string]interface{}) (*APIResponse, error)
	HealthCheck() error
	GetConfig() ClientDBConfig
}

// UniversalDBConnector implements DatabaseConnector for any REST API-based database
type UniversalDBConnector struct {
	config     ClientDBConfig
	httpClient *http.Client
	connected  bool
}

// NewUniversalDBConnector creates a new universal database connector
func NewUniversalDBConnector(config ClientDBConfig) *UniversalDBConnector {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.RetryCount == 0 {
		config.RetryCount = 3
	}

	return &UniversalDBConnector{
		config: config,
		httpClient: &http.Client{
			Timeout: config.Timeout,
		},
		connected: false,
	}
}

// Connect establishes connection to the client database API
func (u *UniversalDBConnector) Connect() error {
	if err := u.HealthCheck(); err != nil {
		return fmt.Errorf("failed to connect to %s: %v", u.config.Name, err)
	}
	u.connected = true
	return nil
}

// Disconnect closes the connection
func (u *UniversalDBConnector) Disconnect() error {
	u.connected = false
	return nil
}

// Send sends data payload to the client database via API
func (u *UniversalDBConnector) Send(payload DataPayload) (*APIResponse, error) {
	if !u.config.Enabled {
		return nil, fmt.Errorf("connector %s is disabled", u.config.Name)
	}

	payload.Timestamp = time.Now()

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	var lastErr error
	for i := 0; i < u.config.RetryCount; i++ {
		resp, err := u.makeRequest("POST", u.config.APIEndpoint+"/data", jsonData)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		time.Sleep(time.Duration(i+1) * time.Second) // Exponential backoff
	}

	return nil, fmt.Errorf("failed after %d retries: %v", u.config.RetryCount, lastErr)
}

// Query sends a query to the client database
func (u *UniversalDBConnector) Query(query map[string]interface{}) (*APIResponse, error) {
	if !u.config.Enabled {
		return nil, fmt.Errorf("connector %s is disabled", u.config.Name)
	}

	jsonData, err := json.Marshal(query)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal query: %v", err)
	}

	return u.makeRequest("POST", u.config.APIEndpoint+"/query", jsonData)
}

// HealthCheck verifies the database API is reachable
func (u *UniversalDBConnector) HealthCheck() error {
	req, err := http.NewRequest("GET", u.config.APIEndpoint+"/health", nil)
	if err != nil {
		return err
	}

	u.setHeaders(req)

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("health check failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check returned status %d", resp.StatusCode)
	}

	return nil
}

// GetConfig returns the connector configuration
func (u *UniversalDBConnector) GetConfig() ClientDBConfig {
	return u.config
}

// makeRequest performs HTTP request to the API
func (u *UniversalDBConnector) makeRequest(method, url string, body []byte) (*APIResponse, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	u.setHeaders(req)

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var apiResp APIResponse
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		// If response is not JSON, create a generic response
		apiResp = APIResponse{
			Success:   resp.StatusCode >= 200 && resp.StatusCode < 300,
			Message:   string(respBody),
			Timestamp: time.Now(),
		}
	}

	if resp.StatusCode >= 400 {
		return &apiResp, fmt.Errorf("API error: %s", apiResp.Error)
	}

	return &apiResp, nil
}

// setHeaders sets authentication and custom headers
func (u *UniversalDBConnector) setHeaders(req *http.Request) {
	if u.config.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+u.config.APIKey)
		req.Header.Set("X-API-Key", u.config.APIKey)
	}

	for key, value := range u.config.Headers {
		req.Header.Set(key, value)
	}
}

// ConnectionPool manages multiple database connections
type ConnectionPool struct {
	connectors map[string]DatabaseConnector
	primary    string
}

// NewConnectionPool creates a new connection pool
func NewConnectionPool() *ConnectionPool {
	return &ConnectionPool{
		connectors: make(map[string]DatabaseConnector),
	}
}

// AddConnector adds a database connector to the pool
func (p *ConnectionPool) AddConnector(name string, connector DatabaseConnector) error {
	if _, exists := p.connectors[name]; exists {
		return fmt.Errorf("connector %s already exists", name)
	}
	p.connectors[name] = connector

	// Set first connector as primary if none set
	if p.primary == "" {
		p.primary = name
	}
	return nil
}

// RemoveConnector removes a database connector from the pool
func (p *ConnectionPool) RemoveConnector(name string) {
	delete(p.connectors, name)
	if p.primary == name {
		p.primary = ""
		for n := range p.connectors {
			p.primary = n
			break
		}
	}
}

// SetPrimary sets the primary connector
func (p *ConnectionPool) SetPrimary(name string) error {
	if _, exists := p.connectors[name]; !exists {
		return fmt.Errorf("connector %s not found", name)
	}
	p.primary = name
	return nil
}

// GetConnector returns a specific connector
func (p *ConnectionPool) GetConnector(name string) (DatabaseConnector, error) {
	conn, exists := p.connectors[name]
	if !exists {
		return nil, fmt.Errorf("connector %s not found", name)
	}
	return conn, nil
}

// GetPrimary returns the primary connector
func (p *ConnectionPool) GetPrimary() (DatabaseConnector, error) {
	if p.primary == "" {
		return nil, fmt.Errorf("no primary connector set")
	}
	return p.GetConnector(p.primary)
}

// SendToAll sends data to all enabled connectors
func (p *ConnectionPool) SendToAll(payload DataPayload) map[string]*APIResponse {
	responses := make(map[string]*APIResponse)
	for name, conn := range p.connectors {
		if conn.GetConfig().Enabled {
			resp, err := conn.Send(payload)
			if err != nil {
				responses[name] = &APIResponse{
					Success:   false,
					Error:     err.Error(),
					Timestamp: time.Now(),
				}
			} else {
				responses[name] = resp
			}
		}
	}
	return responses
}

// SendToPrimary sends data only to the primary connector
func (p *ConnectionPool) SendToPrimary(payload DataPayload) (*APIResponse, error) {
	conn, err := p.GetPrimary()
	if err != nil {
		return nil, err
	}
	return conn.Send(payload)
}

// HealthCheckAll performs health check on all connectors
func (p *ConnectionPool) HealthCheckAll() map[string]error {
	results := make(map[string]error)
	for name, conn := range p.connectors {
		results[name] = conn.HealthCheck()
	}
	return results
}

// ListConnectors returns list of all connector names
func (p *ConnectionPool) ListConnectors() []string {
	names := make([]string, 0, len(p.connectors))
	for name := range p.connectors {
		names = append(names, name)
	}
	return names
}

// DataForwarder handles forwarding data to client databases with masking
type DataForwarder struct {
	pool           *ConnectionPool
	maskingEnabled bool
	auditLog       bool
}

// NewDataForwarder creates a new data forwarder
func NewDataForwarder(pool *ConnectionPool) *DataForwarder {
	return &DataForwarder{
		pool:           pool,
		maskingEnabled: true,
		auditLog:       true,
	}
}

// ForwardData forwards data to client database with optional masking
func (f *DataForwarder) ForwardData(clientID, tableName string, data map[string]interface{}, masked map[string]interface{}) (*APIResponse, error) {
	payload := DataPayload{
		RecordID:   generateRecordID(),
		TableName:  tableName,
		Operation:  "INSERT",
		Data:       data,
		MaskedData: masked,
		ClientID:   clientID,
		Timestamp:  time.Now(),
		Metadata: map[string]string{
			"forwarded_by": "wolfronix",
			"version":      "1.0",
		},
	}

	return f.pool.SendToPrimary(payload)
}

// ForwardToSpecific forwards data to a specific connector
func (f *DataForwarder) ForwardToSpecific(connectorName, clientID, tableName string, data map[string]interface{}) (*APIResponse, error) {
	conn, err := f.pool.GetConnector(connectorName)
	if err != nil {
		return nil, err
	}

	payload := DataPayload{
		RecordID:  generateRecordID(),
		TableName: tableName,
		Operation: "INSERT",
		Data:      data,
		ClientID:  clientID,
		Timestamp: time.Now(),
	}

	return conn.Send(payload)
}

// generateRecordID generates a unique record ID
func generateRecordID() string {
	return fmt.Sprintf("WFX-%d", time.Now().UnixNano())
}

// WebhookConfig for webhook-based integrations
type WebhookConfig struct {
	URL         string            `json:"url"`
	Method      string            `json:"method"` // POST, PUT
	Headers     map[string]string `json:"headers"`
	SecretKey   string            `json:"secret_key"`
	ContentType string            `json:"content_type"`
	Enabled     bool              `json:"enabled"`
}

// WebhookConnector for webhook-based database integrations
type WebhookConnector struct {
	config     WebhookConfig
	httpClient *http.Client
}

// NewWebhookConnector creates a webhook connector
func NewWebhookConnector(config WebhookConfig) *WebhookConnector {
	if config.Method == "" {
		config.Method = "POST"
	}
	if config.ContentType == "" {
		config.ContentType = "application/json"
	}

	return &WebhookConnector{
		config: config,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Send sends data via webhook
func (w *WebhookConnector) Send(payload DataPayload) (*APIResponse, error) {
	if !w.config.Enabled {
		return nil, fmt.Errorf("webhook is disabled")
	}

	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(w.config.Method, w.config.URL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", w.config.ContentType)
	if w.config.SecretKey != "" {
		req.Header.Set("X-Webhook-Secret", w.config.SecretKey)
	}

	for key, value := range w.config.Headers {
		req.Header.Set(key, value)
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return &APIResponse{
		Success:   resp.StatusCode >= 200 && resp.StatusCode < 300,
		Message:   fmt.Sprintf("Webhook returned status %d", resp.StatusCode),
		Timestamp: time.Now(),
	}, nil
}

// BatchPayload for sending multiple records at once
type BatchPayload struct {
	ClientID  string        `json:"client_id"`
	TableName string        `json:"table_name"`
	Records   []DataPayload `json:"records"`
	Timestamp time.Time     `json:"timestamp"`
}

// SendBatch sends multiple records in a single API call
func (u *UniversalDBConnector) SendBatch(batch BatchPayload) (*APIResponse, error) {
	if !u.config.Enabled {
		return nil, fmt.Errorf("connector %s is disabled", u.config.Name)
	}

	batch.Timestamp = time.Now()

	jsonData, err := json.Marshal(batch)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch: %v", err)
	}

	return u.makeRequest("POST", u.config.APIEndpoint+"/batch", jsonData)
}

// StreamConfig for real-time data streaming
type StreamConfig struct {
	BufferSize    int           `json:"buffer_size"`
	FlushInterval time.Duration `json:"flush_interval"`
	MaxRetries    int           `json:"max_retries"`
}

// DataStream handles streaming data to client databases
type DataStream struct {
	connector   DatabaseConnector
	buffer      []DataPayload
	config      StreamConfig
	flushTicker *time.Ticker
	stopChan    chan struct{}
}

// NewDataStream creates a new data stream
func NewDataStream(connector DatabaseConnector, config StreamConfig) *DataStream {
	if config.BufferSize == 0 {
		config.BufferSize = 100
	}
	if config.FlushInterval == 0 {
		config.FlushInterval = 5 * time.Second
	}

	return &DataStream{
		connector: connector,
		buffer:    make([]DataPayload, 0, config.BufferSize),
		config:    config,
		stopChan:  make(chan struct{}),
	}
}

// Start begins the data stream
func (s *DataStream) Start() {
	s.flushTicker = time.NewTicker(s.config.FlushInterval)
	go func() {
		for {
			select {
			case <-s.flushTicker.C:
				s.Flush()
			case <-s.stopChan:
				s.flushTicker.Stop()
				s.Flush() // Final flush
				return
			}
		}
	}()
}

// Stop stops the data stream
func (s *DataStream) Stop() {
	close(s.stopChan)
}

// Add adds a payload to the stream buffer
func (s *DataStream) Add(payload DataPayload) {
	s.buffer = append(s.buffer, payload)
	if len(s.buffer) >= s.config.BufferSize {
		s.Flush()
	}
}

// Flush sends all buffered data to the database
func (s *DataStream) Flush() error {
	if len(s.buffer) == 0 {
		return nil
	}

	// Send each payload (in production, use batch API)
	for _, payload := range s.buffer {
		_, err := s.connector.Send(payload)
		if err != nil {
			// Log error but continue
			continue
		}
	}

	// Clear buffer
	s.buffer = s.buffer[:0]
	return nil
}
