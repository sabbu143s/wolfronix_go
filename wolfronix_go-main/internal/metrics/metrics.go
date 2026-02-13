package metrics

import (
	"database/sql"
	"sync"
	"time"
)

// ClientMetrics holds real-time metrics for a client
type ClientMetrics struct {
	ClientID           string    `json:"client_id"`
	RecordsEncrypted   int64     `json:"records_encrypted"`
	RecordsDecrypted   int64     `json:"records_decrypted"`
	TotalEncryptTimeMs int64     `json:"total_encrypt_time_ms"`
	TotalDecryptTimeMs int64     `json:"total_decrypt_time_ms"`
	AvgEncryptTimeMs   float64   `json:"avg_encrypt_time_ms"`
	AvgDecryptTimeMs   float64   `json:"avg_decrypt_time_ms"`
	ActiveUsers        int       `json:"active_users"`
	TotalUsers         int       `json:"total_users"`
	LastActivity       time.Time `json:"last_activity"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// MetricsStore manages client metrics with thread-safe operations
type MetricsStore struct {
	db      *sql.DB
	cache   map[string]*ClientMetrics
	mu      sync.RWMutex
	flushCh chan string
	done    chan struct{}
}

// NewMetricsStore creates a new metrics store
func NewMetricsStore(db *sql.DB) (*MetricsStore, error) {
	store := &MetricsStore{
		db:      db,
		cache:   make(map[string]*ClientMetrics),
		flushCh: make(chan string, 100),
		done:    make(chan struct{}),
	}

	// Initialize database table
	if err := store.initDB(); err != nil {
		return nil, err
	}

	// Start background flush worker
	go store.flushWorker()

	return store, nil
}

// initDB creates the metrics table if it doesn't exist
func (s *MetricsStore) initDB() error {
	query := `
	CREATE TABLE IF NOT EXISTS client_metrics (
		client_id VARCHAR(255) PRIMARY KEY,
		records_encrypted BIGINT DEFAULT 0,
		records_decrypted BIGINT DEFAULT 0,
		total_encrypt_time_ms BIGINT DEFAULT 0,
		total_decrypt_time_ms BIGINT DEFAULT 0,
		active_users INT DEFAULT 0,
		total_users INT DEFAULT 0,
		last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS client_users (
		id SERIAL PRIMARY KEY,
		client_id VARCHAR(255) NOT NULL,
		user_id VARCHAR(255) NOT NULL,
		role VARCHAR(50) DEFAULT 'guest',
		is_active BOOLEAN DEFAULT true,
		last_login TIMESTAMP,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(client_id, user_id)
	);

	CREATE TABLE IF NOT EXISTS encryption_logs (
		id SERIAL PRIMARY KEY,
		client_id VARCHAR(255) NOT NULL,
		user_id VARCHAR(255),
		operation VARCHAR(20) NOT NULL,
		record_count INT DEFAULT 1,
		duration_ms INT NOT NULL,
		data_size_bytes BIGINT,
		status VARCHAR(20) DEFAULT 'success',
		error_message TEXT,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_encryption_logs_client ON encryption_logs(client_id);
	CREATE INDEX IF NOT EXISTS idx_encryption_logs_created ON encryption_logs(created_at);
	CREATE INDEX IF NOT EXISTS idx_client_users_client ON client_users(client_id);
	`

	_, err := s.db.Exec(query)
	return err
}

// RecordEncryption records an encryption operation
func (s *MetricsStore) RecordEncryption(clientID, userID string, durationMs int64, recordCount int, dataSizeBytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get or create client metrics
	metrics := s.getOrCreateMetrics(clientID)

	// Update metrics
	metrics.RecordsEncrypted += int64(recordCount)
	metrics.TotalEncryptTimeMs += durationMs
	metrics.AvgEncryptTimeMs = float64(metrics.TotalEncryptTimeMs) / float64(metrics.RecordsEncrypted)
	metrics.LastActivity = time.Now()
	metrics.UpdatedAt = time.Now()

	// Log the operation
	go s.logOperation(clientID, userID, "encrypt", recordCount, int(durationMs), dataSizeBytes, "success", "")

	// Queue flush
	select {
	case s.flushCh <- clientID:
	default:
		// Channel full, will be flushed later
	}
}

// RecordDecryption records a decryption operation
func (s *MetricsStore) RecordDecryption(clientID, userID string, durationMs int64, recordCount int, dataSizeBytes int64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get or create client metrics
	metrics := s.getOrCreateMetrics(clientID)

	// Update metrics
	metrics.RecordsDecrypted += int64(recordCount)
	metrics.TotalDecryptTimeMs += durationMs
	metrics.AvgDecryptTimeMs = float64(metrics.TotalDecryptTimeMs) / float64(metrics.RecordsDecrypted)
	metrics.LastActivity = time.Now()
	metrics.UpdatedAt = time.Now()

	// Log the operation
	go s.logOperation(clientID, userID, "decrypt", recordCount, int(durationMs), dataSizeBytes, "success", "")

	// Queue flush
	select {
	case s.flushCh <- clientID:
	default:
	}
}

// RecordError records a failed operation
func (s *MetricsStore) RecordError(clientID, userID, operation string, errorMsg string) {
	go s.logOperation(clientID, userID, operation, 0, 0, 0, "error", errorMsg)
}

// AddUser adds a user to a client
func (s *MetricsStore) AddUser(clientID, userID, role string) error {
	query := `
		INSERT INTO client_users (client_id, user_id, role, is_active, last_login)
		VALUES ($1, $2, $3, true, CURRENT_TIMESTAMP)
		ON CONFLICT (client_id, user_id) DO UPDATE SET
			role = $3,
			is_active = true,
			last_login = CURRENT_TIMESTAMP
	`
	_, err := s.db.Exec(query, clientID, userID, role)
	if err != nil {
		return err
	}

	// Update user count in cache
	s.mu.Lock()
	if metrics, exists := s.cache[clientID]; exists {
		metrics.TotalUsers++
		metrics.ActiveUsers++
	}
	s.mu.Unlock()

	return s.updateUserCounts(clientID)
}

// RemoveUser deactivates a user
func (s *MetricsStore) RemoveUser(clientID, userID string) error {
	query := `UPDATE client_users SET is_active = false WHERE client_id = $1 AND user_id = $2`
	_, err := s.db.Exec(query, clientID, userID)
	if err != nil {
		return err
	}
	return s.updateUserCounts(clientID)
}

// RecordUserLogin records a user login
func (s *MetricsStore) RecordUserLogin(clientID, userID string) error {
	query := `UPDATE client_users SET last_login = CURRENT_TIMESTAMP WHERE client_id = $1 AND user_id = $2`
	_, err := s.db.Exec(query, clientID, userID)
	return err
}

// GetClientMetrics returns metrics for a specific client
func (s *MetricsStore) GetClientMetrics(clientID string) (*ClientMetrics, error) {
	// Check cache first
	s.mu.RLock()
	if metrics, exists := s.cache[clientID]; exists {
		s.mu.RUnlock()
		return metrics, nil
	}
	s.mu.RUnlock()

	// Load from database
	return s.loadMetricsFromDB(clientID)
}

// GetAllClientMetrics returns metrics for all clients
func (s *MetricsStore) GetAllClientMetrics() ([]*ClientMetrics, error) {
	query := `
		SELECT 
			client_id, records_encrypted, records_decrypted,
			total_encrypt_time_ms, total_decrypt_time_ms,
			active_users, total_users,
			last_activity, created_at, updated_at
		FROM client_metrics
		ORDER BY last_activity DESC
	`

	rows, err := s.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*ClientMetrics
	for rows.Next() {
		m := &ClientMetrics{}
		err := rows.Scan(
			&m.ClientID, &m.RecordsEncrypted, &m.RecordsDecrypted,
			&m.TotalEncryptTimeMs, &m.TotalDecryptTimeMs,
			&m.ActiveUsers, &m.TotalUsers,
			&m.LastActivity, &m.CreatedAt, &m.UpdatedAt,
		)
		if err != nil {
			continue
		}

		// Calculate averages
		if m.RecordsEncrypted > 0 {
			m.AvgEncryptTimeMs = float64(m.TotalEncryptTimeMs) / float64(m.RecordsEncrypted)
		}
		if m.RecordsDecrypted > 0 {
			m.AvgDecryptTimeMs = float64(m.TotalDecryptTimeMs) / float64(m.RecordsDecrypted)
		}

		results = append(results, m)
	}

	return results, nil
}

// GetMetricsSummary returns a summary across all clients
func (s *MetricsStore) GetMetricsSummary() (*MetricsSummary, error) {
	query := `
		SELECT 
			COUNT(DISTINCT client_id) as total_clients,
			COALESCE(SUM(records_encrypted), 0) as total_encrypted,
			COALESCE(SUM(records_decrypted), 0) as total_decrypted,
			COALESCE(SUM(total_encrypt_time_ms), 0) as total_encrypt_time,
			COALESCE(SUM(total_decrypt_time_ms), 0) as total_decrypt_time,
			COALESCE(SUM(total_users), 0) as total_users,
			COALESCE(SUM(active_users), 0) as active_users
		FROM client_metrics
	`

	summary := &MetricsSummary{}
	err := s.db.QueryRow(query).Scan(
		&summary.TotalClients,
		&summary.TotalRecordsEncrypted,
		&summary.TotalRecordsDecrypted,
		&summary.TotalEncryptTimeMs,
		&summary.TotalDecryptTimeMs,
		&summary.TotalUsers,
		&summary.ActiveUsers,
	)
	if err != nil {
		return nil, err
	}

	// Calculate averages
	if summary.TotalRecordsEncrypted > 0 {
		summary.AvgEncryptTimeMs = float64(summary.TotalEncryptTimeMs) / float64(summary.TotalRecordsEncrypted)
	}
	if summary.TotalRecordsDecrypted > 0 {
		summary.AvgDecryptTimeMs = float64(summary.TotalDecryptTimeMs) / float64(summary.TotalRecordsDecrypted)
	}

	return summary, nil
}

// MetricsSummary holds aggregate metrics across all clients
type MetricsSummary struct {
	TotalClients          int     `json:"total_clients"`
	TotalRecordsEncrypted int64   `json:"total_records_encrypted"`
	TotalRecordsDecrypted int64   `json:"total_records_decrypted"`
	TotalEncryptTimeMs    int64   `json:"total_encrypt_time_ms"`
	TotalDecryptTimeMs    int64   `json:"total_decrypt_time_ms"`
	AvgEncryptTimeMs      float64 `json:"avg_encrypt_time_ms"`
	AvgDecryptTimeMs      float64 `json:"avg_decrypt_time_ms"`
	TotalUsers            int     `json:"total_users"`
	ActiveUsers           int     `json:"active_users"`
}

// GetClientStats returns detailed statistics for a time range
func (s *MetricsStore) GetClientStats(clientID string, from, to time.Time) (*ClientStats, error) {
	query := `
		SELECT 
			operation,
			COUNT(*) as count,
			COALESCE(SUM(record_count), 0) as total_records,
			COALESCE(AVG(duration_ms), 0) as avg_duration,
			COALESCE(MIN(duration_ms), 0) as min_duration,
			COALESCE(MAX(duration_ms), 0) as max_duration,
			COALESCE(SUM(data_size_bytes), 0) as total_bytes
		FROM encryption_logs
		WHERE client_id = $1 AND created_at BETWEEN $2 AND $3
		GROUP BY operation
	`

	rows, err := s.db.Query(query, clientID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := &ClientStats{
		ClientID: clientID,
		From:     from,
		To:       to,
	}

	for rows.Next() {
		var op string
		var opStats OperationStats
		err := rows.Scan(&op, &opStats.Count, &opStats.TotalRecords, &opStats.AvgDurationMs, &opStats.MinDurationMs, &opStats.MaxDurationMs, &opStats.TotalBytes)
		if err != nil {
			continue
		}

		switch op {
		case "encrypt":
			stats.Encryption = opStats
		case "decrypt":
			stats.Decryption = opStats
		}
	}

	return stats, nil
}

// ClientStats holds detailed statistics for a time range
type ClientStats struct {
	ClientID   string         `json:"client_id"`
	From       time.Time      `json:"from"`
	To         time.Time      `json:"to"`
	Encryption OperationStats `json:"encryption"`
	Decryption OperationStats `json:"decryption"`
}

// OperationStats holds statistics for a single operation type
type OperationStats struct {
	Count         int     `json:"count"`
	TotalRecords  int64   `json:"total_records"`
	AvgDurationMs float64 `json:"avg_duration_ms"`
	MinDurationMs int     `json:"min_duration_ms"`
	MaxDurationMs int     `json:"max_duration_ms"`
	TotalBytes    int64   `json:"total_bytes"`
}

// --- Helper Methods ---

func (s *MetricsStore) getOrCreateMetrics(clientID string) *ClientMetrics {
	if metrics, exists := s.cache[clientID]; exists {
		return metrics
	}

	// Load from DB or create new
	metrics, err := s.loadMetricsFromDB(clientID)
	if err != nil || metrics == nil {
		metrics = &ClientMetrics{
			ClientID:  clientID,
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
	}

	s.cache[clientID] = metrics
	return metrics
}

func (s *MetricsStore) loadMetricsFromDB(clientID string) (*ClientMetrics, error) {
	query := `
		SELECT 
			client_id, records_encrypted, records_decrypted,
			total_encrypt_time_ms, total_decrypt_time_ms,
			active_users, total_users,
			last_activity, created_at, updated_at
		FROM client_metrics
		WHERE client_id = $1
	`

	m := &ClientMetrics{}
	err := s.db.QueryRow(query, clientID).Scan(
		&m.ClientID, &m.RecordsEncrypted, &m.RecordsDecrypted,
		&m.TotalEncryptTimeMs, &m.TotalDecryptTimeMs,
		&m.ActiveUsers, &m.TotalUsers,
		&m.LastActivity, &m.CreatedAt, &m.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	// Calculate averages
	if m.RecordsEncrypted > 0 {
		m.AvgEncryptTimeMs = float64(m.TotalEncryptTimeMs) / float64(m.RecordsEncrypted)
	}
	if m.RecordsDecrypted > 0 {
		m.AvgDecryptTimeMs = float64(m.TotalDecryptTimeMs) / float64(m.RecordsDecrypted)
	}

	return m, nil
}

func (s *MetricsStore) logOperation(clientID, userID, operation string, recordCount, durationMs int, dataSizeBytes int64, status, errorMsg string) {
	query := `
		INSERT INTO encryption_logs (client_id, user_id, operation, record_count, duration_ms, data_size_bytes, status, error_message)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	s.db.Exec(query, clientID, userID, operation, recordCount, durationMs, dataSizeBytes, status, errorMsg)
}

func (s *MetricsStore) updateUserCounts(clientID string) error {
	query := `
		SELECT 
			COUNT(*) as total,
			COUNT(*) FILTER (WHERE is_active = true) as active
		FROM client_users
		WHERE client_id = $1
	`

	var total, active int
	err := s.db.QueryRow(query, clientID).Scan(&total, &active)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if metrics, exists := s.cache[clientID]; exists {
		metrics.TotalUsers = total
		metrics.ActiveUsers = active
	}
	s.mu.Unlock()

	// Update database
	updateQuery := `
		UPDATE client_metrics 
		SET total_users = $2, active_users = $3, updated_at = CURRENT_TIMESTAMP
		WHERE client_id = $1
	`
	_, err = s.db.Exec(updateQuery, clientID, total, active)
	return err
}

// flushWorker periodically saves metrics to database
func (s *MetricsStore) flushWorker() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	pendingFlush := make(map[string]bool)

	for {
		select {
		case <-s.done:
			// Flush remaining before exit
			for clientID := range pendingFlush {
				s.flushToDB(clientID)
			}
			return
		case clientID := <-s.flushCh:
			pendingFlush[clientID] = true

		case <-ticker.C:
			for clientID := range pendingFlush {
				s.flushToDB(clientID)
				delete(pendingFlush, clientID)
			}
		}
	}
}

func (s *MetricsStore) flushToDB(clientID string) {
	s.mu.RLock()
	metrics, exists := s.cache[clientID]
	if !exists {
		s.mu.RUnlock()
		return
	}
	// Copy values to avoid holding lock during DB operation
	m := *metrics
	s.mu.RUnlock()

	query := `
		INSERT INTO client_metrics (
			client_id, records_encrypted, records_decrypted,
			total_encrypt_time_ms, total_decrypt_time_ms,
			active_users, total_users, last_activity, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (client_id) DO UPDATE SET
			records_encrypted = $2,
			records_decrypted = $3,
			total_encrypt_time_ms = $4,
			total_decrypt_time_ms = $5,
			active_users = $6,
			total_users = $7,
			last_activity = $8,
			updated_at = $9
	`

	s.db.Exec(query,
		m.ClientID, m.RecordsEncrypted, m.RecordsDecrypted,
		m.TotalEncryptTimeMs, m.TotalDecryptTimeMs,
		m.ActiveUsers, m.TotalUsers, m.LastActivity, m.UpdatedAt,
	)
}

// Close flushes all pending metrics and shuts down the flush worker
func (s *MetricsStore) Close() {
	close(s.done) // Signal flushWorker to stop

	s.mu.RLock()
	clients := make([]string, 0, len(s.cache))
	for clientID := range s.cache {
		clients = append(clients, clientID)
	}
	s.mu.RUnlock()

	for _, clientID := range clients {
		s.flushToDB(clientID)
	}
}
