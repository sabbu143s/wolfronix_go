package clientdb

import (
	"database/sql"
	"errors"
	"log"
	"time"
)

// ClientRegistry manages client configurations in Wolfronix DB
// This is the ONLY user-related data Wolfronix stores locally
type ClientRegistry struct {
	db *sql.DB
}

// RegisteredClient represents a client registered with Wolfronix
type RegisteredClient struct {
	ID           int64     `json:"id"`
	ClientID     string    `json:"client_id"`
	ClientName   string    `json:"client_name"`
	APIEndpoint  string    `json:"api_endpoint"`  // Client's storage API URL
	APIKey       string    `json:"api_key"`       // Key to authenticate with client's API
	WolfronixKey string    `json:"wolfronix_key"` // Key client uses to call Wolfronix
	UserCount    int       `json:"user_count"`    // Number of registered users
	IsActive     bool      `json:"is_active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// NewClientRegistry creates a new client registry
func NewClientRegistry(db *sql.DB) (*ClientRegistry, error) {
	registry := &ClientRegistry{db: db}
	if err := registry.initDB(); err != nil {
		return nil, err
	}
	return registry, nil
}

// initDB creates the client registry tables
func (r *ClientRegistry) initDB() error {
	query := `
	-- Main client registry table (Wolfronix DB only stores this)
	CREATE TABLE IF NOT EXISTS client_registry (
		id SERIAL PRIMARY KEY,
		client_id VARCHAR(255) UNIQUE NOT NULL,
		client_name VARCHAR(255) NOT NULL,
		api_endpoint TEXT NOT NULL,
		api_key TEXT NOT NULL,
		wolfronix_key VARCHAR(255) UNIQUE NOT NULL,
		user_count INTEGER DEFAULT 0,
		is_active BOOLEAN DEFAULT true,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_client_registry_client_id ON client_registry(client_id);
	CREATE INDEX IF NOT EXISTS idx_client_registry_wolfronix_key ON client_registry(wolfronix_key);
	`
	_, err := r.db.Exec(query)
	if err != nil {
		return err
	}
	log.Println("📋 Client Registry Tables Initialized!")
	return nil
}

// RegisterClient registers a new client with Wolfronix
func (r *ClientRegistry) RegisterClient(client *RegisteredClient) error {
	query := `
		INSERT INTO client_registry (client_id, client_name, api_endpoint, api_key, wolfronix_key, is_active)
		VALUES ($1, $2, $3, $4, $5, true)
		ON CONFLICT (client_id) DO UPDATE SET
			client_name = EXCLUDED.client_name,
			api_endpoint = EXCLUDED.api_endpoint,
			api_key = EXCLUDED.api_key,
			wolfronix_key = EXCLUDED.wolfronix_key,
			updated_at = CURRENT_TIMESTAMP
		RETURNING id
	`
	err := r.db.QueryRow(query,
		client.ClientID,
		client.ClientName,
		client.APIEndpoint,
		client.APIKey,
		client.WolfronixKey,
	).Scan(&client.ID)

	if err != nil {
		return err
	}

	log.Printf("✅ Registered client: %s (ID: %d)", client.ClientID, client.ID)
	return nil
}

// GetClient retrieves a client by client_id
func (r *ClientRegistry) GetClient(clientID string) (*RegisteredClient, error) {
	query := `
		SELECT id, client_id, client_name, api_endpoint, api_key, wolfronix_key, 
		       user_count, is_active, created_at, updated_at
		FROM client_registry
		WHERE client_id = $1 AND is_active = true
	`
	var client RegisteredClient
	err := r.db.QueryRow(query, clientID).Scan(
		&client.ID,
		&client.ClientID,
		&client.ClientName,
		&client.APIEndpoint,
		&client.APIKey,
		&client.WolfronixKey,
		&client.UserCount,
		&client.IsActive,
		&client.CreatedAt,
		&client.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, errors.New("client not found")
	}
	if err != nil {
		return nil, err
	}
	return &client, nil
}

// GetClientByWolfronixKey retrieves a client by their Wolfronix API key
func (r *ClientRegistry) GetClientByWolfronixKey(wolfronixKey string) (*RegisteredClient, error) {
	query := `
		SELECT id, client_id, client_name, api_endpoint, api_key, wolfronix_key, 
		       user_count, is_active, created_at, updated_at
		FROM client_registry
		WHERE wolfronix_key = $1 AND is_active = true
	`
	var client RegisteredClient
	err := r.db.QueryRow(query, wolfronixKey).Scan(
		&client.ID,
		&client.ClientID,
		&client.ClientName,
		&client.APIEndpoint,
		&client.APIKey,
		&client.WolfronixKey,
		&client.UserCount,
		&client.IsActive,
		&client.CreatedAt,
		&client.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return nil, errors.New("invalid API key")
	}
	if err != nil {
		return nil, err
	}
	return &client, nil
}

// GetClientConfig returns a ClientConfig for use with ClientDBConnector
func (r *ClientRegistry) GetClientConfig(clientID string) (*ClientConfig, error) {
	client, err := r.GetClient(clientID)
	if err != nil {
		return nil, err
	}

	return &ClientConfig{
		ClientID:    client.ClientID,
		APIEndpoint: client.APIEndpoint,
		APIKey:      client.APIKey,
		Timeout:     30 * time.Second,
	}, nil
}

// IncrementUserCount increments the user count for a client
func (r *ClientRegistry) IncrementUserCount(clientID string) error {
	query := `
		UPDATE client_registry 
		SET user_count = user_count + 1, updated_at = CURRENT_TIMESTAMP
		WHERE client_id = $1
	`
	_, err := r.db.Exec(query, clientID)
	return err
}

// DecrementUserCount decrements the user count for a client
func (r *ClientRegistry) DecrementUserCount(clientID string) error {
	query := `
		UPDATE client_registry 
		SET user_count = GREATEST(user_count - 1, 0), updated_at = CURRENT_TIMESTAMP
		WHERE client_id = $1
	`
	_, err := r.db.Exec(query, clientID)
	return err
}

// ListClients returns all active clients
func (r *ClientRegistry) ListClients() ([]RegisteredClient, error) {
	query := `
		SELECT id, client_id, client_name, api_endpoint, '', wolfronix_key, 
		       user_count, is_active, created_at, updated_at
		FROM client_registry
		WHERE is_active = true
		ORDER BY created_at DESC
	`
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []RegisteredClient
	for rows.Next() {
		var client RegisteredClient
		err := rows.Scan(
			&client.ID,
			&client.ClientID,
			&client.ClientName,
			&client.APIEndpoint,
			&client.APIKey, // Empty for security
			&client.WolfronixKey,
			&client.UserCount,
			&client.IsActive,
			&client.CreatedAt,
			&client.UpdatedAt,
		)
		if err != nil {
			continue
		}
		clients = append(clients, client)
	}

	return clients, nil
}

// DeactivateClient marks a client as inactive
func (r *ClientRegistry) DeactivateClient(clientID string) error {
	query := `
		UPDATE client_registry 
		SET is_active = false, updated_at = CURRENT_TIMESTAMP
		WHERE client_id = $1
	`
	_, err := r.db.Exec(query, clientID)
	return err
}

// UpdateClientEndpoint updates a client's API endpoint
func (r *ClientRegistry) UpdateClientEndpoint(clientID, newEndpoint string) error {
	query := `
		UPDATE client_registry 
		SET api_endpoint = $2, updated_at = CURRENT_TIMESTAMP
		WHERE client_id = $1
	`
	_, err := r.db.Exec(query, clientID, newEndpoint)
	return err
}
