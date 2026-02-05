-- Wolfronix v1.0 Database Schema
-- Run this in PostgreSQL to set up all required tables

-- 1. Secure Storage (Production) - Core encrypted data storage
CREATE TABLE IF NOT EXISTS secure_storage (
    id SERIAL PRIMARY KEY,
    filename VARCHAR(255) NOT NULL,
    encrypted_data BYTEA NOT NULL,
    key_part_a TEXT NOT NULL,          -- Share A: Encrypted with User's RSA key
    key_part_b TEXT NOT NULL,          -- Share B: Encrypted with Server's RSA key
    iv VARCHAR(64) NOT NULL,           -- AES IV (Base64)
    enc_time_ms INT DEFAULT 0,         -- Encryption time in milliseconds
    client_id VARCHAR(255),            -- Client identifier
    user_id VARCHAR(255),              -- User who encrypted
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_secure_storage_client ON secure_storage(client_id);
CREATE INDEX IF NOT EXISTS idx_secure_storage_user ON secure_storage(user_id);

-- 2. Dev Storage (Layer 1) - Fake data for development environments
CREATE TABLE IF NOT EXISTS dev_storage (
    id SERIAL PRIMARY KEY,
    prod_file_id INT REFERENCES secure_storage(id) ON DELETE CASCADE,
    filename VARCHAR(255) NOT NULL,
    fake_data BYTEA NOT NULL,          -- Synthetic/fake data
    client_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_dev_storage_prod ON dev_storage(prod_file_id);
CREATE INDEX IF NOT EXISTS idx_dev_storage_client ON dev_storage(client_id);

-- 3. User Keys (Zero-Knowledge) - Wrapped private keys
CREATE TABLE IF NOT EXISTS user_keys (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    public_key_pem TEXT NOT NULL,
    encrypted_private_key TEXT NOT NULL,  -- Wrapped with user's password
    salt VARCHAR(64) NOT NULL,            -- PBKDF2 salt
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(client_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_user_keys_client_user ON user_keys(client_id, user_id);

-- 4. Client Metrics - Per-client statistics
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

-- 5. Client Users - Track users per client
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

CREATE INDEX IF NOT EXISTS idx_client_users_client ON client_users(client_id);

-- 6. Encryption Logs - Detailed operation logs
CREATE TABLE IF NOT EXISTS encryption_logs (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    user_id VARCHAR(255),
    operation VARCHAR(20) NOT NULL,    -- 'encrypt' or 'decrypt'
    record_count INT DEFAULT 1,
    duration_ms INT NOT NULL,
    data_size_bytes BIGINT,
    status VARCHAR(20) DEFAULT 'success',
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_encryption_logs_client ON encryption_logs(client_id);
CREATE INDEX IF NOT EXISTS idx_encryption_logs_created ON encryption_logs(created_at);

-- Add any missing columns to existing tables (for upgrades)
DO $$
BEGIN
    -- Add client_id to secure_storage if missing
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'secure_storage' AND column_name = 'client_id') THEN
        ALTER TABLE secure_storage ADD COLUMN client_id VARCHAR(255);
    END IF;
    
    -- Add user_id to secure_storage if missing
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name = 'secure_storage' AND column_name = 'user_id') THEN
        ALTER TABLE secure_storage ADD COLUMN user_id VARCHAR(255);
    END IF;
END $$;
