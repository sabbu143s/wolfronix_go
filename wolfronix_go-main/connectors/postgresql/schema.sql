-- ============================================================================
-- Wolfronix PostgreSQL Schema
-- Run: psql -U your_user -d wolfronix -f schema.sql
-- ============================================================================

-- Encrypted file metadata
CREATE TABLE IF NOT EXISTS wolfronix_files (
    id              BIGSERIAL PRIMARY KEY,
    filename        TEXT NOT NULL,
    file_size       BIGINT DEFAULT 0,
    key_part_a      TEXT NOT NULL,
    key_part_b      TEXT NOT NULL,
    iv              TEXT NOT NULL,
    enc_time_ms     BIGINT DEFAULT 0,
    client_id       TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    storage_type    TEXT DEFAULT 'blob',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Encrypted file binary data (stored separately for performance)
CREATE TABLE IF NOT EXISTS wolfronix_file_data (
    file_id         BIGINT PRIMARY KEY REFERENCES wolfronix_files(id) ON DELETE CASCADE,
    encrypted_data  BYTEA NOT NULL
);

-- User encryption keys (wrapped keys stored per user)
CREATE TABLE IF NOT EXISTS wolfronix_keys (
    user_id                 TEXT NOT NULL,
    client_id               TEXT NOT NULL,
    public_key_pem          TEXT NOT NULL,
    encrypted_private_key   TEXT NOT NULL,
    salt                    TEXT NOT NULL,
    created_at              TIMESTAMPTZ DEFAULT NOW(),
    PRIMARY KEY (user_id, client_id)
);

-- Dev/fake data (Layer 1 - for development environments)
CREATE TABLE IF NOT EXISTS wolfronix_dev_files (
    id              BIGSERIAL PRIMARY KEY,
    prod_file_id    BIGINT,
    filename        TEXT,
    fake_data       BYTEA,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes for fast lookups
CREATE INDEX IF NOT EXISTS idx_wolfronix_files_user ON wolfronix_files(client_id, user_id);
CREATE INDEX IF NOT EXISTS idx_wolfronix_files_client ON wolfronix_files(client_id);
CREATE INDEX IF NOT EXISTS idx_wolfronix_keys_client ON wolfronix_keys(client_id);
