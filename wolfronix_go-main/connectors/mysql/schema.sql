-- ============================================================================
-- Wolfronix MySQL Schema
-- Run this against your MySQL database
-- ============================================================================

CREATE DATABASE IF NOT EXISTS wolfronix CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE wolfronix;

-- Encrypted file metadata
CREATE TABLE IF NOT EXISTS wolfronix_files (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    filename        VARCHAR(500) NOT NULL,
    file_size       BIGINT DEFAULT 0,
    key_part_a      TEXT NOT NULL,
    key_part_b      TEXT NOT NULL,
    iv              TEXT NOT NULL,
    enc_time_ms     BIGINT DEFAULT 0,
    client_id       VARCHAR(255) NOT NULL,
    user_id         VARCHAR(255) NOT NULL,
    storage_type    VARCHAR(50) DEFAULT 'blob',
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_client_user (client_id, user_id),
    INDEX idx_client (client_id)
) ENGINE=InnoDB;

-- Encrypted file binary data
CREATE TABLE IF NOT EXISTS wolfronix_file_data (
    file_id         BIGINT PRIMARY KEY,
    encrypted_data  LONGBLOB NOT NULL,
    FOREIGN KEY (file_id) REFERENCES wolfronix_files(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- User encryption keys (wrapped)
CREATE TABLE IF NOT EXISTS wolfronix_keys (
    user_id                 VARCHAR(255) NOT NULL,
    client_id               VARCHAR(255) NOT NULL,
    public_key_pem          TEXT NOT NULL,
    encrypted_private_key   TEXT NOT NULL,
    salt                    TEXT NOT NULL,
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, client_id),
    INDEX idx_client (client_id)
) ENGINE=InnoDB;

-- Dev/fake data (Layer 1)
CREATE TABLE IF NOT EXISTS wolfronix_dev_files (
    id              BIGINT AUTO_INCREMENT PRIMARY KEY,
    prod_file_id    BIGINT,
    filename        VARCHAR(500),
    fake_data       LONGBLOB,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;
