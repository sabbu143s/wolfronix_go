package keywrap

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// PBKDF2 parameters
	pbkdf2Iterations = 100000
	saltSize         = 32
	keySize          = 32 // AES-256
)

// WrappedKey represents an encrypted private key stored in the database
type WrappedKey struct {
	UserID                   string    `json:"user_id"`
	ClientID                 string    `json:"client_id"`
	PublicKeyPEM             string    `json:"public_key_pem"`
	EncryptedPrivKey         string    `json:"encrypted_private_key"`          // Base64 encoded (password-wrapped)
	Salt                     string    `json:"salt"`                           // Hex encoded salt for password wrapping
	RecoveryEncryptedPrivKey string    `json:"recovery_encrypted_private_key"` // Base64 encoded (mnemonic-wrapped)
	RecoverySalt             string    `json:"recovery_salt"`                  // Hex encoded salt for mnemonic wrapping
	CreatedAt                time.Time `json:"created_at"`
	UpdatedAt                time.Time `json:"updated_at"`
}

// KeyWrapStore manages encrypted key storage
type KeyWrapStore struct {
	db *sql.DB
}

// NewKeyWrapStore creates a new key wrap store
func NewKeyWrapStore(db *sql.DB) (*KeyWrapStore, error) {
	store := &KeyWrapStore{db: db}
	if err := store.initDB(); err != nil {
		return nil, err
	}
	return store, nil
}

// initDB creates the user_keys table if it doesn't exist
func (s *KeyWrapStore) initDB() error {
	query := `
	CREATE TABLE IF NOT EXISTS user_keys (
		id SERIAL PRIMARY KEY,
		user_id VARCHAR(255) NOT NULL,
		client_id VARCHAR(255) NOT NULL,
		public_key_pem TEXT NOT NULL,
		encrypted_private_key TEXT NOT NULL,
		salt VARCHAR(64) NOT NULL,
		recovery_encrypted_private_key TEXT DEFAULT '',
		recovery_salt VARCHAR(64) DEFAULT '',
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(client_id, user_id)
	);

	CREATE INDEX IF NOT EXISTS idx_user_keys_client_user ON user_keys(client_id, user_id);
	`
	if _, err := s.db.Exec(query); err != nil {
		return err
	}

	// Add recovery columns if they don't exist (migration for existing databases)
	migrations := []string{
		`ALTER TABLE user_keys ADD COLUMN IF NOT EXISTS recovery_encrypted_private_key TEXT DEFAULT ''`,
		`ALTER TABLE user_keys ADD COLUMN IF NOT EXISTS recovery_salt VARCHAR(64) DEFAULT ''`,
	}
	for _, m := range migrations {
		s.db.Exec(m) // Ignore errors — column may already exist
	}

	return nil
}

// DeriveKeyFromPassword derives a 256-bit key from password using PBKDF2
func DeriveKeyFromPassword(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, pbkdf2Iterations, keySize, sha256.New)
}

// GenerateSalt generates a cryptographically secure random salt
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// WrapPrivateKey encrypts a private key with a password-derived key
// Returns: encryptedKey (base64), salt (base64), error
func WrapPrivateKey(privateKeyPEM string, password string) (string, string, error) {
	// 1. Generate random salt
	salt, err := GenerateSalt()
	if err != nil {
		return "", "", err
	}

	// 2. Derive wrapping key from password
	wrappingKey := DeriveKeyFromPassword(password, salt)

	// 3. Encrypt private key with AES-GCM
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return "", "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", "", err
	}

	// 4. Generate nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", "", err
	}

	// 5. Encrypt (nonce is prepended to ciphertext)
	ciphertext := gcm.Seal(nonce, nonce, []byte(privateKeyPEM), nil)

	// 6. Encode to base64
	encryptedKey := base64.StdEncoding.EncodeToString(ciphertext)
	saltB64 := base64.StdEncoding.EncodeToString(salt)

	return encryptedKey, saltB64, nil
}

// UnwrapPrivateKey decrypts an encrypted private key using password
func UnwrapPrivateKey(encryptedKeyB64 string, saltB64 string, password string) (string, error) {
	// 1. Decode from base64
	ciphertext, err := base64.StdEncoding.DecodeString(encryptedKeyB64)
	if err != nil {
		return "", errors.New("invalid encrypted key format")
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return "", errors.New("invalid salt format")
	}

	// 2. Derive wrapping key from password
	wrappingKey := DeriveKeyFromPassword(password, salt)

	// 3. Create AES-GCM cipher
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// 4. Extract nonce and decrypt
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", errors.New("decryption failed - wrong password")
	}

	return string(plaintext), nil
}

// StoreWrappedKey stores a user's wrapped private key and public key
func (s *KeyWrapStore) StoreWrappedKey(clientID, userID, publicKeyPEM, encryptedPrivKey, salt string) error {
	query := `
		INSERT INTO user_keys (client_id, user_id, public_key_pem, encrypted_private_key, salt, updated_at)
		VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
		ON CONFLICT (client_id, user_id) DO UPDATE SET
			public_key_pem = $3,
			encrypted_private_key = $4,
			salt = $5,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := s.db.Exec(query, clientID, userID, publicKeyPEM, encryptedPrivKey, salt)
	return err
}

// StoreWrappedKeyWithRecovery stores a user's wrapped keys including recovery-wrapped key
func (s *KeyWrapStore) StoreWrappedKeyWithRecovery(clientID, userID, publicKeyPEM, encryptedPrivKey, salt, recoveryEncryptedPrivKey, recoverySalt string) error {
	query := `
		INSERT INTO user_keys (client_id, user_id, public_key_pem, encrypted_private_key, salt, recovery_encrypted_private_key, recovery_salt, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
		ON CONFLICT (client_id, user_id) DO UPDATE SET
			public_key_pem = $3,
			encrypted_private_key = $4,
			salt = $5,
			recovery_encrypted_private_key = $6,
			recovery_salt = $7,
			updated_at = CURRENT_TIMESTAMP
	`
	_, err := s.db.Exec(query, clientID, userID, publicKeyPEM, encryptedPrivKey, salt, recoveryEncryptedPrivKey, recoverySalt)
	return err
}

// UpdatePasswordWrappedKey updates only the password-wrapped key (used during recovery)
func (s *KeyWrapStore) UpdatePasswordWrappedKey(clientID, userID, encryptedPrivKey, salt string) error {
	query := `
		UPDATE user_keys
		SET encrypted_private_key = $3, salt = $4, updated_at = CURRENT_TIMESTAMP
		WHERE client_id = $1 AND user_id = $2
	`
	result, err := s.db.Exec(query, clientID, userID, encryptedPrivKey, salt)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errors.New("user not found")
	}
	return nil
}

// GetWrappedKey retrieves a user's wrapped key data
func (s *KeyWrapStore) GetWrappedKey(clientID, userID string) (*WrappedKey, error) {
	query := `
		SELECT user_id, client_id, public_key_pem, encrypted_private_key, salt,
		       COALESCE(recovery_encrypted_private_key, ''), COALESCE(recovery_salt, ''),
		       created_at, updated_at
		FROM user_keys
		WHERE client_id = $1 AND user_id = $2
	`

	wk := &WrappedKey{}
	err := s.db.QueryRow(query, clientID, userID).Scan(
		&wk.UserID, &wk.ClientID, &wk.PublicKeyPEM,
		&wk.EncryptedPrivKey, &wk.Salt,
		&wk.RecoveryEncryptedPrivKey, &wk.RecoverySalt,
		&wk.CreatedAt, &wk.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return wk, nil
}

// GetPublicKey retrieves only the public key for a user
func (s *KeyWrapStore) GetPublicKey(clientID, userID string) (string, error) {
	query := `SELECT public_key_pem FROM user_keys WHERE client_id = $1 AND user_id = $2`

	var publicKey string
	err := s.db.QueryRow(query, clientID, userID).Scan(&publicKey)

	if err == sql.ErrNoRows {
		return "", errors.New("user not found")
	}
	if err != nil {
		return "", err
	}

	return publicKey, nil
}

// DeleteUserKeys removes a user's keys from the database
func (s *KeyWrapStore) DeleteUserKeys(clientID, userID string) error {
	query := `DELETE FROM user_keys WHERE client_id = $1 AND user_id = $2`
	_, err := s.db.Exec(query, clientID, userID)
	return err
}

// ListUserKeys lists all users with keys for a client
func (s *KeyWrapStore) ListUserKeys(clientID string) ([]WrappedKey, error) {
	query := `
		SELECT user_id, client_id, public_key_pem, encrypted_private_key, salt, created_at, updated_at
		FROM user_keys
		WHERE client_id = $1
		ORDER BY created_at DESC
	`

	rows, err := s.db.Query(query, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []WrappedKey
	for rows.Next() {
		var wk WrappedKey
		err := rows.Scan(
			&wk.UserID, &wk.ClientID, &wk.PublicKeyPEM,
			&wk.EncryptedPrivKey, &wk.Salt,
			&wk.CreatedAt, &wk.UpdatedAt,
		)
		if err != nil {
			continue
		}
		keys = append(keys, wk)
	}

	return keys, nil
}
