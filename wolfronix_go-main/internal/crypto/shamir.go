package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
)

// Shamir Secret Sharing Implementation
// Splits a secret into n shares where any k shares can reconstruct the secret
// Based on polynomial interpolation over GF(256)

// Share represents a single share of the secret
type Share struct {
	X     byte   // x-coordinate (share index, 1-255)
	Y     []byte // y-values for each byte of secret
	Index int    // Human-readable index
}

// ShamirConfig holds configuration for secret sharing
type ShamirConfig struct {
	Threshold int // Minimum shares needed to reconstruct (k)
	Total     int // Total number of shares to create (n)
}

// DefaultShamirConfig returns a 3-of-5 configuration
func DefaultShamirConfig() ShamirConfig {
	return ShamirConfig{
		Threshold: 3,
		Total:     5,
	}
}

// SplitSecret splits a secret into n shares with threshold k
// Returns k-of-n shares where any k shares can reconstruct the secret
func SplitSecret(secret []byte, threshold, total int) ([]Share, error) {
	if threshold < 2 {
		return nil, errors.New("threshold must be at least 2")
	}
	if total < threshold {
		return nil, errors.New("total shares must be >= threshold")
	}
	if total > 255 {
		return nil, errors.New("maximum 255 shares supported")
	}
	if len(secret) == 0 {
		return nil, errors.New("secret cannot be empty")
	}

	// Create shares
	shares := make([]Share, total)
	for i := 0; i < total; i++ {
		shares[i] = Share{
			X:     byte(i + 1), // x values are 1 to n (0 is reserved for secret)
			Y:     make([]byte, len(secret)),
			Index: i + 1,
		}
	}

	// For each byte of the secret, create a random polynomial and evaluate
	for byteIdx, secretByte := range secret {
		// Generate random polynomial coefficients
		// f(x) = secret + a1*x + a2*x^2 + ... + a(k-1)*x^(k-1)
		coefficients := make([]byte, threshold)
		coefficients[0] = secretByte // constant term is the secret byte

		// Random coefficients for higher degree terms
		if _, err := rand.Read(coefficients[1:]); err != nil {
			return nil, fmt.Errorf("failed to generate random coefficients: %w", err)
		}

		// Evaluate polynomial at each x to get shares
		for i := 0; i < total; i++ {
			shares[i].Y[byteIdx] = evaluatePolynomial(coefficients, shares[i].X)
		}
	}

	return shares, nil
}

// CombineShares reconstructs the secret from k or more shares
func CombineShares(shares []Share) ([]byte, error) {
	if len(shares) < 2 {
		return nil, errors.New("need at least 2 shares to reconstruct")
	}

	// Verify all shares have same length
	secretLen := len(shares[0].Y)
	for _, share := range shares {
		if len(share.Y) != secretLen {
			return nil, errors.New("share length mismatch")
		}
	}

	// Check for duplicate x values
	seen := make(map[byte]bool)
	for _, share := range shares {
		if seen[share.X] {
			return nil, errors.New("duplicate share detected")
		}
		seen[share.X] = true
	}

	// Reconstruct secret using Lagrange interpolation
	secret := make([]byte, secretLen)
	for byteIdx := 0; byteIdx < secretLen; byteIdx++ {
		// Collect (x, y) pairs for this byte position
		points := make([]struct{ x, y byte }, len(shares))
		for i, share := range shares {
			points[i].x = share.X
			points[i].y = share.Y[byteIdx]
		}

		// Lagrange interpolation at x=0 gives us the secret
		secret[byteIdx] = lagrangeInterpolate(points, 0)
	}

	return secret, nil
}

// evaluatePolynomial evaluates polynomial at x using Horner's method in GF(256)
func evaluatePolynomial(coefficients []byte, x byte) byte {
	if x == 0 {
		return coefficients[0]
	}

	// Horner's method: ((a_n * x + a_{n-1}) * x + ...) * x + a_0
	result := byte(0)
	for i := len(coefficients) - 1; i >= 0; i-- {
		result = gfAdd(gfMul(result, x), coefficients[i])
	}
	return result
}

// lagrangeInterpolate performs Lagrange interpolation at target x in GF(256)
func lagrangeInterpolate(points []struct{ x, y byte }, target byte) byte {
	result := byte(0)

	for i := 0; i < len(points); i++ {
		// Calculate Lagrange basis polynomial L_i(target)
		basis := byte(1)
		for j := 0; j < len(points); j++ {
			if i == j {
				continue
			}
			// basis *= (target - x_j) / (x_i - x_j)
			num := gfSub(target, points[j].x)
			den := gfSub(points[i].x, points[j].x)
			basis = gfMul(basis, gfDiv(num, den))
		}
		// result += y_i * L_i(target)
		result = gfAdd(result, gfMul(points[i].y, basis))
	}

	return result
}

// GF(256) Arithmetic using AES polynomial (x^8 + x^4 + x^3 + x + 1)
// This is the same field used in AES, making it efficient

// gfAdd performs addition in GF(256) - just XOR
func gfAdd(a, b byte) byte {
	return a ^ b
}

// gfSub performs subtraction in GF(256) - same as addition (XOR)
func gfSub(a, b byte) byte {
	return a ^ b
}

// gfMul performs multiplication in GF(256)
func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[(int(gfLog[a])+int(gfLog[b]))%255]
}

// gfDiv performs division in GF(256)
func gfDiv(a, b byte) byte {
	if b == 0 {
		panic("division by zero in GF(256)")
	}
	if a == 0 {
		return 0
	}
	return gfExp[(int(gfLog[a])-int(gfLog[b])+255)%255]
}

// Precomputed log and exp tables for GF(256) with generator 3
var gfLog [256]byte
var gfExp [256]byte

func init() {
	// Generate log and exp tables using generator 3
	// Polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B)
	x := byte(1)
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfLog[x] = byte(i)
		x = gfMulNoTable(x, 3)
	}
	gfExp[255] = gfExp[0] // For wraparound
}

// gfMulNoTable multiplies without lookup tables (used for table generation)
func gfMulNoTable(a, b byte) byte {
	var result byte = 0
	for b > 0 {
		if b&1 != 0 {
			result ^= a
		}
		highBit := a & 0x80
		a <<= 1
		if highBit != 0 {
			a ^= 0x1B // AES polynomial reduction
		}
		b >>= 1
	}
	return result
}

// === INTEGRATION WITH EXISTING CRYPTO SYSTEM ===

// ShamirKeyManager manages AES keys with Shamir secret sharing
type ShamirKeyManager struct {
	config ShamirConfig
}

// NewShamirKeyManager creates a new key manager with given config
func NewShamirKeyManager(config ShamirConfig) *ShamirKeyManager {
	return &ShamirKeyManager{config: config}
}

// SplitAESKey splits an AES key into shares
func (m *ShamirKeyManager) SplitAESKey(key []byte) ([]Share, error) {
	if len(key) != 32 {
		return nil, errors.New("AES key must be 32 bytes (256-bit)")
	}
	return SplitSecret(key, m.config.Threshold, m.config.Total)
}

// RecoverAESKey recovers the AES key from shares
func (m *ShamirKeyManager) RecoverAESKey(shares []Share) ([]byte, error) {
	if len(shares) < m.config.Threshold {
		return nil, fmt.Errorf("need at least %d shares, got %d", m.config.Threshold, len(shares))
	}
	return CombineShares(shares)
}

// EncryptedShare wraps a Share with RSA encryption for secure distribution
type EncryptedShare struct {
	Index         int    `json:"index"`
	EncryptedData string `json:"encrypted_data"` // Base64 RSA-encrypted share
	PublicKeyID   string `json:"public_key_id"`  // Identifier for the recipient's public key
}

// EncryptShareForDistribution encrypts a share with recipient's RSA public key
func EncryptShareForDistribution(share Share, recipientPubKey string, keyID string) (*EncryptedShare, error) {
	// Serialize share: X (1 byte) + Y (variable)
	data := make([]byte, 1+len(share.Y))
	data[0] = share.X
	copy(data[1:], share.Y)

	// Encrypt with RSA
	encrypted, err := EncryptRSA(data, recipientPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt share: %w", err)
	}

	return &EncryptedShare{
		Index:         share.Index,
		EncryptedData: encrypted,
		PublicKeyID:   keyID,
	}, nil
}

// DecryptShareFromDistribution decrypts a share using recipient's RSA private key
func DecryptShareFromDistribution(encShare *EncryptedShare, privKey string) (*Share, error) {
	// Decrypt with RSA
	data, err := DecryptRSA(encShare.EncryptedData, privKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt share: %w", err)
	}

	if len(data) < 2 {
		return nil, errors.New("invalid share data")
	}

	return &Share{
		X:     data[0],
		Y:     data[1:],
		Index: encShare.Index,
	}, nil
}

// === HYBRID ENCRYPTION WORKFLOW ===

// HybridEncryptResult contains all data needed for hybrid encryption
type HybridEncryptResult struct {
	EncryptedData []byte           `json:"encrypted_data"` // AES-CTR encrypted data
	IV            []byte           `json:"iv"`             // AES initialization vector
	KeyShares     []EncryptedShare `json:"key_shares"`     // RSA-encrypted Shamir shares
	Threshold     int              `json:"threshold"`      // Minimum shares needed
	TotalShares   int              `json:"total_shares"`   // Total shares created
}

// HybridEncrypt performs the full hybrid encryption workflow:
// 1. Generate AES key
// 2. Encrypt data with AES-CTR
// 3. Split AES key with Shamir
// 4. Encrypt each share with recipient's RSA public key
func HybridEncrypt(plaintext []byte, recipientKeys map[string]string, config ShamirConfig) (*HybridEncryptResult, error) {
	if len(recipientKeys) < config.Total {
		return nil, fmt.Errorf("need %d recipient keys, got %d", config.Total, len(recipientKeys))
	}

	// 1. Generate AES key and IV
	aesKey, err := GenerateAESKey()
	if err != nil {
		return nil, fmt.Errorf("failed to generate AES key: %w", err)
	}
	iv, err := GenerateIV()
	if err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// 2. Encrypt data with AES-GCM (for integrity)
	encryptedData, err := EncryptAESGCM(string(plaintext), aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// 3. Split AES key with Shamir
	manager := NewShamirKeyManager(config)
	shares, err := manager.SplitAESKey(aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to split key: %w", err)
	}

	// 4. Encrypt each share with corresponding recipient's public key
	encryptedShares := make([]EncryptedShare, len(shares))
	i := 0
	for keyID, pubKey := range recipientKeys {
		if i >= len(shares) {
			break
		}
		encShare, err := EncryptShareForDistribution(shares[i], pubKey, keyID)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt share %d: %w", i, err)
		}
		encryptedShares[i] = *encShare
		i++
	}

	return &HybridEncryptResult{
		EncryptedData: []byte(encryptedData),
		IV:            iv,
		KeyShares:     encryptedShares,
		Threshold:     config.Threshold,
		TotalShares:   config.Total,
	}, nil
}

// HybridDecrypt performs the decryption workflow:
// 1. Collect at least k encrypted shares
// 2. Decrypt shares with respective private keys
// 3. Combine shares to recover AES key
// 4. Decrypt data with AES
func HybridDecrypt(result *HybridEncryptResult, privateKeys map[string]string) ([]byte, error) {
	// 1. Decrypt available shares
	var decryptedShares []Share
	for _, encShare := range result.KeyShares {
		privKey, ok := privateKeys[encShare.PublicKeyID]
		if !ok {
			continue // Skip shares we don't have keys for
		}

		share, err := DecryptShareFromDistribution(&encShare, privKey)
		if err != nil {
			continue // Skip shares that fail to decrypt
		}
		decryptedShares = append(decryptedShares, *share)
	}

	// 2. Check if we have enough shares
	if len(decryptedShares) < result.Threshold {
		return nil, fmt.Errorf("insufficient shares: need %d, have %d", result.Threshold, len(decryptedShares))
	}

	// 3. Combine shares to recover AES key
	aesKey, err := CombineShares(decryptedShares)
	if err != nil {
		return nil, fmt.Errorf("failed to combine shares: %w", err)
	}

	// 4. Decrypt data with AES
	plaintext, err := DecryptAESGCM(string(result.EncryptedData), aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt data: %w", err)
	}

	return []byte(plaintext), nil
}
