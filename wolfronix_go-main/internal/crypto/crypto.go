package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
)

// --- A. STREAMING AES (Unlimited Size) ---

// Create a Stream Encryptor (Reader wrapper)
func NewAESStreamReader(source io.Reader, key []byte, iv []byte) (io.Reader, error) {
	block, err := aes.NewCipher(key)
	if err != nil { return nil, err }

	// CTR Mode is perfect for streaming (Parallelizable, No padding)
	stream := cipher.NewCTR(block, iv)
	
	return &cipher.StreamReader{S: stream, R: source}, nil
}

// Create a Stream Decryptor (Reader wrapper - Symmetric to Encryptor in CTR)
func NewAESStreamDecryptor(source io.Reader, key []byte, iv []byte) (io.Reader, error) {
	// In CTR mode, encrypt and decrypt are the same math
	return NewAESStreamReader(source, key, iv) 
}

// Helper: Generate Random IV (16 bytes)
func GenerateIV() ([]byte, error) {
	iv := make([]byte, 16) // AES block size
	if _, err := io.ReadFull(rand.Reader, iv); err != nil { return nil, err }
	return iv, nil
}

// Generate 32 bytes Key
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil { return nil, err }
	return key, nil
}

// --- B. BLOCK CIPHER (For Keys & Small Data) ---

func EncryptAESGCM(plainText string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil { return "", err }
	gcm, err := cipher.NewGCM(block)
	if err != nil { return "", err }
	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plainText), nil)), nil
}

func DecryptAESGCM(b64Cipher string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(b64Cipher)
	if err != nil { return "", err }
	block, err := aes.NewCipher(key)
	if err != nil { return "", err }
	gcm, err := cipher.NewGCM(block)
	if err != nil { return "", err }
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize { return "", errors.New("bad cipher") }
	plain, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	return string(plain), err
}

// --- C. RSA UTILITIES ---
func GenerateRSAKeys() (string, string) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	pubBytes := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})),
	       string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes}))
}

func EncryptRSA(data []byte, pubKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil { return "", errors.New("bad key") }
	pub, _ := x509.ParsePKCS1PublicKey(block.Bytes)
	enc, err := rsa.EncryptPKCS1v15(rand.Reader, pub, data)
	return base64.StdEncoding.EncodeToString(enc), err
}

func DecryptRSA(b64Data string, privKeyPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(privKeyPEM))
	if block == nil { return nil, errors.New("bad key") }
	priv, _ := x509.ParsePKCS1PrivateKey(block.Bytes)
	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil { return nil, err }
	return rsa.DecryptPKCS1v15(rand.Reader, priv, data)
}
