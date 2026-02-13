package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// --- A. KEY & IV GENERATION ---
func GenerateIV() ([]byte, error) {
	iv := make([]byte, 16) // AES block size
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}
	return iv, nil
}

// Generate 32 bytes Key
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, err
	}
	return key, nil
}

// --- B. BLOCK CIPHER (For Keys & Small Data) ---

func EncryptAESGCM(plainText string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("nonce generation failed: %w", err)
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(plainText), nil)), nil
}

func DecryptAESGCM(b64Cipher string, key []byte) (string, error) {
	data, err := base64.StdEncoding.DecodeString(b64Cipher)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("bad cipher")
	}
	plain, err := gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
	return string(plain), err
}

// --- C. RSA UTILITIES ---

// GenerateRSAKeys generates a 2048-bit RSA key pair and returns (privatePEM, publicPEM, error).
func GenerateRSAKeys() (string, string, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("RSA key generation failed: %w", err)
	}
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	pubBytes := x509.MarshalPKCS1PublicKey(&priv.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes})),
		string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: pubBytes})),
		nil
}

// EncryptRSA encrypts data with an RSA public key (PKCS1 or PKIX/SPKI format).
func EncryptRSA(data []byte, pubKeyPEM string) (string, error) {
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil {
		return "", errors.New("bad key: failed to decode PEM block")
	}

	// Try PKCS1 first, then fall back to PKIX/SPKI (Web Crypto API format)
	var pub *rsa.PublicKey
	if k, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		pub = k
	} else if generic, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		if rsaPub, ok := generic.(*rsa.PublicKey); ok {
			pub = rsaPub
		} else {
			return "", errors.New("bad key: not an RSA public key")
		}
	} else {
		return "", errors.New("bad key: unsupported public key format")
	}

	enc, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)
	if err != nil {
		return "", fmt.Errorf("RSA encryption failed: %w", err)
	}
	return base64.StdEncoding.EncodeToString(enc), nil
}

// DecryptRSA decrypts base64-encoded data with an RSA private key (PKCS1 or PKCS8 format).
func DecryptRSA(b64Data string, privKeyPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(privKeyPEM))
	if block == nil {
		return nil, errors.New("bad key: failed to decode PEM block")
	}

	// Try PKCS1 first, then fall back to PKCS8
	var priv *rsa.PrivateKey
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		priv = k
	} else if generic, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if rsaPriv, ok := generic.(*rsa.PrivateKey); ok {
			priv = rsaPriv
		} else {
			return nil, errors.New("bad key: not an RSA private key")
		}
	} else {
		return nil, errors.New("bad key: unsupported private key format")
	}

	data, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, data, nil)
}
