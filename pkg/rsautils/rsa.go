// Modified by PastureStack in 2026: normalized for the current Go toolchain.
package rsautils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
)

// Decryptor handles decrypting messages
type Decryptor interface {
	Decrypt(cipherText string) ([]byte, error)
}

type rsaDecryptor struct {
	privateKeyPath string
	key            *rsa.PrivateKey
}

// NewRSADecryptorKeyFromFile returns an RSA decryptor
func NewRSADecryptorKeyFromFile(privateKeyPath string) (Decryptor, error) {
	key, err := loadPrivateKeyFromFile(privateKeyPath)
	if err != nil {
		return nil, err
	}

	return rsaDecryptor{
		privateKeyPath: privateKeyPath,
		key:            key,
	}, nil
}

func NewRSADecryptorKeyFromString(privateKey string) (Decryptor, error) {
	key, err := loadPrivateKeyFromString(privateKey)
	if err != nil {
		return nil, err
	}

	return rsaDecryptor{
		privateKeyPath: "",
		key:            key,
	}, nil
}

// Decrypt implments the decryptor interface
func (r rsaDecryptor) Decrypt(cipherText string) ([]byte, error) {
	return rsaDecrypt(r.key, cipherText)
}

func loadPrivateKeyFromFile(keyPath string) (*rsa.PrivateKey, error) {
	// The path is an administrator-supplied process configuration value, not request data.
	keyData, err := os.ReadFile(keyPath) // #nosec G304 -- reading the explicitly configured private-key file is the intended operation
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, errors.New("could not decode private key; is it PEM format?")
	}

	return parsePrivateKey(block.Bytes)
}

func loadPrivateKeyFromString(keyString string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyString))
	if block == nil {
		return nil, errors.New("could not decode private key; is it PEM format?")
	}
	return parsePrivateKey(block.Bytes)
}

func parsePrivateKey(der []byte) (*rsa.PrivateKey, error) {
	key, err := x509.ParsePKCS1PrivateKey(der)
	if err != nil {
		return nil, err
	}
	if key.N.BitLen() < 2048 {
		return nil, errors.New("RSA private key must be at least 2048 bits")
	}
	return key, nil
}

func rsaDecrypt(priv *rsa.PrivateKey, cipherText string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return []byte{}, err
	}

	return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, data, []byte(""))
}
