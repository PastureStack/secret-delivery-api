// Modified by PastureStack in 2026: reject malformed and non-RSA keys safely.
package rsautils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

// RSAPublicKey a struct to hold an RSA Public Key
type RSAPublicKey struct {
	*rsa.PublicKey
}

// PublicKeyFromString returns an RSA public key object from a string
func PublicKeyFromString(pKey string) (*RSAPublicKey, error) {
	key, err := loadRSAPublicKey(pKey)
	if err != nil {
		return nil, err
	}
	return &RSAPublicKey{key}, nil
}

// Encrypt uses RSA Public key to encrypt data
func (pk *RSAPublicKey) Encrypt(text string) (string, error) {
	rng := rand.Reader
	cipherText, err := rsa.EncryptOAEP(sha256.New(), rng, pk.PublicKey, []byte(text), []byte(""))

	return base64.StdEncoding.EncodeToString(cipherText), err
}

func loadRSAPublicKey(key string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, errors.New("Could not decode public key block")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pub, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("Decoded public key is not RSA")
	}
	if pub.N.BitLen() < 2048 {
		return nil, errors.New("RSA public key must be at least 2048 bits")
	}

	return pub, nil
}
