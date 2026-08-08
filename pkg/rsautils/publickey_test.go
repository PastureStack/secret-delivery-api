// Added by PastureStack in 2026: non-RSA public-key regression coverage.
package rsautils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestPublicKeyFromStringRejectsNonRSAKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}))

	if _, err := PublicKeyFromString(publicKey); err == nil {
		t.Fatal("expected non-RSA public key error")
	}
}

func TestPublicKeyFromStringRejectsMalformedPEM(t *testing.T) {
	if _, err := PublicKeyFromString("not a PEM key"); err == nil {
		t.Fatal("expected malformed PEM error")
	}
}

func TestPublicKeyFromStringRejectsWeakRSAKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}))
	if _, err := PublicKeyFromString(publicKey); err == nil {
		t.Fatal("expected weak RSA public key error")
	}
}
