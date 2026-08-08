package rsautils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestNewRSADecryptorKeyFromStringRejectsMalformedPEM(t *testing.T) {
	if _, err := NewRSADecryptorKeyFromString("not a PEM key"); err == nil {
		t.Fatal("expected malformed private key error")
	}
}

func TestRSAEncryptDecryptRoundTripFromStringAndFile(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	publicBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicBytes})
	publicKey, err := PublicKeyFromString(string(publicPEM))
	if err != nil {
		t.Fatal(err)
	}
	cipherText, err := publicKey.Encrypt("secret")
	if err != nil {
		t.Fatal(err)
	}

	fromString, err := NewRSADecryptorKeyFromString(string(privatePEM))
	if err != nil {
		t.Fatal(err)
	}
	plainText, err := fromString.Decrypt(cipherText)
	if err != nil || string(plainText) != "secret" {
		t.Fatalf("unexpected string-key result %q: %v", plainText, err)
	}

	keyPath := filepath.Join(t.TempDir(), "private.pem")
	if err := os.WriteFile(keyPath, privatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile, err := NewRSADecryptorKeyFromFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	plainText, err = fromFile.Decrypt(cipherText)
	if err != nil || string(plainText) != "secret" {
		t.Fatalf("unexpected file-key result %q: %v", plainText, err)
	}
	if _, err := fromFile.Decrypt("not base64!"); err == nil {
		t.Fatal("expected malformed cipher text error")
	}
}

func TestNewRSADecryptorKeyFromFileRejectsMalformedPEM(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "private.pem")
	if err := os.WriteFile(keyPath, []byte("not a PEM key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRSADecryptorKeyFromFile(keyPath); err == nil {
		t.Fatal("expected malformed private key file error")
	}
}

func TestNewRSADecryptorRejectsWeakPrivateKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if _, err := NewRSADecryptorKeyFromString(string(privatePEM)); err == nil {
		t.Fatal("expected weak private key error")
	}
}
