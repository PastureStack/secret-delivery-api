package aesutils

import (
	"encoding/json"
	"strings"
	"testing"
)

const secretText = "my secret to keep"

type testKey struct {
	key []byte
}

func (tk *testKey) Key() ([]byte, error) {
	return tk.key, nil
}

func TestLocalKeyClient(t *testing.T) {
	k, err := NewRandomAESKey(32)
	if err != nil {
		t.Error(err)
	}

	encdata, err := GetEncryptedText(k, secretText, "aes256-gcm")
	if err != nil {
		t.Error(err)
	}

	data, err := GetClearText(k, encdata)
	if err != nil {
		t.Fatal(err)
	}

	if data != secretText {
		t.Errorf("Secret data decrypted to %s and we expected %s", data, secretText)
	}
}

func TestNewRandomAESKeyRejectsNonAES256Length(t *testing.T) {
	for _, length := range []int{-1, 0, 16, 24, 31, 33} {
		if _, err := NewRandomAESKey(length); err == nil {
			t.Errorf("expected length %d to be rejected", length)
		}
	}
}

func TestNewAESKeyFromBytesCopiesInputAndOutput(t *testing.T) {
	input := []byte("01234567890123456789012345678901")
	key := NewAESKeyFromBytes(input)
	input[0] = 'x'

	first, err := key.Key()
	if err != nil {
		t.Fatal(err)
	}
	if first[0] != '0' {
		t.Fatal("constructor retained mutable caller key material")
	}
	first[0] = 'y'
	second, err := key.Key()
	if err != nil {
		t.Fatal(err)
	}
	if second[0] != '0' {
		t.Fatal("Key returned mutable internal key material")
	}
}

func TestGetEncryptedTextRejectsWrongAlgorithmAndKeyLength(t *testing.T) {
	validKey := NewAESKeyFromBytes([]byte("01234567890123456789012345678901"))
	if _, err := GetEncryptedText(validKey, secretText, "aes128-gcm"); err == nil {
		t.Fatal("expected unsupported algorithm error")
	}
	shortKey := NewAESKeyFromBytes([]byte("0123456789012345"))
	if _, err := GetEncryptedText(shortKey, secretText, aesGCMAlgorithm); err == nil {
		t.Fatal("expected non-AES-256 key error")
	}
}

func TestGetClearTextRejectsMalformedEnvelopeWithoutPanic(t *testing.T) {
	key := NewAESKeyFromBytes([]byte("01234567890123456789012345678901"))
	tests := []AESSecret{
		{Algorithm: "unknown", Nonce: make([]byte, 12), CipherText: make([]byte, 16)},
		{Algorithm: aesGCMAlgorithm, Nonce: []byte{1}, CipherText: make([]byte, 16)},
		{Algorithm: aesGCMAlgorithm, Nonce: make([]byte, 12), CipherText: []byte{1}},
	}
	for _, tc := range tests {
		payload, err := json.Marshal(tc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := GetClearText(key, string(payload)); err == nil {
			t.Fatalf("expected malformed envelope to be rejected: %s", payload)
		}
	}
	if _, err := GetClearText(key, strings.Repeat("x", 32)); err == nil {
		t.Fatal("expected malformed JSON to be rejected")
	}
}

func TestGetClearTextRejectsTamperedCiphertext(t *testing.T) {
	key := NewAESKeyFromBytes([]byte("01234567890123456789012345678901"))
	encrypted, err := GetEncryptedText(key, secretText, aesGCMAlgorithm)
	if err != nil {
		t.Fatal(err)
	}
	var envelope AESSecret
	if err := json.Unmarshal([]byte(encrypted), &envelope); err != nil {
		t.Fatal(err)
	}
	envelope.CipherText[0] ^= 0xff
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := GetClearText(key, string(payload)); err == nil {
		t.Fatal("expected authenticated decryption failure")
	}
}
