package vault

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestNewClientRejectsInvalidConfiguration(t *testing.T) {
	tests := [][2]string{
		{"", "token"},
		{"file:///tmp/vault", "token"},
		{"http://vault.example.test", "token"},
		{"https://user:password@example.test", "token"},
		{"https://example.test?token=secret", "token"},
		{"https://example.test", ""},
	}
	for _, tc := range tests {
		if _, err := NewClient(tc[0], tc[1]); err == nil {
			t.Fatalf("expected address %q and token length %d to be rejected", tc[0], len(tc[1]))
		}
	}
}

func TestVaultTransitRoundTripAndSignature(t *testing.T) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requests, 1)
		if r.Header.Get("X-Vault-Token") != "test-token" {
			t.Errorf("missing Vault token header")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			writeVaultData(t, w, map[string]interface{}{"meta": map[string]interface{}{}})
		case "/v1/transit/encrypt/test-key":
			writeVaultData(t, w, map[string]interface{}{"ciphertext": "vault:v1:cipher"})
		case "/v1/transit/decrypt/test-key":
			writeVaultData(t, w, map[string]interface{}{"plaintext": "cGxhaW50ZXh0"})
		case "/v1/transit/random/8":
			writeVaultData(t, w, map[string]interface{}{"random_bytes": "nonce"})
		case "/v1/transit/hmac/test-key":
			writeVaultData(t, w, map[string]interface{}{"hmac": "vault:v1:hmac"})
		case "/v1/transit/verify/test-key/sha2-256":
			writeVaultData(t, w, map[string]interface{}{"valid": true})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}
	cipherText, err := client.GetEncryptedText("test-key", "cGxhaW50ZXh0")
	if err != nil || cipherText != "vault:v1:cipher" {
		t.Fatalf("unexpected encryption result %q: %v", cipherText, err)
	}
	plainText, err := client.GetClearText("test-key", cipherText)
	if err != nil || plainText != "cGxhaW50ZXh0" {
		t.Fatalf("unexpected decryption result %q: %v", plainText, err)
	}
	signature, err := client.Sign("test-key", plainText)
	if err != nil || signature != "nonce:vault:v1:hmac" {
		t.Fatalf("unexpected signature %q: %v", signature, err)
	}
	verified, err := client.VerifySignature("test-key", signature, plainText)
	if err != nil || !verified {
		t.Fatalf("signature did not verify: %v, %v", verified, err)
	}
	beforeMalformed := atomic.LoadInt32(&requests)
	for _, malformed := range []string{"malformed", ":", "nonce:", ":hmac"} {
		if verified, err := client.VerifySignature("test-key", malformed, plainText); err == nil || verified {
			t.Fatalf("expected malformed signature %q error", malformed)
		}
	}
	if atomic.LoadInt32(&requests) != beforeMalformed {
		t.Fatal("malformed signature unexpectedly reached Vault")
	}
	if err := client.Delete("test-key", cipherText); err != nil {
		t.Fatalf("no-storage delete should be a no-op: %v", err)
	}
}

func TestVaultStoragePathsAreScopedToGeneratedDigests(t *testing.T) {
	const cipherText = "vault:v1:cipher"
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(cipherText)))
	expectedPath := "secret/team/v1-secrets/" + digest
	var deleted string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/auth/token/lookup-self":
			writeVaultData(t, w, map[string]interface{}{"meta": map[string]interface{}{"storage_dir": "/secret/team/"}})
		case r.URL.Path == "/v1/transit/encrypt/test-key":
			writeVaultData(t, w, map[string]interface{}{"ciphertext": cipherText})
		case r.URL.Path == "/v1/"+expectedPath && r.Method == http.MethodPut:
			writeVaultData(t, w, map[string]interface{}{})
		case r.URL.Path == "/v1/"+expectedPath && r.Method == http.MethodGet:
			writeVaultData(t, w, map[string]interface{}{"cipherText": cipherText})
		case r.URL.Path == "/v1/transit/decrypt/test-key":
			writeVaultData(t, w, map[string]interface{}{"plaintext": "cGxhaW50ZXh0"})
		case r.URL.Path == "/v1/"+expectedPath && r.Method == http.MethodDelete:
			deleted = strings.TrimPrefix(r.URL.Path, "/v1/")
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(server.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}
	storedPath, err := client.GetEncryptedText("test-key", "cGxhaW50ZXh0")
	if err != nil || storedPath != expectedPath {
		t.Fatalf("unexpected stored path %q: %v", storedPath, err)
	}
	plainText, err := client.GetClearText("test-key", storedPath)
	if err != nil || plainText != "cGxhaW50ZXh0" {
		t.Fatalf("unexpected stored secret result %q: %v", plainText, err)
	}
	for _, invalid := range []string{
		"secret/team/other",
		"secret/team/v1-secrets/../outside",
		"other/v1-secrets/" + digest,
		"secret/team/v1-secrets/" + strings.ToUpper(digest),
	} {
		if err := client.Delete("test-key", invalid); err == nil {
			t.Fatalf("expected arbitrary Vault path %q to be rejected", invalid)
		}
	}
	if err := client.Delete("test-key", storedPath); err != nil {
		t.Fatal(err)
	}
	if deleted != expectedPath {
		t.Fatalf("unexpected deleted path %q", deleted)
	}
}

func TestVaultRejectsInvalidKeyNamesAndEmptyResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/auth/token/lookup-self" {
			writeVaultData(t, w, map[string]interface{}{"meta": map[string]interface{}{}})
			return
		}
		writeVaultData(t, w, nil)
	}))
	defer server.Close()
	client, err := NewClient(server.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, keyName := range []string{"", ".", "..", "a/b", `a\b`, "a\nkey"} {
		if _, err := client.GetEncryptedText(keyName, "value"); err == nil {
			t.Fatalf("expected key name %q to be rejected", keyName)
		}
	}
	if _, err := client.GetEncryptedText("test-key", "value"); err == nil {
		t.Fatal("expected empty Vault response error")
	}
}

func writeVaultData(t *testing.T, w http.ResponseWriter, data interface{}) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(map[string]interface{}{"data": data}); err != nil {
		t.Fatal(err)
	}
}
