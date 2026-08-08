package service

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/PastureStack/secret-delivery-api/backends"
)

func TestDecodeJSONBodyAcceptsOneBoundedObject(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"value"}`))
	destination := map[string]string{}
	if err := decodeJSONBody(recorder, request, &destination); err != nil {
		t.Fatal(err)
	}
	if destination["name"] != "value" {
		t.Fatalf("unexpected decoded value: %#v", destination)
	}
}

func TestDecodeJSONBodyRejectsEmptyNullTrailingAndOversizedBodies(t *testing.T) {
	tests := []string{"", "null", `{}` + `{}`, strings.Repeat("x", int(maxRequestBodyBytes)+1)}
	for _, body := range tests {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		if err := decodeJSONBody(recorder, request, &map[string]interface{}{}); err == nil {
			t.Fatalf("expected body of length %d to be rejected", len(body))
		}
	}
}

func TestRouterCreatesEncryptedSecretAndSetsSecurityHeaders(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(directory+string(os.PathSeparator)+"test-key", []byte("01234567890123456789012345678901"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := backends.SetBackendConfigs(&backends.Configs{EncryptionKeyPath: directory}); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, "http://example.test/v1-secrets/secrets/create",
		strings.NewReader(`{"type":"secretInput","backend":"localkey","keyName":"test-key","clearText":"sensitive value"}`))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	NewRouter().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", recorder.Code, recorder.Body.String())
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("secret response is cacheable")
	}
	if recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatal("missing nosniff response header")
	}
	if strings.Contains(recorder.Body.String(), "sensitive value") {
		t.Fatal("response leaked clear text")
	}
	var response map[string]interface{}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response["cipherText"] == "" || response["signature"] == "" {
		t.Fatalf("encrypted response is incomplete: %#v", response)
	}
}

func TestRouterRejectsInvalidInputWithoutExposingInternalError(t *testing.T) {
	if err := backends.SetBackendConfigs(backends.NewConfig()); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "http://example.test/v1-secrets/secrets/create",
		strings.NewReader(`{"type":"secretInput","backend":"localkey","keyName":"../outside","clearText":"secret"}`))
	recorder := httptest.NewRecorder()
	NewRouter().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status %d: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "../outside") || strings.Contains(recorder.Body.String(), "secret key name") {
		t.Fatalf("response exposed internal validation detail: %s", recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "Invalid request") {
		t.Fatalf("response lacks safe error message: %s", recorder.Body.String())
	}
}

func TestRouterRejectsNullBulkItemWithoutPanic(t *testing.T) {
	if err := backends.SetBackendConfigs(backends.NewConfig()); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost,
		"http://example.test/v1-secrets/secrets/create?action=bulk", strings.NewReader(`{"data":[null]}`))
	recorder := httptest.NewRecorder()
	NewRouter().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unexpected status %d: %s", recorder.Code, recorder.Body.String())
	}
}

func TestRouterRewrapsAndPurgesSingleAndBulkSecrets(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(directory+string(os.PathSeparator)+"test-key",
		[]byte("01234567890123456789012345678901"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := backends.SetBackendConfigs(&backends.Configs{EncryptionKeyPath: directory}); err != nil {
		t.Fatal(err)
	}
	router := NewRouter()

	create := serveJSON(t, router, http.MethodPost, "/v1-secrets/secrets/create",
		map[string]interface{}{
			"type": "secretInput", "backend": "localkey", "keyName": "test-key", "clearText": "single secret",
		})
	if create.Code != http.StatusOK {
		t.Fatalf("single create failed: %d %s", create.Code, create.Body.String())
	}
	var encrypted map[string]interface{}
	if err := json.Unmarshal(create.Body.Bytes(), &encrypted); err != nil {
		t.Fatal(err)
	}
	encrypted["rewrapKey"] = testRSAPublicKey(t)

	rewrap := serveJSON(t, router, http.MethodPost, "/v1-secrets/secrets/rewrap", encrypted)
	if rewrap.Code != http.StatusOK || !strings.Contains(rewrap.Body.String(), "rewrapText") {
		t.Fatalf("single rewrap failed: %d %s", rewrap.Code, rewrap.Body.String())
	}
	purge := serveJSON(t, router, http.MethodPost, "/v1-secrets/secrets/purge", encrypted)
	if purge.Code != http.StatusNoContent {
		t.Fatalf("single purge failed: %d %s", purge.Code, purge.Body.String())
	}

	bulkCreate := serveJSON(t, router, http.MethodPost, "/v1-secrets/secrets/create?action=bulk",
		map[string]interface{}{"data": []map[string]interface{}{
			{"type": "secretInput", "backend": "localkey", "keyName": "test-key", "clearText": "first"},
			{"type": "secretInput", "backend": "localkey", "keyName": "test-key", "clearText": "second"},
		}})
	if bulkCreate.Code != http.StatusOK {
		t.Fatalf("bulk create failed: %d %s", bulkCreate.Code, bulkCreate.Body.String())
	}
	var bulkEncrypted map[string]interface{}
	if err := json.Unmarshal(bulkCreate.Body.Bytes(), &bulkEncrypted); err != nil {
		t.Fatal(err)
	}
	bulkEncrypted["rewrapKey"] = testRSAPublicKey(t)
	bulkRewrap := serveJSON(t, router, http.MethodPost, "/v1-secrets/secrets/rewrap?action=bulk", bulkEncrypted)
	if bulkRewrap.Code != http.StatusOK {
		t.Fatalf("bulk rewrap failed: %d %s", bulkRewrap.Code, bulkRewrap.Body.String())
	}
	bulkPurge := serveJSON(t, router, http.MethodPost, "/v1-secrets/secrets/purge?action=bulk", bulkEncrypted)
	if bulkPurge.Code != http.StatusNoContent {
		t.Fatalf("bulk purge failed: %d %s", bulkPurge.Code, bulkPurge.Body.String())
	}
}

func TestRouterReturnsSafeNotFoundResponse(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/missing", nil)
	recorder := httptest.NewRecorder()
	NewRouter().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unexpected status %d", recorder.Code)
	}
	if !strings.Contains(recorder.Body.String(), "Not found") {
		t.Fatalf("unexpected error response: %s", recorder.Body.String())
	}
}

func TestBrowserAndHTMLFormatRequestsRemainLocalJSON(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "http://example.test/v1-secrets?_format=html", nil)
	request.Header.Set("User-Agent", "Mozilla/5.0")
	request.Header.Set("Accept", "*/*")
	recorder := httptest.NewRecorder()
	NewRouter().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", recorder.Code, recorder.Body.String())
	}
	if !strings.HasPrefix(recorder.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("unexpected browser response type %q", recorder.Header().Get("Content-Type"))
	}
	if strings.Contains(strings.ToLower(recorder.Body.String()), "<script") ||
		strings.Contains(strings.ToLower(recorder.Body.String()), "<!doctype") {
		t.Fatal("browser response contains executable HTML")
	}
}

func TestNewHTTPServerHasResourceExhaustionLimits(t *testing.T) {
	server := NewHTTPServer("127.0.0.1:0")
	if server.Addr != "127.0.0.1:0" || server.Handler == nil {
		t.Fatalf("unexpected server configuration: %#v", server)
	}
	if server.ReadHeaderTimeout != readHeaderTimeout || server.ReadTimeout != readTimeout ||
		server.WriteTimeout != writeTimeout || server.IdleTimeout != idleTimeout ||
		server.MaxHeaderBytes != maxHeaderBytes {
		t.Fatalf("server resource limits are incomplete: %#v", server)
	}
}

func serveJSON(t *testing.T, handler http.Handler, method, target string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(method, "http://example.test"+target, strings.NewReader(string(encoded)))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func testRSAPublicKey(t *testing.T) string {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded}))
}
