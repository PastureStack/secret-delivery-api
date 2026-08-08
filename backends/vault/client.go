// Modified by PastureStack in 2026: harden optional values and sensitive logging.
package vault

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/sirupsen/logrus"
)

const vaultRequestTimeout = 30 * time.Second

// Client is the struct that implements the backend interface
type Client struct {
	url        string
	token      string
	storageDir string
}

// NewClient returns a Client type that is ready to interact
// with vault
func NewClient(url, token string) (*Client, error) {
	if err := validateVaultAddress(url); err != nil {
		return nil, err
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("Vault token is required")
	}

	client := &Client{
		url:   url,
		token: token,
	}

	storageDir, err := client.getStorageDir()
	if err != nil {
		return nil, err
	}
	client.storageDir = storageDir

	return client, nil
}

// GetEncryptedText None Client just returns the clearText
func (v *Client) GetEncryptedText(keyName, clearText string) (string, error) {
	if err := validateVaultKeyName(keyName); err != nil {
		return "", err
	}
	encryptPath := fmt.Sprintf("/transit/encrypt/%s", url.PathEscape(keyName))

	data := map[string]interface{}{
		"plaintext": clearText,
	}

	secret, err := v.writeToVault(encryptPath, data)
	if err != nil {
		logrus.Error(err)
		return "", fmt.Errorf("Issue encrypting with %s key", keyName)
	}

	if cipherText, ok := secretString(secret, "ciphertext"); ok {
		if v.storageDir != "" {
			cipherText, err = v.storeSecretInVault(cipherText)
			if err != nil {
				return "", err
			}
		}
		return cipherText, nil
	}

	return "", errors.New("Could not encrypt cleartext")
}

// GetClearText  None Client just returns the cipherText
func (v *Client) GetClearText(keyName, cipherText string) (string, error) {
	if err := validateVaultKeyName(keyName); err != nil {
		return "", err
	}
	var err error
	decryptPath := fmt.Sprintf("/transit/decrypt/%s", url.PathEscape(keyName))

	if v.storageDir != "" {
		cipherText, err = v.retrieveSecretFromVault(cipherText)
		if err != nil {
			return "", err
		}
	}

	secret, err := v.writeToVault(decryptPath, map[string]interface{}{"ciphertext": cipherText})
	if err != nil {
		logrus.Error(err)
		return "", fmt.Errorf("Issue decrypting secret with %s key", keyName)
	}

	if plainText, ok := secretString(secret, "plaintext"); ok {
		return plainText, nil
	}

	return "", errors.New("Could not decrypt ciphertext")
}

// Sign implements the interface
func (v *Client) Sign(keyName, clearText string) (string, error) {
	if err := validateVaultKeyName(keyName); err != nil {
		return "", err
	}
	hmacPath := fmt.Sprintf("/transit/hmac/%s", url.PathEscape(keyName))
	data := map[string]interface{}{
		"algorithm": "sha2-256",
	}

	nonceResp, err := v.writeToVault("/transit/random/8", map[string]interface{}{})
	if err != nil {
		return "", err
	}

	nonce, ok := secretString(nonceResp, "random_bytes")
	if !ok {
		return "", errors.New("Could not generate nonce")
	}

	data["input"], _ = formatSignatureString(nonce, clearText)

	secret, err := v.writeToVault(hmacPath, data)
	if err != nil {
		return "", err
	}

	if signature, ok := secretString(secret, "hmac"); ok {
		return nonce + ":" + signature, nil
	}

	return "", errors.New("Could not get a signature")
}

// VerifySignature verifies the signature
func (v *Client) VerifySignature(keyName, signature, message string) (bool, error) {
	if err := validateVaultKeyName(keyName); err != nil {
		return false, err
	}
	comparePath := fmt.Sprintf("/transit/verify/%s/sha2-256", url.PathEscape(keyName))

	sigSplit := strings.SplitN(signature, ":", 2)
	if len(sigSplit) != 2 || sigSplit[0] == "" || sigSplit[1] == "" {
		return false, errors.New("Invalid signature format")
	}

	nonce := sigSplit[0]

	data := map[string]interface{}{
		"hmac": sigSplit[1],
	}

	data["input"], _ = formatSignatureString(nonce, message)

	secret, err := v.writeToVault(comparePath, data)
	if err != nil {
		return false, err
	}

	if secret == nil || secret.Data == nil {
		return false, errors.New("Vault verification response is empty")
	}
	verified, ok := secret.Data["valid"].(bool)
	if verified && ok {
		return true, nil
	}
	return false, nil
}

func (v *Client) Delete(keyName, cipherText string) error {
	if err := validateVaultKeyName(keyName); err != nil {
		return err
	}
	if v.storageDir != "" {
		if err := v.validateStoragePath(cipherText); err != nil {
			return err
		}
		client, err := v.getVaultClient()
		if err != nil {
			return err
		}
		_, err = client.Logical().Delete(cipherText)
		if err != nil {
			return err
		}
	}

	return nil
}

func (v *Client) writeToVault(path string, data map[string]interface{}) (*api.Secret, error) {
	vaultClient, err := v.getVaultClient()
	if err != nil {
		return nil, err
	}

	return vaultClient.Logical().Write(path, data)
}

func (v *Client) getStorageDir() (string, error) {
	secret, err := v.writeToVault("/auth/token/lookup-self", map[string]interface{}{})
	if err != nil {
		return "", err
	}

	if secret == nil || secret.Data == nil {
		return "", errors.New("Vault token lookup response is empty")
	}
	if meta, ok := secret.Data["meta"].(map[string]interface{}); ok {
		if storageDir, ok := meta["storage_dir"].(string); ok {
			return normalizeStorageDir(storageDir)
		}
	}

	return "", nil
}

func (v *Client) getVaultClient() (*api.Client, error) {
	config := api.DefaultConfig()
	if err := config.ReadEnvironment(); err != nil {
		return nil, err
	}
	config.Address = v.url
	config.Timeout = vaultRequestTimeout
	if config.HttpClient != nil {
		config.HttpClient.Timeout = vaultRequestTimeout
	}

	client, err := api.NewClient(config)
	if err != nil {
		return nil, err
	}
	client.SetToken(v.token)

	return client, nil
}

func testVaultTransitKeyExists(vaultCli *api.Client, keyName string) (bool, error) {
	if err := validateVaultKeyName(keyName); err != nil {
		return false, err
	}
	exists := false
	keyPath := fmt.Sprintf("/transit/keys/%s", url.PathEscape(keyName))

	secret, err := vaultCli.Logical().Read(keyPath)
	if err != nil {
		return exists, err
	}

	if secret != nil {
		if name, ok := secret.Data["name"]; ok && name == keyName {
			exists = true
		}
	}

	return exists, nil
}

func formatSignatureString(nonce, data string) (string, error) {
	return base64.StdEncoding.EncodeToString([]byte(nonce + ":" + data)), nil
}

func (v *Client) storeSecretInVault(cipherText string) (string, error) {
	// write secret to path in Vault
	hash := sha256.New()
	hash.Write([]byte(cipherText))

	path := fmt.Sprintf("%s/v1-secrets/%x", v.storageDir, hash.Sum(nil))

	_, err := v.writeToVault(path, map[string]interface{}{
		"cipherText": cipherText,
	})
	if err != nil {
		return "", err
	}

	// we will just pass back the location
	return path, nil
}

func (v *Client) retrieveSecretFromVault(path string) (string, error) {
	if err := v.validateStoragePath(path); err != nil {
		return "", err
	}
	cli, err := v.getVaultClient()
	if err != nil {
		return "", err
	}

	secret, err := cli.Logical().Read(path)
	if err != nil {
		return "", err
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("No secret data at this location")
	}
	if text, ok := secret.Data["cipherText"].(string); ok {
		return text, nil
	}

	return "", fmt.Errorf("No CipherText at this location")
}

func validateVaultAddress(address string) error {
	parsed, err := url.ParseRequestURI(address)
	if err != nil {
		return fmt.Errorf("invalid Vault address: %w", err)
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return errors.New("Vault address must use http or https and include a host")
	}
	if parsed.Scheme == "http" {
		host := parsed.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return errors.New("plain HTTP Vault addresses are restricted to loopback")
		}
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("Vault address must not include credentials, query parameters, or a fragment")
	}
	return nil
}

func validateVaultKeyName(keyName string) error {
	if keyName == "" || keyName == "." || keyName == ".." ||
		strings.ContainsAny(keyName, "/\\\x00\r\n") {
		return errors.New("invalid Vault key name")
	}
	return nil
}

func normalizeStorageDir(storageDir string) (string, error) {
	storageDir = strings.Trim(storageDir, "/")
	if storageDir == "" {
		return "", nil
	}
	if strings.ContainsAny(storageDir, "\\\x00\r\n") {
		return "", errors.New("invalid Vault storage directory")
	}
	cleaned := path.Clean(storageDir)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", errors.New("invalid Vault storage directory")
	}
	return cleaned, nil
}

func (v *Client) validateStoragePath(storagePath string) error {
	prefix := v.storageDir + "/v1-secrets/"
	if v.storageDir == "" || !strings.HasPrefix(storagePath, prefix) {
		return errors.New("Vault storage path is outside the configured secret directory")
	}
	digest := strings.TrimPrefix(storagePath, prefix)
	if strings.Contains(digest, "/") || len(digest) != sha256.Size*2 || digest != strings.ToLower(digest) {
		return errors.New("Vault storage path has an invalid digest")
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size {
		return errors.New("Vault storage path has an invalid digest")
	}
	return nil
}

func secretString(secret *api.Secret, key string) (string, bool) {
	if secret == nil || secret.Data == nil {
		return "", false
	}
	value, ok := secret.Data[key].(string)
	return value, ok && value != ""
}
