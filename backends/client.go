// Modified by PastureStack in 2026: neutral internal package paths.
package backends

import (
	"errors"

	"github.com/PastureStack/secret-delivery-api/backends/localkey"
	"github.com/PastureStack/secret-delivery-api/backends/none"
	"github.com/PastureStack/secret-delivery-api/backends/vault"
)

var runtimeConfigs *Configs

// EncryptorClient defines the interface for backend encryption clients
type EncryptorClient interface {
	GetEncryptedText(keyName string, clearText string) (string, error)
	GetClearText(keyName string, cipherText string) (string, error)
	Sign(keyName string, text string) (string, error)
	VerifySignature(keyName string, signature string, message string) (bool, error)
	Delete(keyName, cipherText string) error
}

// New returns an encrytion client of a specific type
func New(name string) (EncryptorClient, error) {
	if runtimeConfigs == nil {
		return nil, errors.New("backend configuration is not initialized")
	}

	switch name {
	case "none":
		if runtimeConfigs.AllowInsecureNoneBackend {
			return &none.Client{}, nil
		}
		return nil, errors.New("insecure none backend is disabled")
	case "localkey":
		if runtimeConfigs.EncryptionKeyPath != "" {
			return localkey.NewLocalKey(runtimeConfigs.EncryptionKeyPath)
		}
		return nil, errors.New("local key backend is not configured")
	case "vault":
		if runtimeConfigs.VaultURL != "" && runtimeConfigs.VaultToken != "" {
			return vault.NewClient(runtimeConfigs.VaultURL, runtimeConfigs.VaultToken)
		}
		return nil, errors.New("Vault backend is not configured")
	default:
		return nil, errors.New("unknown encryption backend")
	}
}
