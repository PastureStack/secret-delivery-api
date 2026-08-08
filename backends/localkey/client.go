// Modified by PastureStack in 2026: neutral internal package path.
package localkey

import (
	"errors"
	"os"
	"runtime"
	"strings"

	"github.com/PastureStack/secret-delivery-api/pkg/aesutils"
)

// Client implements the backend client interface
type Client struct {
	encryptionKeyPath string
}

// support both IV and Nonce for non-breaking
type internalSecret struct {
	Nonce      []byte `json:"nonce,omitempty"`
	IV         []byte `json:"iv,ommitempty"`
	Algorithm  string
	CipherText []byte
}

// NewLocalKey initializes a new local key
func NewLocalKey(keyPath string) (*Client, error) {
	err := errors.New("No encryption key path configured. Must be a directory")

	if keyPath != "" {
		if isDir, err := testIsDir(keyPath); isDir && err == nil {
			return &Client{encryptionKeyPath: keyPath}, nil
		}
	}

	return &Client{}, err
}

func (l *Client) loadEncryptionKeyFromPath(keyName string) (aesutils.AESKey, error) {
	if keyName == "" || keyName == "." || keyName == ".." ||
		strings.ContainsAny(keyName, "/\\\x00\r\n") {
		return nil, errors.New("invalid local key name")
	}
	root, err := os.OpenRoot(l.encryptionKeyPath) // #nosec G304 -- administrator-supplied key directory
	if err != nil {
		return nil, err
	}
	defer root.Close()

	info, err := root.Lstat(keyName)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("local encryption key must be a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("local encryption key permissions must not allow group or other access")
	}

	keyBytes, err := root.ReadFile(keyName)
	if err != nil {
		return nil, err
	}
	return aesutils.NewAESKeyFromBytes(keyBytes), nil
}

// GetEncryptedText localkey Client just returns the clearText
func (l *Client) GetEncryptedText(keyName, clearText string) (string, error) {
	key, err := l.loadEncryptionKeyFromPath(keyName)
	if err != nil {
		return "", err
	}

	return aesutils.GetEncryptedText(key, clearText, "aes256-gcm")
}

// GetClearText localkey Client
func (l *Client) GetClearText(keyName, secretBlob string) (string, error) {
	key, err := l.loadEncryptionKeyFromPath(keyName)
	if err != nil {
		return "", err
	}

	return aesutils.GetClearText(key, secretBlob)
}

// Sign implements the interface
func (l *Client) Sign(keyName, clearText string) (string, error) {
	key, err := l.loadEncryptionKeyFromPath(keyName)
	if err != nil {
		return "", err
	}

	return aesutils.Sign(key, clearText)
}

// VerifySignature implements the interface.
func (l *Client) VerifySignature(keyName, signature, message string) (bool, error) {
	key, err := l.loadEncryptionKeyFromPath(keyName)
	if err != nil {
		return false, err
	}

	return aesutils.VerifySignature(key, signature, message)
}

// Delete No op nothing stored
func (l *Client) Delete(keyName, cipherText string) error {
	return nil
}

func testIsDir(keyPath string) (bool, error) {
	root, err := os.OpenRoot(keyPath) // #nosec G304 -- keyPath is administrator-supplied process configuration
	if err != nil {
		return false, err
	}
	if err := root.Close(); err != nil {
		return false, err
	}

	return true, nil
}
