package localkey

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

const secretText = "my secret to keep"

func TestLocalKeyClientRoundTripAndSignature(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "test-key"),
		[]byte("01234567890123456789012345678901"), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := NewLocalKey(directory)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := client.GetEncryptedText("test-key", secretText)
	if err != nil {
		t.Fatal(err)
	}
	clearText, err := client.GetClearText("test-key", encrypted)
	if err != nil {
		t.Fatal(err)
	}
	if clearText != secretText {
		t.Fatalf("decrypted %q, want %q", clearText, secretText)
	}
	signature, err := client.Sign("test-key", clearText)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := client.VerifySignature("test-key", signature, clearText)
	if err != nil || !verified {
		t.Fatalf("signature did not verify: %v, %v", verified, err)
	}
	verified, err = client.VerifySignature("test-key", signature, "tampered")
	if err != nil || verified {
		t.Fatalf("tampered message verification result: %v, %v", verified, err)
	}
	if err := client.Delete("test-key", encrypted); err != nil {
		t.Fatalf("local delete should be a no-op: %v", err)
	}
}

func TestNewLocalKeyRejectsMissingOrNonDirectoryPath(t *testing.T) {
	if _, err := NewLocalKey(""); err == nil {
		t.Fatal("expected empty key directory error")
	}
	file := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(file, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewLocalKey(file); err == nil {
		t.Fatal("expected non-directory key path error")
	}
}

func TestLocalKeyRejectsMissingAndWrongLengthKeys(t *testing.T) {
	directory := t.TempDir()
	client, err := NewLocalKey(directory)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetEncryptedText("missing", secretText); err == nil {
		t.Fatal("expected missing key error")
	}
	if err := os.WriteFile(filepath.Join(directory, "short"), []byte("too-short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetEncryptedText("short", secretText); err == nil {
		t.Fatal("expected wrong key length error")
	}
	for _, keyName := range []string{"", ".", "..", "../outside", `folder\key`, "line\nfeed"} {
		if _, err := client.GetEncryptedText(keyName, secretText); err == nil {
			t.Fatalf("expected key name %q to be rejected", keyName)
		}
	}
}

func TestLocalKeyRejectsInsecureFilesOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not expose Unix key-file mode bits")
	}
	directory := t.TempDir()
	client, err := NewLocalKey(directory)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "world-readable")
	if err := os.WriteFile(keyPath, []byte("01234567890123456789012345678901"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetEncryptedText("world-readable", secretText); err == nil {
		t.Fatal("expected group/world-readable key to be rejected")
	}
	if err := os.Chmod(keyPath, 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "symlink")
	if err := os.Symlink(keyPath, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := client.GetEncryptedText("symlink", secretText); err == nil {
		t.Fatal("expected symlink key to be rejected")
	}
}
