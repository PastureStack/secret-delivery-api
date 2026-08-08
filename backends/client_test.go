package backends

import "testing"

func TestNewRequiresInitializedConfiguration(t *testing.T) {
	runtimeConfigs = nil
	if _, err := New("localkey"); err == nil {
		t.Fatal("expected uninitialized backend configuration error")
	}
	if err := SetBackendConfigs(nil); err == nil {
		t.Fatal("expected nil backend configuration error")
	}
}

func TestNoneBackendRequiresExplicitOptIn(t *testing.T) {
	if err := SetBackendConfigs(NewConfig()); err != nil {
		t.Fatal(err)
	}
	if _, err := New("none"); err == nil {
		t.Fatal("expected insecure compatibility backend to be disabled")
	}

	config := NewConfig()
	config.AllowInsecureNoneBackend = true
	if err := SetBackendConfigs(config); err != nil {
		t.Fatal(err)
	}
	config.AllowInsecureNoneBackend = false
	if _, err := New("none"); err != nil {
		t.Fatalf("explicitly enabled compatibility backend was rejected: %v", err)
	}
}

func TestNewLocalKeyAndUnknownBackends(t *testing.T) {
	config := NewConfig()
	config.EncryptionKeyPath = t.TempDir()
	if err := SetBackendConfigs(config); err != nil {
		t.Fatal(err)
	}
	if _, err := New("localkey"); err != nil {
		t.Fatalf("configured local key backend was rejected: %v", err)
	}
	if _, err := New("unknown"); err == nil {
		t.Fatal("expected unknown backend error")
	}
}
