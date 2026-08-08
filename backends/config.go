package backends

import "errors"

type Configs struct {
	VaultToken               string
	VaultURL                 string
	EncryptionKeyPath        string
	AllowInsecureNoneBackend bool
}

func NewConfig() *Configs {
	return &Configs{}
}

func SetBackendConfigs(config *Configs) error {
	if config == nil {
		return errors.New("backend configuration is required")
	}
	copy := *config
	runtimeConfigs = &copy
	return nil
}
