// Modified by PastureStack in 2026: neutral internal package path.
package secrets

import (
	"errors"

	"github.com/PastureStack/secret-delivery-api/compat/controlplane/client"
	"github.com/PastureStack/secret-delivery-api/pkg/aesutils"
	"github.com/sirupsen/logrus"
)

func NewBulkSecretInput() *BulkSecretInput {

	return &BulkSecretInput{
		Resource: client.Resource{
			Type: "bulkSecretInput",
		},
		Data: []*UnencryptedSecret{},
	}
}

func GetBulkEncryptedSecretResource() *BulkEncryptedSecret {
	return &BulkEncryptedSecret{}
}

func NewBulkEncryptedSecret(secretInput *BulkSecretInput) (*BulkEncryptedSecret, error) {
	if secretInput == nil {
		return nil, errors.New("bulk secret input is required")
	}
	bsi := &BulkEncryptedSecret{
		Resource: client.Resource{
			Type: "bulkEncryptedSecret",
		},
		Data: []*EncryptedSecret{},
	}

	return bsi, bsi.seal(secretInput.Data)
}

func NewBulkRewrappedSecret(secrets *BulkEncryptedSecret) (*BulkRewrappedSecret, error) {
	if secrets == nil {
		return nil, errors.New("bulk encrypted secret is required")
	}
	brs := &BulkRewrappedSecret{
		Resource: client.Resource{
			Type: "bulkRewrappedSecret",
		},
	}

	return brs, brs.rewrap(secrets)
}

func (bes *BulkEncryptedSecret) Delete() error {
	if bes == nil {
		return errors.New("bulk encrypted secret is required")
	}
	for _, secret := range bes.Data {
		if secret == nil {
			return errors.New("bulk encrypted secret contains a null item")
		}
		err := secret.Delete()
		if err != nil {
			logrus.Error(err)
			return err
		}
	}

	return nil
}

func (s *BulkRewrappedSecret) rewrap(secrets *BulkEncryptedSecret) error {
	tmpKey, err := aesutils.NewRandomAESKey(32)
	if err != nil {
		return err
	}

	for _, secret := range secrets.Data {
		if secret == nil {
			return errors.New("bulk encrypted secret contains a null item")
		}
		secret.SetTmpKey(tmpKey)
		secret.RewrapKey = secrets.RewrapKey

		rewrapped, err := NewRewrappedSecret(secret)
		if err != nil {
			logrus.Errorf("Could not decrypt secret")
			return err
		}
		s.Data = append(s.Data, rewrapped)
	}

	return nil
}

func (bes *BulkEncryptedSecret) seal(clearData []*UnencryptedSecret) error {
	for _, clear := range clearData {
		if clear == nil {
			return errors.New("bulk secret input contains a null item")
		}
		secret, err := NewEncryptedSecret(clear)
		if err != nil {
			logrus.Error(err)
			return err
		}
		bes.Data = append(bes.Data, secret)
	}
	return nil
}
