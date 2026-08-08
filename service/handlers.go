// Modified by PastureStack in 2026: neutral internal package path and safe errors.
package service

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/PastureStack/secret-delivery-api/compat/controlplane/api"
	"github.com/PastureStack/secret-delivery-api/compat/controlplane/client"
	"github.com/PastureStack/secret-delivery-api/secrets"
	"github.com/sirupsen/logrus"
)

const maxRequestBodyBytes int64 = 1 << 20

type errObj struct {
	client.Resource
	Status  string `json:"status,omitempty"`
	Message string `json:"message,omitempty"`
}

// ListSecrets to make schemas work better
func ListSecrets(w http.ResponseWriter, r *http.Request) (int, error) {
	apiContext := api.GetApiContext(r)
	secretCollection := &secrets.SecretCollection{
		Collection: client.Collection{
			ResourceType: "secret",
		},
	}
	secretCollection.Actions = map[string]string{
		"create":             apiContext.UrlBuilder.Collection("secret") + "/create",
		"rewrap":             apiContext.UrlBuilder.Collection("secret") + "/rewrap",
		"purge":              apiContext.UrlBuilder.Collection("secret") + "/purge",
		"rewrap?action=bulk": apiContext.UrlBuilder.Collection("secret") + "/rewrap?action=bulk",
		"create?action=bulk": apiContext.UrlBuilder.Collection("secret") + "/create?action=bulk",
		"purge?action=bulk":  apiContext.UrlBuilder.Collection("secret") + "/purge?action=bulk",
	}

	apiContext.Write(secretCollection)

	return http.StatusOK, nil
}

// CreateSecret POST handler for route /secrets to create a new secret
func CreateSecret(w http.ResponseWriter, r *http.Request) (int, error) {
	apiContext := api.GetApiContext(r)

	sec := secrets.NewUnencryptedSecret(apiContext)

	err := decodeJSONBody(w, r, sec)
	if err != nil {
		logrus.Errorf("Could not decode request body: %s", err)
		return http.StatusBadRequest, err
	}

	secret, err := secrets.NewEncryptedSecret(sec)
	if err != nil {
		logrus.Errorf("Could not encrypt secret")
		logrus.Error(err)
		return http.StatusBadRequest, err
	}

	apiContext.Write(&secret)

	return http.StatusOK, nil
}

// BulkCreateSecret handles creating a list of multiple secrets and generating response
func BulkCreateSecret(w http.ResponseWriter, r *http.Request) (int, error) {
	apiContext := api.GetApiContext(r)
	bulkSecret := secrets.NewBulkSecretInput()

	err := decodeJSONBody(w, r, bulkSecret)
	if err != nil {
		return http.StatusBadRequest, err
	}

	bulkSecrets, err := secrets.NewBulkEncryptedSecret(bulkSecret)
	if err != nil {
		logrus.Error(err)
		return http.StatusBadRequest, err
	}

	apiContext.Write(bulkSecrets)
	return http.StatusOK, nil
}

// RewrapSecret rewraps a single secret witha  usersupplied public key
func RewrapSecret(w http.ResponseWriter, r *http.Request) (int, error) {
	apiContext := api.GetApiContext(r)

	sec := secrets.GetEncryptedSecretResource()

	err := decodeJSONBody(w, r, sec)
	if err != nil {
		logrus.Errorf("Could not decode request body: %s", err)
		return http.StatusBadRequest, err
	}

	secret, err := secrets.NewRewrappedSecret(sec)
	if err != nil {
		logrus.Errorf("Could not rewrap secret")
		return http.StatusBadRequest, err
	}

	apiContext.Write(&secret)
	return http.StatusOK, nil
}

// BulkRewrapSecret rewraps multiple secrets with a single given public key
func BulkRewrapSecret(w http.ResponseWriter, r *http.Request) (int, error) {
	apiContext := api.GetApiContext(r)
	bulkSecret := secrets.GetBulkEncryptedSecretResource()

	err := decodeJSONBody(w, r, bulkSecret)
	if err != nil {
		logrus.Errorf("Could not decode request body: %s", err)
		return http.StatusBadRequest, err
	}

	bulkRewrapped, err := secrets.NewBulkRewrappedSecret(bulkSecret)
	if err != nil {
		logrus.Error(err)
		return http.StatusBadRequest, err
	}

	apiContext.Write(&bulkRewrapped)
	return http.StatusOK, nil
}

// DeleteSecret provides a hook to the backend to clear out data.
func DeleteSecret(w http.ResponseWriter, r *http.Request) (int, error) {
	sec := secrets.GetEncryptedSecretResource()

	err := decodeJSONBody(w, r, sec)
	if err != nil {
		logrus.Errorf("Could not decode request body: %s", err)
		return http.StatusBadRequest, err
	}

	err = sec.Delete()
	if err != nil {
		logrus.Error(err)
		return http.StatusBadRequest, err
	}

	w.WriteHeader(http.StatusNoContent)
	return http.StatusNoContent, nil
}

// BulkDeleteSecret provides a hook to the backend to clear out data.
func BulkDeleteSecret(w http.ResponseWriter, r *http.Request) (int, error) {
	bulkSecret := secrets.GetBulkEncryptedSecretResource()

	err := decodeJSONBody(w, r, bulkSecret)
	if err != nil {
		logrus.Errorf("Could not decode request body: %s", err)
		return http.StatusBadRequest, err
	}

	err = bulkSecret.Delete()
	if err != nil {
		logrus.Error(err)
		return http.StatusBadRequest, err
	}

	w.WriteHeader(http.StatusNoContent)
	return http.StatusNoContent, nil
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, destination interface{}) error {
	if r == nil || r.Body == nil {
		return errors.New("request body is required")
	}
	if destination == nil {
		return errors.New("JSON destination is required")
	}

	limited := http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 || bytes.Equal(body, []byte("null")) {
		return errors.New("request body must contain a JSON object")
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra interface{}
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain exactly one JSON value")
		}
		return err
	}
	return nil
}

// URLEncoded encodes the urls so that spaces are allowed in resource names
func URLEncoded(str string) string {
	u, err := url.Parse(str)
	if err != nil {
		logrus.Errorf("Error encoding the url: %s , error: %v", str, err)
		return str
	}
	return u.String()
}
