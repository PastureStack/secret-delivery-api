// Modified by PastureStack in 2026: neutral internal package path and wording.
package service

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/PastureStack/secret-delivery-api/compat/controlplane/api"
	"github.com/PastureStack/secret-delivery-api/compat/controlplane/client"
	"github.com/PastureStack/secret-delivery-api/secrets"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// HandleError is a wrapper that handles response codes and error messages
func HandleError(s *client.Schemas, t func(http.ResponseWriter, *http.Request) (int, error)) http.Handler {
	return api.ApiHandler(s, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if code, err := t(rw, req); err != nil {
			logrus.Errorf("Error in request, code : %d: %s", code, err)
			apiContext := api.GetApiContext(req)
			rw.Header().Set("Content-Type", "application/json")
			rw.WriteHeader(code)

			apiContext.Write(&errObj{
				Resource: client.Resource{
					Type: "error",
				},
				Status:  strconv.Itoa(code),
				Message: safeErrorMessage(code),
			})
		}
	}))
}

// NewRouter creates the router and wires up the preserved control-plane API schema.
func NewRouter() *mux.Router {
	schemas := &client.Schemas{}
	f := HandleError

	schemas.AddType("apiVersion", client.Resource{})
	schemas.AddType("schema", client.Schema{})

	schemas.AddType("bulkSecretInput", secrets.BulkSecretInput{})
	schemas.AddType("bulkEncryptedSecret", secrets.BulkEncryptedSecret{})
	schemas.AddType("bulkRewrappedSecret", secrets.BulkRewrappedSecret{})

	schemas.AddType("secretInput", secrets.UnencryptedSecret{})
	schemas.AddType("encryptedSecret", secrets.EncryptedSecret{})
	schemas.AddType("rewrappedSecret", secrets.RewrappedSecret{})

	secret := schemas.AddType("secret", secrets.Secret{})
	secret.CollectionMethods = []string{"GET"}
	secret.CollectionActions = map[string]client.Action{
		"rewrap": {
			Input:  "encryptedSecret",
			Output: "rewrappedSecret",
		},
		"rewrap?action=bulk": {
			Input:  "bulkSecretInput",
			Output: "bulkEncryptedSecret",
		},
		"create": {
			Input:  "secretInput",
			Output: "encryptedSecret",
		},
		"create?action=bulk": {
			Input:  "bulkSecretInput",
			Output: "bulkEncryptedSecret",
		},
		"purge": {
			Input:  "encryptedSecret",
			Output: "encryptedSecret",
		},
		"purge?action=bulk": {
			Input:  "bulkEncryptedSecret",
			Output: "bulkEncryptedSecret",
		},
	}

	router := mux.NewRouter().StrictSlash(false)
	router.Use(securityHeaders)

	// Preserved control-plane compatibility routes.
	router.Methods("GET").Path("/v1-secrets").Handler(api.VersionHandler(schemas, "v1-secrets"))
	router.Methods("GET").Path("/v1-secrets/").Handler(api.VersionHandler(schemas, "v1-secrets"))

	router.Methods("GET").Path("/v1-secrets/schemas").Handler(api.SchemasHandler(schemas))
	router.Methods("GET").Path("/v1-secrets/schemas/").Handler(api.SchemasHandler(schemas))

	router.Methods("GET").Path("/v1-secrets/schemas/{id}").Handler(api.SchemaHandler(schemas))
	router.Methods("GET").Path("/v1-secrets/schemas/{id}/").Handler(api.SchemaHandler(schemas))

	router.Methods("GET").Path("/v1-secrets/secrets").Handler(f(schemas, ListSecrets))
	router.Methods("GET").Path("/v1-secrets/secrets/").Handler(f(schemas, ListSecrets))

	err := schemas.AddType("error", errObj{})
	err.CollectionMethods = []string{}

	//Application Routes -- Order matters here
	router.Methods("POST").
		Path("/v1-secrets/secrets/create").
		Queries("action", "bulk").
		Handler(f(schemas, BulkCreateSecret))

	router.Methods("POST").Path("/v1-secrets/secrets/create").Handler(f(schemas, CreateSecret))

	router.Methods("POST").
		Path("/v1-secrets/secrets/rewrap").
		Queries("action", "bulk").
		Handler(f(schemas, BulkRewrapSecret))

	router.Methods("POST").Path("/v1-secrets/secrets/rewrap").Handler(f(schemas, RewrapSecret))

	router.Methods("POST").
		Path("/v1-secrets/secrets/purge").
		Queries("action", "bulk").
		Handler(f(schemas, BulkDeleteSecret))

	router.Methods("POST").
		Path("/v1-secrets/secrets/purge").
		Handler(f(schemas, DeleteSecret))

	// These just loop back to themselves in the schemas
	router.Methods("GET").Path("/v1-secrets/secrets/create").Handler(f(schemas, ListSecrets))
	router.Methods("GET").Path("/v1-secrets/secrets/create/").Handler(f(schemas, ListSecrets))

	router.Methods("GET").Path("/v1-secrets/secrets/rewrap").Handler(f(schemas, ListSecrets))
	router.Methods("GET").Path("/v1-secrets/secrets/rewrap/").Handler(f(schemas, ListSecrets))

	router.Methods("GET").Path("/v1-secrets/secrets/create").Queries("action", "bulk").Handler(f(schemas, ListSecrets))
	router.Methods("GET").Path("/v1-secrets/secrets/create/").Queries("action", "bulk").Handler(f(schemas, ListSecrets))
	router.Methods("GET").Path("/v1-secrets/secrets/rewrap").Queries("action", "bulk").Handler(f(schemas, ListSecrets))
	router.Methods("GET").Path("/v1-secrets/secrets/rewrap/").Queries("action", "bulk").Handler(f(schemas, ListSecrets))

	router.NotFoundHandler = f(schemas, func(w http.ResponseWriter, req *http.Request) (int, error) {
		return 404, errors.New("Not found")
	})

	return router
}

func safeErrorMessage(code int) string {
	switch code {
	case http.StatusBadRequest:
		return "Invalid request"
	case http.StatusNotFound:
		return "Not found"
	default:
		if message := http.StatusText(code); message != "" {
			return message
		}
		return "Request failed"
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
