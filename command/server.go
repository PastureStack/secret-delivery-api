// Modified by PastureStack in 2026: neutral package path and operator wording.
package command

import (
	"github.com/PastureStack/secret-delivery-api/backends"
	"github.com/PastureStack/secret-delivery-api/service"
	"github.com/urfave/cli"
)

func ServerCommand() cli.Command {
	return cli.Command{
		Name:   "server",
		Usage:  "Start the Secret Delivery API server",
		Action: startServer,
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:   "enc-key-path",
				Usage:  "Encryption key file to use for localkey encryption",
				EnvVar: "ENC_KEY_PATH",
			},
			cli.StringFlag{
				Name:   "vault-url",
				Usage:  "URL For Vault server with Transit backend enabled",
				EnvVar: "VAULT_ADDR",
			},
			cli.StringFlag{
				Name:   "vault-token",
				Usage:  "URL For Vault server with Transit backend enabled",
				EnvVar: "VAULT_TOKEN",
			},
			cli.StringFlag{
				Name:   "listen-address",
				Usage:  "Address to listen on",
				Value:  "127.0.0.1:8181",
				EnvVar: "SECRETS_API_LISTEN_ADDRESS",
			},
			cli.BoolFlag{
				Name:   "allow-insecure-none-backend",
				Usage:  "Allow the legacy unencrypted compatibility backend",
				EnvVar: "ALLOW_INSECURE_NONE_BACKEND",
			},
		},
	}
}

func startServer(c *cli.Context) error {
	backendConfig := backends.NewConfig()

	backendConfig.EncryptionKeyPath = c.String("enc-key-path")
	backendConfig.VaultURL = c.String("vault-url")
	backendConfig.VaultToken = c.String("vault-token")
	backendConfig.AllowInsecureNoneBackend = c.Bool("allow-insecure-none-backend")

	if err := backends.SetBackendConfigs(backendConfig); err != nil {
		return err
	}

	return service.StartServer(c.String("listen-address"))
}
