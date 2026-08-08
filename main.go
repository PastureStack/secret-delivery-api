// Modified by PastureStack in 2026: neutral identity and compatibility settings.
package main

import (
	"os"

	"github.com/PastureStack/secret-delivery-api/command"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

var VERSION = "v0.0.0-dev"

func beforeApp(c *cli.Context) error {
	if c.GlobalBool("debug") {
		logrus.SetLevel(logrus.DebugLevel)
	}
	return nil
}

func main() {
	app := cli.NewApp()
	app.Name = "secret-delivery-api"
	app.Version = VERSION
	app.Usage = "secret delivery API server"
	app.Before = beforeApp
	app.Flags = []cli.Flag{
		cli.BoolFlag{
			Name:   "debug,d",
			EnvVar: "PASTURESTACK_SECRET_DELIVERY_API_DEBUG,DEFAULT_CATTLE_SECRETS_API_DEBUG",
		},
	}

	app.Commands = []cli.Command{
		command.ServerCommand(),
	}

	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}
