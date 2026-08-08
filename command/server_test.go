package command

import (
	"flag"
	"testing"

	"github.com/PastureStack/secret-delivery-api/backends"
	"github.com/urfave/cli"
)

func TestServerCommandUsesSafeLoopbackDefaultAndExplicitLegacyOptIn(t *testing.T) {
	command := ServerCommand()
	set := flag.NewFlagSet("server", flag.ContinueOnError)
	for _, cliFlag := range command.Flags {
		cliFlag.Apply(set)
	}
	context := cli.NewContext(cli.NewApp(), set, nil)
	if got := context.String("listen-address"); got != "127.0.0.1:8181" {
		t.Fatalf("unexpected default listen address %q", got)
	}
	if context.Bool("allow-insecure-none-backend") {
		t.Fatal("insecure compatibility backend is enabled by default")
	}
}

func TestStartServerPropagatesListenFailureAfterApplyingConfiguration(t *testing.T) {
	command := ServerCommand()
	set := flag.NewFlagSet("server", flag.ContinueOnError)
	for _, cliFlag := range command.Flags {
		cliFlag.Apply(set)
	}
	if err := set.Parse([]string{"--listen-address", "invalid address", "--allow-insecure-none-backend"}); err != nil {
		t.Fatal(err)
	}
	context := cli.NewContext(cli.NewApp(), set, nil)
	if err := startServer(context); err == nil {
		t.Fatal("expected invalid listen address error")
	}
	if _, err := backends.New("none"); err != nil {
		t.Fatalf("startServer did not apply explicit compatibility opt-in: %v", err)
	}
}
