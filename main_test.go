package main

import (
	"flag"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/urfave/cli"
)

func TestBeforeAppAppliesDebugLevel(t *testing.T) {
	previous := logrus.GetLevel()
	t.Cleanup(func() { logrus.SetLevel(previous) })
	set := flag.NewFlagSet("app", flag.ContinueOnError)
	set.Bool("debug", false, "")
	if err := set.Set("debug", "true"); err != nil {
		t.Fatal(err)
	}
	context := cli.NewContext(cli.NewApp(), set, nil)
	if err := beforeApp(context); err != nil {
		t.Fatal(err)
	}
	if logrus.GetLevel() != logrus.DebugLevel {
		t.Fatalf("unexpected log level %s", logrus.GetLevel())
	}
}
