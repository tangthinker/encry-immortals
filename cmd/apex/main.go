// Command apex is the CLI entry point.
package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/tangthinker/encry-immortals/internal/cli"
)

// version is overridable with -ldflags "-X main.version=...".
var version = "0.1.0-dev"

func main() {
	cli.Version = version
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigs
		os.Exit(130)
	}()
	app := &cli.App{}
	os.Exit(app.Run(os.Args[1:]))
}
