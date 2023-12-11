// Package main is the entry point of the hashID application.
package main

import (
	"context"
	"os"

	"ntwrk.space/mmaths/hashid/internal/commands"
)

func main() {
	app := commands.RootCommand()
	err := app.Run(context.Background(), os.Args)
	if err != nil {
		os.Exit(1)
	}
}
