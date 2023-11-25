package main

import (
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v2"

	"ntwrk.space/mmaths/hashid/internal/commands"
)

func main() {
	app := &cli.App{
		Name:        "hashID",
		Usage:       "hash identifier",
		Description: "Identify the different types of hashes used to encrypt data and especially passwords.",
		Version:     "0.0.1",
		Copyright:   "MIT",
		UsageText:   "hashID [global options] command [command options] [arguments...]",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:    "exotic",
				Aliases: []string{"x"},
				Usage:   "Show exotic hash types",
			},
			&cli.BoolFlag{
				Name:    "extended",
				Aliases: []string{"e"},
				Usage:   "Show extended hash types",
			},
			&cli.BoolFlag{
				Name:    "mode",
				Aliases: []string{"m"},
				Usage:   "Show hashcat mode",
			},
			&cli.BoolFlag{
				Name:    "format",
				Aliases: []string{"f"},
				Usage:   "Show JohntheRipper format",
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "Output destination file (default: stdout)",
			},
		},
		DefaultCommand: "identify",
		Action:         commands.IdentifySingleHash,
		Commands: []*cli.Command{
			commands.IdentifyCommand(),
			commands.FileCommand(),
		},
		OnUsageError: func(c *cli.Context, err error, isSubcommand bool) error {
			fmt.Fprintf(c.App.Writer, "Error: %s\n", err.Error())
			cli.ShowAppHelp(c)
			return nil
		},
		UseShortOptionHandling: true,
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
