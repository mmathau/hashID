package main

import (
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v2"

	"ntwrk.space/mmaths/hashid/internal/commands"
)

func main() {
	categoryHashOptions := "Hash Options:"
	app := &cli.App{
		Name:                   "hashID",
		Usage:                  "hash identifier",
		Description:            "Identify the different types of hashes used to encrypt data and especially passwords.",
		Version:                "0.0.1",
		UsageText:              "hashID [global options] command [command options] [arguments...]",
		DefaultCommand:         "hash",
		UseShortOptionHandling: true,
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Category: categoryHashOptions,
				Name:     "exotic",
				Aliases:  []string{"x"},
				Usage:    "show exotic hash types",
			},
			&cli.BoolFlag{
				Category: categoryHashOptions,
				Name:     "extended",
				Aliases:  []string{"e"},
				Usage:    "show extended hash types",
			},
			&cli.BoolFlag{
				Category: categoryHashOptions,
				Name:     "hashcat",
				Aliases:  []string{"m"},
				Usage:    "show hashcat mode",
			},
			&cli.BoolFlag{
				Category: categoryHashOptions,
				Name:     "john",
				Aliases:  []string{"j"},
				Usage:    "show JohntheRipper format",
			},
			&cli.StringFlag{
				Name:    "output",
				Aliases: []string{"o"},
				Usage:   "set output format `[json|xml]`",
				Action: func(c *cli.Context, s string) error {
					if s != "json" && s != "xml" {
						return fmt.Errorf("invalid output format: %s", s)
					}
					return nil
				},
			},
			&cli.BoolFlag{
				Name:    "quiet",
				Aliases: []string{"q"},
				Usage:   "suppress unknown hash output",
			},
		},
		Action: commands.IdentifyHashesFromString,
		Commands: []*cli.Command{
			commands.HashCommand(),
			commands.FileCommand(),
		},
		OnUsageError: func(c *cli.Context, err error, isSubcommand bool) error {
			fmt.Fprintf(c.App.Writer, "Error: %s\n", err.Error())
			cli.ShowAppHelp(c)
			return nil
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
