package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/urfave/cli/v3"

	"ntwrk.space/mmaths/hashid/pkg/hashtypes"
)

// hashCommand returns the hash command.
func hashCommand() *cli.Command {
	return &cli.Command{
		Name:      "hash",
		Usage:     "Identify hash from input string",
		Aliases:   []string{"id"},
		ArgsUsage: "HASH",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:     "hashcat",
				Usage:    "show hashcat mode",
				Aliases:  []string{"m"},
				OnlyOnce: true,
			},
			&cli.BoolFlag{
				Name:     "john",
				Usage:    "show JohnTheRipper format",
				Aliases:  []string{"j"},
				OnlyOnce: true,
			},
			&cli.BoolFlag{
				Name:     "unknown",
				Usage:    "hide unknown hash types",
				Aliases:  []string{"u"},
				OnlyOnce: true,
			},
		},
		UseShortOptionHandling: true,
		Action: func(ctx context.Context, c *cli.Command) error {
			if c.Args().Len() == 0 {
				return cli.ShowAppHelp(c)
			}

			_, err := processStringInput(ctx, c)
			if err != nil {
				return err
			}

			return nil
		},
	}
}

// processStringInput processes the input string and returns the results.
func processStringInput(ctx context.Context, c *cli.Command) (map[string][]hashtypes.Hash, error) {
	results := make(map[string][]hashtypes.Hash, 0)
	htypes, err := hashtypes.New()
	if err != nil {
		return results, err
	}
	for _, arg := range c.Args().Slice() {
		str := strings.TrimSpace(arg)
		result := htypes.FindHashType(str)
		filtered := filterResults(c, result)
		results[str] = filtered
		if c.IsSet("unknown") && len(filtered) == 0 {
			continue
		}
		o, err := formatOutput(c, str, filtered)
		if err != nil {
			return results, err
		}
		fmt.Fprintf(c.Root().Writer, "%s\n", o)
	}

	return results, nil
}
