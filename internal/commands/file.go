package commands

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v3"

	"ntwrk.space/mmaths/hashid/pkg/hashtypes"
)

// fileCommand returns the file command.
func fileCommand() *cli.Command {
	return &cli.Command{
		Name:      "file",
		Usage:     "Identify hashes from input file",
		Aliases:   []string{"fn"},
		ArgsUsage: "FILE",
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
			&cli.BoolFlag{
				Name:       "quiet",
				Usage:      "suppress all output",
				Aliases:    []string{"q"},
				OnlyOnce:   true,
				Persistent: true,
			},
		},
		UseShortOptionHandling: true,
		Commands: []*cli.Command{
			splitCommand(),
		},
		Action: func(ctx context.Context, c *cli.Command) error {
			if c.Args().Len() != 1 {
				return cli.ShowSubcommandHelp(c)
			}

			_, err := processInputFile(c, c.Args().First())
			if err != nil {
				return err
			}

			return nil
		},
	}
}

// processInputFile processes the input file.
func processInputFile(c *cli.Command, filename string) (map[string][]hashtypes.Hash, error) {
	results := make(map[string][]hashtypes.Hash, 0)
	htypes, err := hashtypes.New()
	if err != nil {
		return results, err
	}
	path, err := filepath.Abs(filename)
	if err != nil {
		return results, fmt.Errorf("error getting absolute path: %w", err)
	}

	file, err := os.Open(path)
	if err != nil {
		return results, fmt.Errorf("error opening file: %w", err)
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		result := htypes.FindHashType(line)
		filtered := filterResults(c, result)
		results[line] = filtered

		if c.IsSet("quiet") || (c.IsSet("unknown") && len(filtered) == 0) {
			continue
		}
		o, err := formatOutput(c, line, filtered)
		if err != nil {
			return results, err
		}
		fmt.Fprintf(c.Root().Writer, "%s\n", o)
	}
	if err := scanner.Err(); err != nil {
		return results, fmt.Errorf("error reading file: %w", err)
	}

	return results, nil
}
