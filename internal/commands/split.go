package commands

import (
	"context"
	"os"
	"strings"

	"github.com/urfave/cli/v3"

	"ntwrk.space/mmaths/hashid/pkg/hashtypes"
)

// splitCommand returns the split command.
func splitCommand() *cli.Command {
	return &cli.Command{
		Name:      "split",
		Usage:     "Split hashes from input file into subfiles",
		ArgsUsage: "FILE",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:     "modes",
				Usage:    "split by hashcat modes",
				Aliases:  []string{"m"},
				OnlyOnce: true,
			},
			&cli.BoolFlag{
				Name:     "formats",
				Usage:    "split by JohnTheRipper formats",
				Aliases:  []string{"j"},
				OnlyOnce: true,
			},
			&cli.BoolFlag{
				Name:     "unknown",
				Usage:    "split by unknown hashes",
				Aliases:  []string{"u"},
				OnlyOnce: true,
			},
		},
		UseShortOptionHandling: true,
		Action: func(ctx context.Context, c *cli.Command) error {
			if c.Args().Len() != 1 {
				return cli.ShowSubcommandHelp(c)
			}
			result, err := processInputFile(c, c.Args().First())
			if err != nil {
				return err
			}
			if c.IsSet("modes") || c.IsSet("formats") || c.IsSet("unknown") {
				err = writeSplitFiles(c, result)
				if err != nil {
					return err
				}
			}

			return nil
		},
	}
}

func writeSplitFiles(c *cli.Command, results map[string][]hashtypes.Hash) error {
	hashcatFiles := make(map[string][]string, 0)
	jtrFiles := make(map[string][]string, 0)
	unknownHashes := make([]string, 0)
	for line, matches := range results {
		if len(matches) == 0 {
			unknownHashes = append(unknownHashes, line)
			continue
		}
		for _, m := range matches {
			if m.Hashcat() != "" {
				hashcatFiles[m.Hashcat()] = append(hashcatFiles[m.Hashcat()], line)
			}
			if m.John() != "" {
				jtrFiles[m.John()] = append(jtrFiles[m.John()], line)
			}
		}
	}
	if c.IsSet("modes") {
		err := writeFiles(hashcatFiles)
		if err != nil {
			return err
		}
	}
	if c.IsSet("formats") {
		err := writeFiles(jtrFiles)
		if err != nil {
			return err
		}
	}
	if c.IsSet("unknown") {
		err := writeFiles(map[string][]string{
			"unknown": unknownHashes,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

/*
func writeSplitFiles(c *cli.Command, results map[string][]hashtypes.Hash) error {
	hashcatFiles := make(map[string][]string, 0)
	jtrFiles := make(map[string][]string, 0)
	unknownHashes := make([]string, 0)
	for line, matches := range results {
		if len(matches) == 0 {
			unknownHashes = append(unknownHashes, line)
			continue
		}
		for _, m := range matches {
			if m.Hashcat() != "" {
				hashcatFiles[m.Hashcat()] = append(hashcatFiles[m.Hashcat()], line)
			}
			if m.John() != "" {
				jtrFiles[m.John()] = append(jtrFiles[m.John()], line)
			}
		}
	}
	if c.IsSet("modes") {
		err := writeFiles(hashcatFiles)
		if err != nil {
			return err
		}
	}
	if c.IsSet("formats") {
		err := writeFiles(jtrFiles)
		if err != nil {
			return err
		}
	}
	if c.IsSet("unknown") {
		err := writeFile("unknown.txt", unknownHashes)
		if err != nil {
			return err
		}
	}

	return nil
}
*/

func writeFiles(f map[string][]string) error {
	for filename, content := range f {
		err := writeFile(filename, content)
		if err != nil {
			return err
		}
	}

	return nil
}

func writeFile(filename string, contents []string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}

	_, err = f.WriteString(strings.Join(contents, "\n"))
	if err != nil {
		_ = f.Close() // write error takes precedence
		return err
	}

	return f.Close()
}
