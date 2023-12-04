package commands

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/urfave/cli/v2"

	"ntwrk.space/mmaths/hashid/pkg/hashtypes"
)

// FileCommand returns the file command.
func FileCommand() *cli.Command {
	return &cli.Command{
		Name:      "file",
		Usage:     "Identify hashes from input file",
		ArgsUsage: "FILE",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:  "split-hashcat",
				Usage: "split hashes into files for each hashcat mode",
			},
			&cli.BoolFlag{
				Name:  "split-john",
				Usage: "split hashes into files for each John format",
			},
		},
		Action: IdentifyHashesFromFile,
	}
}

// IdentifyHashesFromFile identifies hashes from a file.
func IdentifyHashesFromFile(c *cli.Context) error {
	if !c.Args().Present() {
		return cli.ShowAppHelp(c)
	}

	hashid, err := hashtypes.New()
	if err != nil {
		return cli.Exit(fmt.Errorf("error initializing hashtypes: %w", err), 1)
	}

	inputFile := c.Args().Get(0)
	path, err := filepath.Abs(inputFile)
	if err != nil {
		return cli.Exit(fmt.Errorf("error getting absolute path: %w", err), 1)
	}

	file, err := os.Open(path)
	if err != nil {
		return cli.Exit(fmt.Errorf("error opening file: %w", err), 1)
	}

	var line string
	withJohn := make(map[string][]string)
	withHashcat := make(map[string][]string)
	contents := bufio.NewScanner(file)
	for contents.Scan() {
		line = strings.TrimSpace(contents.Text())
		matches, err := process(c, hashid, line)
		if err != nil {
			return err
		}
		for _, m := range matches {
			hc := m.Hashcat()
			if hc != "" {
				withHashcat[hc] = append(withHashcat[hc], line)
			}
			jtr := m.John()
			if jtr != "" {
				withJohn[jtr] = append(withJohn[jtr], line)
			}
		}
	}
	if err := contents.Err(); err != nil {
		return cli.Exit(fmt.Errorf("error reading file: %w", err), 1)

	}

	if c.IsSet("split-hashcat") {
		for k, v := range withHashcat {
			// create a file for each hashcat mode
			err := writeFile(fmt.Sprintf("mode_%s.txt", k), v)
			if err != nil {
				return cli.Exit(fmt.Errorf("error writing file: %w", err), 1)
			}
		}
	}
	if c.IsSet("split-john") {
		for k, v := range withJohn {
			// create a file for each john format
			err := writeFile(fmt.Sprintf("format_%s.txt", k), v)
			if err != nil {
				return cli.Exit(fmt.Errorf("error writing file: %w", err), 1)
			}
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
