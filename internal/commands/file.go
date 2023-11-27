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
	defer file.Close()

	var s string
	withJohn := make(map[string][]string)
	withHashcat := make(map[string][]string)
	contents := bufio.NewScanner(file)
	for contents.Scan() {
		// trim possible whitespace
		s = strings.TrimSpace(contents.Text())
		matches := hashid.FindHashType(s)
		matches = filterMatches(c, matches)
		out, err := formatOutput(c, s, matches)
		if err != nil {
			return err
		}
		for _, m := range matches {
			hc := m.Hashcat()
			if hc != "" {
				withHashcat[hc] = append(withHashcat[hc], s)
			}
			jtr := m.John()
			if jtr != "" {
				withJohn[jtr] = append(withJohn[jtr], s)
			}
		}

		fmt.Fprintf(c.App.Writer, "%s\n", out)
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
	defer f.Close()

	_, err = f.WriteString(strings.Join(contents, "\n"))
	if err != nil {
		return err
	}

	return nil
}
