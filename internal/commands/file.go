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
		Action:    identifyHashesInFile,
	}
}

func identifyHashesInFile(c *cli.Context) error {
	if c.NArg() == 0 {
		return cli.ShowAppHelp(c)
	}

	if c.IsSet("output") {
		output := c.String("output")
		file, err := os.Create(output)
		if err != nil {
			return cli.Exit(fmt.Errorf("error creating output file: %w", err), 1)
		}
		defer file.Close()
		c.App.Writer = file
	}

	hashid, err := hashtypes.New()
	if err != nil {
		return cli.Exit(fmt.Errorf("error initializing hashtypes: %w", err), 1)
	}

	inputFile := c.Args().Get(0)
	path, err := filepath.Abs(filepath.Clean(inputFile))
	if err != nil {
		return cli.Exit(fmt.Errorf("error getting absolute path: %w", err), 1)
	}
	file, err := os.Open(path)
	if err != nil {
		return cli.Exit(fmt.Errorf("error opening file: %w", err), 1)
	}
	defer file.Close()

	fmt.Fprintf(c.App.Writer, "--File '%s'--\n", file.Name())
	contents := bufio.NewScanner(file)

	var s string
	for contents.Scan() {
		// trim possible whitespace
		s = strings.TrimSpace(contents.Text())

		fmt.Fprintf(c.App.Writer, "Analyzing: %s\n", s)
		matches := hashid.FindHashType(s)
		if len(matches) == 0 {
			// no match was found
			fmt.Fprintf(c.App.Writer, "[-] Unknown Hash\n")
			continue
		}

		for _, match := range matches {
			// skip exotic hash types if not requested
			if !c.IsSet("exotic") && match.Exotic {
				continue
			}
			// skip extended hash types if not requested
			if !c.IsSet("extended") && match.Extended {
				continue
			}

			output := match.Name
			if c.IsSet("mode") && match.Hashcat != "" {
				output = fmt.Sprintf("%s [Hashcat: %s]", output, match.Hashcat)
			}
			if c.IsSet("format") && match.JohnTheRipper != "" {
				output = fmt.Sprintf("%s [John: %s]", output, match.JohnTheRipper)
			}

			fmt.Fprintf(c.App.Writer, "[+] %s\n", output)
		}
	}
	if err := contents.Err(); err != nil {
		return cli.Exit(fmt.Errorf("error reading file: %w", err), 1)

	}
	fmt.Fprintf(c.App.Writer, "--End of file '%s'--\n", file.Name())

	return nil
}
