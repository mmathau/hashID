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

	var s string
	contents := bufio.NewScanner(file)
	for contents.Scan() {
		// trim possible whitespace
		s = strings.TrimSpace(contents.Text())
		matches := hashid.FindHashType(s)
		out, err := FormatOutput(c, s, matches)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.App.Writer, "%s\n", out)
	}
	if err := contents.Err(); err != nil {
		return cli.Exit(fmt.Errorf("error reading file: %w", err), 1)

	}

	return nil
}
