package commands

import (
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"

	"ntwrk.space/mmaths/hashid/pkg/hashtypes"
)

func IdentifyCommand() *cli.Command {
	return &cli.Command{
		Name:      "identify",
		Usage:     "Identify hash from input",
		ArgsUsage: "HASH",
		Aliases:   []string{"id"},
		Action:    IdentifySingleHash,
	}
}

func IdentifySingleHash(c *cli.Context) error {
	if c.NArg() == 0 {
		return cli.ShowAppHelp(c)
	}

	hashid, err := hashtypes.New()
	if err != nil {
		return cli.Exit(fmt.Errorf("error initializing hashtypes: %w", err), 1)
	}

	inputHash := c.Args().Get(0)

	// trim possible whitespace
	s := strings.TrimSpace(inputHash)

	matches := hashid.FindHashType(s)
	out, err := FormatOutput(c, s, matches)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.App.Writer, "%s\n", out)

	return nil
}
