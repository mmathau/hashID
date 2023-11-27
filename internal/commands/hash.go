package commands

import (
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"

	"ntwrk.space/mmaths/hashid/pkg/hashtypes"
)

func IdentifyCommand() *cli.Command {
	return &cli.Command{
		Name:      "hash",
		Usage:     "Identify hash from input string",
		ArgsUsage: "HASH",
		Aliases:   []string{"id"},
		Action:    IdentifyHashesFromString,
	}
}

func IdentifyHashesFromString(c *cli.Context) error {
	if !c.Args().Present() {
		return cli.ShowAppHelp(c)
	}

	hashid, err := hashtypes.New()
	if err != nil {
		return cli.Exit(fmt.Errorf("error initializing hashtypes: %w", err), 1)
	}

	for _, arg := range c.Args().Slice() {
		// trim possible whitespace
		s := strings.TrimSpace(arg)
		matches := hashid.FindHashType(s)
		matches = filterMatches(c, matches)
		out, err := formatOutput(c, s, matches)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.App.Writer, "%s\n", out)

	}

	return nil
}
