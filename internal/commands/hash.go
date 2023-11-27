package commands

import (
	"fmt"

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
		_, err := process(c, hashid, arg)
		if err != nil {
			return err
		}
	}

	return nil
}
