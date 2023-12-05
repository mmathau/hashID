package commands

import (
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"

	"ntwrk.space/mmaths/hashid/pkg/hashtypes"
)

// ListCommand returns the list command.
func ListCommand() *cli.Command {
	return &cli.Command{
		Name:      "list",
		Usage:     "Shows information about supported hash types",
		UsageText: "hashID list command [command options]",
		Subcommands: []*cli.Command{
			{
				Name:   "names",
				Usage:  "list all supported hash types",
				Action: listHashNames,
			},
			{
				Name:   "modes",
				Usage:  "list all supported hashcat modes",
				Action: listHashcatModes,
			},
			{
				Name:   "formats",
				Usage:  "list all supported JohnTheRipper formats",
				Action: listJohnFormats,
			},
		},
	}
}

// listHashNames lists all supported hash types.
func listHashNames(c *cli.Context) error {
	hashid, err := hashtypes.New()
	if err != nil {
		return cli.Exit(fmt.Errorf("error initializing hashtypes: %w", err), 1)
	}

	var hashNames []string
	for _, hash := range hashid.AllTypes() {
		hashNames = append(hashNames, hash.Name())
	}
	fmt.Fprintln(c.App.Writer, strings.Join(hashNames, "\n"))

	return nil
}

// listHashcatModes lists all supported hashcat modes.
func listHashcatModes(c *cli.Context) error {
	hashid, err := hashtypes.New()
	if err != nil {
		return cli.Exit(fmt.Errorf("error initializing hashtypes: %w", err), 1)
	}
	fmt.Fprintln(c.App.Writer, strings.Join(hashid.HashcatModes(), "\n"))

	return nil
}

// listJohnFormats lists all supported JohnTheRipper formats.
func listJohnFormats(c *cli.Context) error {
	hashid, err := hashtypes.New()
	if err != nil {
		return cli.Exit(fmt.Errorf("error initializing hashtypes: %w", err), 1)
	}
	fmt.Fprintln(c.App.Writer, strings.Join(hashid.JohnFormats(), "\n"))

	return nil
}
