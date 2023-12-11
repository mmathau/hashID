package commands

import (
	"context"
	"fmt"
	"strings"

	"github.com/urfave/cli/v3"

	"ntwrk.space/mmaths/hashid/pkg/hashtypes"
)

// listCommand returns the list command.
func listCommand() *cli.Command {
	return &cli.Command{
		Name:    "list",
		Usage:   "Shows information about supported hash types",
		Aliases: []string{"ls"},
		Commands: []*cli.Command{
			{
				Name:   "names",
				Usage:  "list all supported hash types",
				Action: listHashNames,
			},
			{
				Name:   "exotic",
				Usage:  "list all supported exotic hash types",
				Action: listExoticHashNames,
			},
			{
				Name:   "extended",
				Usage:  "list all supported extended hash types",
				Action: listExtendedHashNames,
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
func listHashNames(ctx context.Context, c *cli.Command) error {
	hashid, err := hashtypes.New()
	if err != nil {
		return cli.Exit(fmt.Errorf("error initializing hashtypes: %w", err), 1)
	}

	var hashNames []string
	for _, hash := range hashid.AllTypes() {
		hashNames = append(hashNames, hash.Name())
	}
	fmt.Fprintln(c.Root().Writer, strings.Join(hashNames, "\n"))

	return nil
}

// listExoticHashNames lists all supported exoitc hash types.
func listExoticHashNames(ctx context.Context, c *cli.Command) error {
	hashid, err := hashtypes.New()
	if err != nil {
		return cli.Exit(fmt.Errorf("error initializing hashtypes: %w", err), 1)
	}

	var exoticNames []string
	for _, hash := range hashid.ExoticTypes() {
		exoticNames = append(exoticNames, hash.Name())
	}
	fmt.Fprintln(c.Root().Writer, strings.Join(exoticNames, "\n"))

	return nil
}

// listExtendedHashNames lists all supported extended hash types.
func listExtendedHashNames(ctx context.Context, c *cli.Command) error {
	hashid, err := hashtypes.New()
	if err != nil {
		return cli.Exit(fmt.Errorf("error initializing hashtypes: %w", err), 1)
	}

	var extendedNames []string
	for _, hash := range hashid.ExtendedTypes() {
		extendedNames = append(extendedNames, hash.Name())
	}
	fmt.Fprintln(c.Root().Writer, strings.Join(extendedNames, "\n"))

	return nil
}

// listHashcatModes lists all supported hashcat modes.
func listHashcatModes(ctx context.Context, c *cli.Command) error {
	hashid, err := hashtypes.New()
	if err != nil {
		return cli.Exit(fmt.Errorf("error initializing hashtypes: %w", err), 1)
	}
	fmt.Fprintln(c.Root().Writer, strings.Join(hashid.HashcatModes(), "\n"))

	return nil
}

// listJohnFormats lists all supported JohnTheRipper formats.
func listJohnFormats(ctx context.Context, c *cli.Command) error {
	hashid, err := hashtypes.New()
	if err != nil {
		return cli.Exit(fmt.Errorf("error initializing hashtypes: %w", err), 1)
	}
	fmt.Fprintln(c.Root().Writer, strings.Join(hashid.JohnFormats(), "\n"))

	return nil
}
