package commands

import (
	"fmt"
	"os"
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

	if c.IsSet("output") {
		output := c.String("output")
		file, err := os.Create(output)
		if err != nil {
			return cli.Exit(fmt.Errorf("error creating output file: %v", err), 1)
		}
		defer file.Close()
		c.App.Writer = file
	}

	hashid, err := hashtypes.New()
	if err != nil {
		return cli.Exit(fmt.Errorf("error initializing hashtypes: %w", err), 1)
	}

	inputHash := c.Args().Get(0)
	fmt.Fprintf(c.App.Writer, "Analyzing: %s\n", inputHash)

	// trim possible whitespace
	s := strings.TrimSpace(inputHash)

	matches := hashid.FindHashType(s)
	if len(matches) == 0 {
		// no match was found
		fmt.Fprintf(c.App.Writer, "[-] Unknown Hash\n")
		return nil
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

	return nil
}
