// Package commands provides the command line interface for the hashID application.
// It defines the available commands and options, handles input processing and output formatting.
package commands

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"strings"

	"github.com/urfave/cli/v3"

	"ntwrk.space/mmaths/hashid/pkg/hashtypes"
)

// RootCommand returns the root command.
func RootCommand() *cli.Command {
	return &cli.Command{
		Name:        "hashID",
		Usage:       "hash identifier",
		Description: "Identify the different types of hashes used to encrypt data and especially passwords.",
		Version:     "0.0.2",
		Commands: []*cli.Command{
			hashCommand(),
			fileCommand(),
			listCommand(),
		},
		DefaultCommand: "hash",
		Flags: []cli.Flag{
			&cli.BoolFlag{
				Name:     "exotic",
				Usage:    "include exotic hash types",
				Aliases:  []string{"x"},
				OnlyOnce: true,
			},
			&cli.BoolFlag{
				Name:     "extended",
				Usage:    "include extended hash types",
				Aliases:  []string{"e"},
				OnlyOnce: true,
			},
			&cli.StringFlag{
				Name:        "output",
				Aliases:     []string{"o"},
				Usage:       "set output format `[json|xml]`",
				DefaultText: "console",
				OnlyOnce:    true,
				Validator: func(s string) error {
					switch s {
					case "", "json", "xml":
						return nil
					default:
						return errors.New("invalid format for output")
					}
				},

				Config: cli.StringConfig{TrimSpace: true},
			},
		},
		UseShortOptionHandling: true,
	}
}

type output struct {
	Hash  string  `json:"hash" xml:"hash"`
	Match []match `json:"match" xml:"match"`
}

type match struct {
	Name    string `json:"name" xml:"name"`
	Hashcat string `json:"hashcat,omitempty" xml:"hashcat,omitempty"`
	John    string `json:"john,omitempty" xml:"john,omitempty"`
}

// WriteJSON marshalls the output as JSON.
func (o *output) WriteJSON() ([]byte, error) {
	return json.Marshal(&o)
}

// WriteXML marshalls the output as XML.
func (o *output) WriteXML() ([]byte, error) {
	return xml.Marshal(&o)
}

// WriteConsole formats the output for the console.
func (o *output) WriteConsole() ([]byte, error) {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Analyzing: %q\n", o.Hash))
	if len(o.Match) == 0 {
		builder.WriteString("[-] Unknown\n")
		return []byte(builder.String()), nil
	}
	for _, m := range o.Match {
		builder.WriteString(fmt.Sprintf("[+] %s ", m.Name))

		if m.Hashcat != "" {
			builder.WriteString(fmt.Sprintf("[Hashcat: %s]", m.Hashcat))
		}
		if m.John != "" {
			builder.WriteString(fmt.Sprintf("[John: %s]", m.John))
		}
		builder.WriteString("\n")
	}

	return []byte(builder.String()), nil
}

// filterResults filters the results based on the command line options.
func filterResults(c *cli.Command, results []hashtypes.Hash) []hashtypes.Hash {
	rootCmd := c.Root()
	var filtered []hashtypes.Hash
	for _, t := range results {
		if !rootCmd.IsSet("exotic") && t.Exotic() {
			continue
		}
		if !rootCmd.IsSet("extended") && t.Extended() {
			continue
		}
		filtered = append(filtered, t)
	}

	return filtered
}

// formatOutput formats the output based on the command line options.
func formatOutput(c *cli.Command, search string, results []hashtypes.Hash) ([]byte, error) {
	output := output{
		Hash:  search,
		Match: make([]match, 0, len(results)),
	}

	for _, t := range results {
		m := match{Name: t.Name()}
		if c.IsSet("hashcat") && t.Hashcat() != "" {
			m.Hashcat = t.Hashcat()
		}
		if c.IsSet("john") && t.John() != "" {
			m.John = t.John()
		}
		output.Match = append(output.Match, m)
	}

	if c.Root().IsSet("output") {
		switch c.Root().String("output") {
		case "json":
			return output.WriteJSON()
		case "xml":
			return output.WriteXML()
		}
	}

	return output.WriteConsole()
}
