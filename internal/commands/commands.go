package commands

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"

	"ntwrk.space/mmaths/hashid/pkg/hashtypes"
)

type output struct {
	Hash  string  `json:"hash" xml:"hash"`
	Match []match `json:"match" xml:"match"`
}

type match struct {
	Name    string `json:"name" xml:"name"`
	Hashcat string `json:"hashcat,omitempty" xml:"hashcat,omitempty"`
	John    string `json:"john,omitempty" xml:"john,omitempty"`
}

// Console method formats the output for console display.
func (o output) Console() []byte {
	var builder strings.Builder
	builder.WriteString(fmt.Sprintf("Analyzing: '%s'\n", o.Hash))
	if len(o.Match) == 0 {
		builder.WriteString("[-] Unknown\n")
		return []byte(builder.String())
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

	return []byte(builder.String())
}

// JSON returns the marshaled output as JSON.
func (o output) JSON() ([]byte, error) {
	return json.Marshal(o)
}

// XML returns the marshaled output as XML.
func (o output) XML() ([]byte, error) {
	return xml.Marshal(o)
}

func process(c *cli.Context, id *hashtypes.Hashes, hash string) ([]hashtypes.Hash, error) {
	s := strings.TrimSpace(hash)
	matches := id.FindHashType(s)
	matches = filter(c, matches)
	out, err := formatOutput(c, s, matches)
	if err != nil {
		return matches, err
	}
	fmt.Fprintf(c.App.Writer, "%s\n", out)

	return matches, nil
}

func filter(c *cli.Context, matches []hashtypes.Hash) []hashtypes.Hash {
	var filtered []hashtypes.Hash
	for _, m := range matches {
		// skip exotic or extended hash types if not requested
		if (!c.IsSet("exotic") && m.Exotic()) || (!c.IsSet("extended") && m.Extended()) {
			continue
		}
		filtered = append(filtered, m)
	}

	return filtered
}

func formatOutput(c *cli.Context, hash string, matches []hashtypes.Hash) ([]byte, error) {
	o := output{
		Hash:  hash,
		Match: make([]match, 0, len(matches)),
	}

	// skip unknown hashes if quiet flag is set
	if c.IsSet("quiet") {
		if len(matches) == 0 {
			return []byte(""), nil
		}
	}

	for _, m := range matches {
		mt := match{Name: m.Name()}
		if c.IsSet("hashcat") && m.Hashcat() != "" {
			mt.Hashcat = m.Hashcat()
		}
		if c.IsSet("john") && m.John() != "" {
			mt.John = m.John()
		}
		o.Match = append(o.Match, mt)
	}

	if c.IsSet("output") {
		switch c.String("output") {
		case "json":
			return o.JSON()
		case "xml":
			return o.XML()
		}
	}

	return o.Console(), nil
}
