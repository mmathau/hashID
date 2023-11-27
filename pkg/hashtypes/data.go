package hashtypes

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
)

//go:embed data.json
var embeddedFile embed.FS

type hashType struct {
	Name          string `json:"name"`
	Regex         string `json:"regex"`
	HashcatMode   string `json:"hashcat"`
	JohnTheRipper string `json:"john"`
	Exotic        bool   `json:"exotic"`
	Extended      bool   `json:"extended"`
}

func load() ([]Hash, error) {
	var hashes []Hash

	file, err := embeddedFile.Open("data.json")
	if err != nil {
		return nil, fmt.Errorf("error opening embedded file: %w", err)
	}
	defer file.Close()

	var ht []hashType
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&ht)
	if err != nil {
		return nil, fmt.Errorf("error decoding json: %w", err)
	}

	for _, h := range ht {
		regex, err := regexp.Compile("(?i)" + h.Regex)
		if err != nil {
			return nil, fmt.Errorf("error compiling regex: %w", err)
		}
		hash := Hash{
			name:     h.Name,
			regex:    regex,
			exotic:   h.Exotic,
			extended: h.Extended,
			hashcat:  h.HashcatMode,
			john:     h.JohnTheRipper,
		}
		hashes = append(hashes, hash)
	}

	return hashes, nil
}
