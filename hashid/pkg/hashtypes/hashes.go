package hashtypes

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
)

//go:embed hashes.json
var embeddedFile embed.FS

type hashType struct {
	Name          string `json:"name"`
	Regex         string `json:"regex"`
	Hashcat       string `json:"hashcat"`
	JohnTheRipper string `json:"john"`
	Exotic        bool   `json:"exotic"`
	Extended      bool   `json:"extended"`
	regex         *regexp.Regexp
}

type Hashes struct {
	types []hashType
}

func New() (*Hashes, error) {
	hashTypes, err := loadFromEmbedded()
	if err != nil {
		return nil, err
	}

	return &Hashes{
		types: hashTypes,
	}, nil
}

func loadFromEmbedded() ([]hashType, error) {
	var hashTypes []hashType

	file, err := embeddedFile.Open("hashes.json")
	if err != nil {
		return nil, fmt.Errorf("error opening embedded file: %w", err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	var h []hashType
	err = decoder.Decode(&h)
	if err != nil {
		return nil, fmt.Errorf("error decoding json: %w", err)
	}

	for i := range h {
		regex, err := regexp.Compile(fmt.Sprintf("(?i)%s", h[i].Regex))
		if err != nil {
			return nil, fmt.Errorf("error compiling regex: %w", err)
		}
		h[i].regex = regex
	}

	hashTypes = append(hashTypes, h...)

	return hashTypes, nil
}

func (h *Hashes) FindHashType(hash string) []hashType {
	var found []hashType
	for _, ht := range h.types {
		if ht.regex.MatchString(hash) {
			found = append(found, ht)
		}
	}

	return found
}
