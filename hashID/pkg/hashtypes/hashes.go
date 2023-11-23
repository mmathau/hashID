package hashtypes

import (
	"embed"
	"encoding/json"
	"fmt"
	"regexp"
)

//go:embed *.json
var embeddedFiles embed.FS

type hashType struct {
	Name          string `json:"name"`
	Regex         string `json:"regex"`
	Hashcat       string `json:"hashcat"`
	JohnTheRipper string `json:"john"`
	regex         *regexp.Regexp
	exotic        bool
	extended      bool
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

	files, err := embeddedFiles.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("error reading embedded dir: %w", err)
	}
	for _, entry := range files {
		fileName := entry.Name()
		file, err := embeddedFiles.Open(fileName)
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

		switch fileName {
		case "exotic.json":
			for i := range h {
				h[i].exotic = true
			}
		case "extended.json":
			for i := range h {
				h[i].extended = true
			}
		}

		hashTypes = append(hashTypes, h...)
	}

	return hashTypes, nil
}

func (h *hashType) Exotic() bool {
	return h.exotic
}

func (h *hashType) Extended() bool {
	return h.extended
}

func (h *Hashes) FindHashType(hash string) []hashType {
	var found []hashType
	for _, hashType := range h.types {
		if hashType.regex.MatchString(hash) {
			found = append(found, hashType)
		}
	}

	return found
}
