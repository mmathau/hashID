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

func (h *Hashes) GetAllHashTypes() []string {
	var all []string
	for _, ht := range h.types {
		all = append(all, ht.Name)
	}

	return all
}

func (h *Hashes) GetExoticHashTypes() []string {
	var exotic []string
	for _, ht := range h.types {
		if ht.Exotic {
			exotic = append(exotic, ht.Name)
		}
	}

	return exotic
}

func (h *Hashes) GetExtendedHashTypes() []string {
	var extended []string
	for _, ht := range h.types {
		if ht.Extended {
			extended = append(extended, ht.Name)
		}
	}

	return extended
}

func (h *Hashes) GetHashcatModes() []string {
	modes := make(map[string]struct{})
	for _, ht := range h.types {
		if ht.Hashcat != "" {
			modes[ht.Hashcat] = struct{}{}
		}
	}

	var uniqueModes []string
	for mode := range modes {
		uniqueModes = append(uniqueModes, mode)
	}

	return uniqueModes
}

func (h *Hashes) GetJohnFormats() []string {
	formats := make(map[string]struct{})
	for _, ht := range h.types {
		if ht.JohnTheRipper != "" {
			formats[ht.JohnTheRipper] = struct{}{}
		}
	}

	var uniqueFormats []string
	for format := range formats {
		uniqueFormats = append(uniqueFormats, format)
	}

	return uniqueFormats
}
