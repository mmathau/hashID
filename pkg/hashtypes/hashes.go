package hashtypes

import "regexp"

type Hash struct {
	name     string
	regex    *regexp.Regexp
	exotic   bool
	extended bool
	hashcat  string
	john     string
}

func (h *Hash) Name() string {
	return h.name
}

func (h *Hash) Regex() string {
	return h.regex.String()
}

func (h *Hash) Exotic() bool {
	return h.exotic
}

func (h *Hash) Extended() bool {
	return h.extended
}

func (h *Hash) Hashcat() string {
	return h.hashcat
}

func (h *Hash) John() string {
	return h.john
}

type Hashes struct {
	types []Hash
}

func New() (*Hashes, error) {
	hashes, err := load()
	if err != nil {
		return nil, err
	}

	return &Hashes{
		types: hashes,
	}, nil
}

func (h *Hashes) AllTypes() []Hash {
	return h.types
}

func (h *Hashes) ExoticTypes() []Hash {
	var exotic []Hash
	for _, ht := range h.types {
		if ht.Exotic() {
			exotic = append(exotic, ht)
		}
	}

	return exotic
}

func (h *Hashes) ExtendedTypes() []Hash {
	var extended []Hash
	for _, ht := range h.types {
		if ht.Extended() {
			extended = append(extended, ht)
		}
	}

	return extended
}

func (h *Hashes) FindHashType(hash string) []Hash {
	var found []Hash
	for _, ht := range h.types {
		if ht.regex.MatchString(hash) {
			found = append(found, ht)
		}
	}

	return found
}
