// Package hashtypes provides a set of types and functions for working with different hash types.
package hashtypes

import (
	"regexp"
	"sort"
	"strconv"
)

// Hash represents a hash type.
type Hash struct {
	name     string
	regex    *regexp.Regexp
	exotic   bool
	extended bool
	hashcat  string
	john     string
}

// Name returns the name of the hash.
func (h *Hash) Name() string {
	return h.name
}

// Regex returns the regex used to match the hash.
func (h *Hash) Regex() string {
	return h.regex.String()
}

// Exotic returns whether the hash is considered exotic.
func (h *Hash) Exotic() bool {
	return h.exotic
}

// Extended returns whether the hash is marked as extended.
func (h *Hash) Extended() bool {
	return h.extended
}

// Hashcat returns the hashcat mode of the hash.
func (h *Hash) Hashcat() string {
	return h.hashcat
}

// John returns the JohnTheRipper format of the hash.
func (h *Hash) John() string {
	return h.john
}

// Hashes represents a collection of hash types.
type Hashes struct {
	types []Hash
}

// New creates a new Hashes instance.
func New() (*Hashes, error) {
	hashes, err := load()
	if err != nil {
		return nil, err
	}

	return &Hashes{
		types: hashes,
	}, nil
}

// AllTypes returns all hash types.
func (h *Hashes) AllTypes() []Hash {
	return h.types
}

// ExoticTypes returns all exotic hash types.
func (h *Hashes) ExoticTypes() []Hash {
	var exotic []Hash
	for _, ht := range h.types {
		if ht.Exotic() {
			exotic = append(exotic, ht)
		}
	}

	return exotic
}

// ExtendedTypes returns all extended hash types.
func (h *Hashes) ExtendedTypes() []Hash {
	var extended []Hash
	for _, ht := range h.types {
		if ht.Extended() {
			extended = append(extended, ht)
		}
	}

	return extended
}

// HashcatModes returns all hashcat modes.
func (h *Hashes) HashcatModes() []string {
	modes := make(map[string]bool)
	for _, ht := range h.types {
		mode := ht.Hashcat()
		if mode != "" {
			modes[mode] = true
		}
	}

	uniqueModes := make([]string, 0, len(modes))
	for mode := range modes {
		uniqueModes = append(uniqueModes, mode)
	}

	// convert string to int, sort and convert back to string
	intModes := make([]int, 0, len(uniqueModes))
	for _, mode := range uniqueModes {
		intMode, _ := strconv.Atoi(mode)
		intModes = append(intModes, intMode)
	}
	sort.Ints(intModes)

	for i, mode := range intModes {
		uniqueModes[i] = strconv.Itoa(mode)
	}

	return uniqueModes
}

// JohnFormats returns all john formats.
func (h *Hashes) JohnFormats() []string {
	formats := make(map[string]bool)
	for _, ht := range h.types {
		format := ht.John()
		if format != "" {
			formats[format] = true
		}
	}

	uniqueFormats := make([]string, 0, len(formats))
	for format := range formats {
		uniqueFormats = append(uniqueFormats, format)
	}

	sort.Strings(uniqueFormats)

	return uniqueFormats
}

// FindHashType finds and returns hash types that match the given hash string.
func (h *Hashes) FindHashType(hash string) []Hash {
	var found []Hash
	for _, ht := range h.types {
		if ht.regex.MatchString(hash) {
			found = append(found, ht)
		}
	}

	return found
}
