package hashtypes

import "regexp"

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
