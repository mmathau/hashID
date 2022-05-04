/*
Copyright © 2022 mmaths

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program;  if not, see <http://www.gnu.org/licenses/>.
*/

package data

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
)

var (
	//go:embed default.json
	defaultTypes []byte
	//go:embed extended.json
	extendedTypes []byte
	//go:embed exotic.json
	exoticTypes []byte
)

type HashType struct {
	Name    string  `json:"name"`
	Regex   *Regexp `json:"regex"`
	Hashcat string  `json:"hashcat"`
	John    string  `json:"john"`
	status
}

type Regexp struct {
	regexp.Regexp
}

type status struct {
	extended bool
	exotic   bool
}

// Unmarshals embedded json files and returns a slice of hash types
func LoadPrototypes() ([]HashType, error) {
	var err error
	var d, e, x []HashType

	if err = json.Unmarshal(defaultTypes, &d); err != nil {
		return nil, err
	}

	if err = json.Unmarshal(extendedTypes, &e); err != nil {
		return nil, err
	}
	// set extended bool
	for k := range e {
		e[k].extended = true
	}

	if err = json.Unmarshal(exoticTypes, &x); err != nil {
		return nil, err
	}
	// set exotic bool
	for k := range x {
		x[k].exotic = true
	}

	d = append(d, e...)
	return append(d, x...), nil
}

// Returns a true if regex matches given input string
func (h *HashType) Match(s string) bool {
	return h.Regex.MatchString(s)
}

// Returns true if hash type is flagged as extended
func (s *status) IsExtended() bool {
	return s.extended
}

// Returns true if hash type is flagged as exotic
func (s *status) IsExotic() bool {
	return s.exotic
}

// Compile wraps the result of the standard library's
// regexp.Compile, for easy (un)marshaling.
// https://stackoverflow.com/a/62558450
func compile(expr string) (*Regexp, error) {
	// add case-insensitive flag
	re, err := regexp.Compile(fmt.Sprintf("(?i)%s", expr))
	if err != nil {
		return nil, err
	}

	return &Regexp{*re}, nil
}

// UnmarshalText satisfies the encoding.TextMarshaler interface,
// also used by json.Unmarshal.
func (r *Regexp) UnmarshalText(text []byte) error {
	rr, err := compile(string(text))
	if err != nil {
		return err
	}
	*r = *rr

	return nil
}

// MarshalText satisfies the encoding.TextMarshaler interface,
// also used by json.Marshal.
func (r *Regexp) MarshalText() ([]byte, error) {
	return []byte(r.String()), nil
}
