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

package hashid

import (
	"errors"
	"fmt"
	"hashid/internal/data"
)

var Prototypes []data.HashType

func init() {
	var err error
	Prototypes, err = data.LoadPrototypes()
	if err != nil {
		panic(err)
	}
}

func IdentifyHash(s string, flagExtended, flagExotic bool) ([]data.HashType, error) {
	var matches []data.HashType
	for _, v := range Prototypes {
		if v.Match(s) {
			if (v.IsExtended() && !flagExtended) || (v.IsExotic() && !flagExotic) {
				continue
			}
			matches = append(matches, v)
		}
	}
	if len(matches) == 0 {
		return nil, errors.New("unknown hash")
	}

	return matches, nil
}

// Format output helper
func FormatOutput(d data.HashType, showMode, showFormat bool) (s string) {
	s = fmt.Sprintf("[+] %s", d.Name)
	if showMode && d.Hashcat != "" {
		s = fmt.Sprintf("%s [Hashcat: %s]", s, d.Hashcat)
	}
	if showFormat && d.John != "" {
		s = fmt.Sprintf("%s [JtR Format: %s]", s, d.John)
	}

	return s
}

func GetHashTypes() []string {
	var hashNames []string
	for _, v := range Prototypes {
		hashNames = append(hashNames, v.Name)
	}

	return hashNames
}

func GetHashcatModes() []string {
	var hashcatModes []string
	for _, v := range Prototypes {
		hashcatModes = append(hashcatModes, v.Hashcat)
	}

	return hashcatModes
}
