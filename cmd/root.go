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

package cmd

import (
	"hashid/internal/hashid"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	// Flags
	extended   bool
	exotic     bool
	showMode   bool
	showFormat bool
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "hashID",
	Short:   "hash identifier",
	Long:    "Identify the different types of hashes used to encrypt data and especially passwords.",
	Version: "4.0.0",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		// Trim possible whitespace
		s := strings.TrimSpace(args[0])

		cmd.Printf("Analyzing '%v'\n", s)
		matches, err := hashid.IdentifyHash(s, extended, exotic)
		if err != nil {
			// Exit early if no match was found
			cmd.Println("[-] Unknown Hash")
			return nil
		}

		for _, v := range matches {
			cmd.Println(hashid.FormatOutput(v, showMode, showFormat))
		}

		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.PersistentFlags().BoolVarP(&exotic, "exotic", "x", false, "include exotic hash types")
	rootCmd.PersistentFlags().BoolVarP(&extended, "extended", "e", false, "include salted hash type variations")

	rootCmd.PersistentFlags().BoolVarP(&showMode, "hashcat", "m", false, "show corresponding Hashcat mode in output")
	rootCmd.PersistentFlags().BoolVarP(&showFormat, "john", "j", false, "show corresponding JohnTheRipper format in output")
}
