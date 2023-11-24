/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"ntwrk.space/mmaths/hashid/pkg/hashtypes"
)

var (
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
	Args:    cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		hashid, err := hashtypes.New()
		if err != nil {
			cmd.PrintErrln(fmt.Errorf("error initializing hashtypes: %w", err))
			return
		}
		// trim possible whitespace
		s := strings.TrimSpace(args[0])

		cmd.Printf("Analyzing '%s'\n", s)
		matches := hashid.FindHashType(s)
		if len(matches) == 0 {
			// exit early if no match was found
			cmd.PrintErrln("[-] Unknown Hash")
			return
		}

		for _, match := range matches {
			// skip exotic hash types if not requested
			if !exotic && match.Exotic {
				continue
			}
			// skip extended hash types if not requested
			if !extended && match.Extended {
				continue
			}

			output := fmt.Sprintf("[+] %s", match.Name)
			if showMode && match.Hashcat != "" {
				output = fmt.Sprintf("%s [Hashcat: %s]", output, match.Hashcat)
			}
			if showFormat && match.JohnTheRipper != "" {
				output = fmt.Sprintf("%s [John: %s]", output, match.JohnTheRipper)
			}

			cmd.Println(output)
		}
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
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
