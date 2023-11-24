/*
Copyright © 2023 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"ntwrk.space/mmaths/hashid/pkg/hashtypes"
)

// fileCmd represents the file command
var fileCmd = &cobra.Command{
	Use:   "file",
	Short: "Analyze given input file",
	Long:  "Analyze given input file.",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		hashid, err := hashtypes.New()
		if err != nil {
			cmd.PrintErrln(fmt.Errorf("error initializing hashtypes: %w", err))
			return
		}

		filePath, err := filepath.Abs(filepath.Clean(args[0]))
		if err != nil {
			cmd.PrintErrln(fmt.Errorf("error getting absolute path: %w", err))
			return
		}
		file, err := os.Open(filePath)
		if err != nil {
			cmd.PrintErrln(fmt.Errorf("error opening file: %w", err))
			return
		}
		defer file.Close()

		cmd.Printf("--File '%s'--\n", file.Name())
		contents := bufio.NewScanner(file)

		var s string
		for contents.Scan() {
			// trim possible whitespace
			s = strings.TrimSpace(contents.Text())

			cmd.Printf("Analyzing '%s'\n", s)
			matches := hashid.FindHashType(s)
			if len(matches) == 0 {
				// exit early if no match was found
				cmd.PrintErrln("[-] Unknown Hash")
				continue
			}

			for _, match := range matches {
				if (!exotic && match.Exotic) || (!extended && match.Extended) {
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
		}
		if err := contents.Err(); err != nil {
			cmd.PrintErrln(fmt.Errorf("error reading file: %w", err))
			return
		}
		cmd.Printf("--End of file '%s'--\n", file.Name())
	},
}

func init() {
	rootCmd.AddCommand(fileCmd)
}
