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
	"bufio"
	"hashid/internal/hashid"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	// Flags
	outfile string
)

// fileCmd represents the file command
var fileCmd = &cobra.Command{
	Use:   "file",
	Short: "Analyze given input file",
	Long:  "A longer description for file.",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		// Check for outfile flag
		if cmd.Flags().Changed("outfile") {
			outputPath, _ := cmd.Flags().GetString("outfile")
			outputFile, err := os.OpenFile(outputPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				return err
			}
			defer outputFile.Close()
			// Redirect output
			cmd.SetOut(outputFile)
		}

		filePath, err := filepath.Abs(filepath.Clean(args[0]))
		if err != nil {
			return err
		}
		file, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer file.Close()

		cmd.Printf("--File '%v'--\n", file.Name())
		contents := bufio.NewScanner(file)

		for contents.Scan() {
			line := contents.Text()
			// Trim possible whitespace
			line = strings.TrimSpace(line)

			cmd.Printf("Analyzing '%v'\n", line)
			matches, err := hashid.IdentifyHash(line, extended, exotic)
			if err != nil {
				cmd.Println("[-] Unknown Hash")
				continue
			}

			for _, v := range matches {
				cmd.Println(hashid.FormatOutput(v, showMode, showFormat))
			}
		}
		if err := contents.Err(); err != nil {
			return err
		}
		cmd.Printf("--End of file '%v'--\n", file.Name())

		return nil
	},
}

func init() {
	rootCmd.AddCommand(fileCmd)

	fileCmd.Flags().StringVarP(&outfile, "outfile", "o", "", "write output to file")
}
