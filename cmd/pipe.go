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
	"fmt"
	"hashid/internal/hashid"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// pipeCmd represents the pipe command
var pipeCmd = &cobra.Command{
	Use:   "pipe",
	Short: "Read from stdin / interactive mode",
	Long:  `A longer description pipe.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("pipe called")

		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "." {
				break
			}
			// Trim possible whitespace
			line = strings.TrimSpace(line)

			cmd.Printf("Analyzing '%v'\n", line)
			matches, err := hashid.IdentifyHash(line, extended, exotic)
			if err != nil {
				// Exit early if no match was found
				cmd.Println("[-] Unknown Hash")
				continue
			}

			for _, v := range matches {
				cmd.Println(hashid.FormatOutput(v, showMode, showFormat))
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(pipeCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// pipeCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// pipeCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}
