package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number of my reporting tool",
	Long:  `Print the version number of my reporting tool.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Email defense reporting tool version 0.01")
	},
}
