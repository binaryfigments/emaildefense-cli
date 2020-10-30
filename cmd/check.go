package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/binaryfigments/emaildefense"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(checkCmd)
	checkCmd.PersistentFlags().StringVar(&cfgFile, "domain", "ocsr.nl", "the domain that we want to check")
	checkCmd.PersistentFlags().StringVar(&cfgFile, "nameserver", "8.8.8.8", "the domain that we want to check")
	checkCmd.PersistentFlags().Bool("full", false, "use Viper for configuration")
}

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Generate a report about a domains.",
	Run: func(cmd *cobra.Command, args []string) {
		domain, _ := cmd.Flags().GetString("domain")
		nameserver, _ := cmd.Flags().GetString("nameserver")
		full, _ := cmd.Flags().GetBool("full")

		caadata := emaildefense.Get(domain, nameserver, full)

		json, err := json.MarshalIndent(caadata, "", "  ")
		if err != nil {
			fmt.Println(err)
		}
		fmt.Printf("%s\n", json)

	},
}
