package cmd

import (
	"github.com/spf13/cobra"
)

var (
	// Used for flags.
	cfgFile string

	rootCmd = &cobra.Command{
		Use:   "emaildefense-cli",
		Short: "Email defense reporting tool.",
		Long:  `An e-mail defense reporting tool that checks for SPF, DKIM and DMARC.`,
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "domain", "example.org", "the domain that we want to check")
	rootCmd.PersistentFlags().Bool("viper", true, "use Viper for configuration")
}
