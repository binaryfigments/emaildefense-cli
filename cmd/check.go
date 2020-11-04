package cmd

import (
	"fmt"
	"os"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(checkCmd)
	checkCmd.PersistentFlags().StringP("domain", "d", "ocsr.nl", "the domain that we want to check")
	checkCmd.PersistentFlags().StringP("nameserver", "n", "8.8.8.8", "the domain that we want to check")
}

var checkCmd = &cobra.Command{
	Use:   "check",
	Short: "Generate a report about a domains.",
	Run: func(cmd *cobra.Command, args []string) {
		domain, _ := cmd.Flags().GetString("domain")
		nameserver, _ := cmd.Flags().GetString("nameserver")

		yellow := color.New(color.FgYellow).SprintFunc()
		red := color.New(color.FgRed).SprintFunc()
		green := color.New(color.FgGreen).SprintFunc()
		blue := color.New(color.FgBlue).SprintFunc()
		// fmt.Printf("This is a %s and this is %s.\n", yellow("warning"), red("error"))
		// fmt.Printf("This is a %s and this is %s.\n", green("warning"), blue("error"))

		fmt.Printf("%s Start checking email defense for domain %s.\n", blue("[+]"), blue(domain))

		fmt.Printf("%s Getting MX records for domain %s.\n", blue("[+]"), blue(domain))
		mx, err := getMX(domain, nameserver)
		if err != nil {
			fmt.Printf("%s Error: %s.\n", red("[x]"), red(err))
		}

		if len(mx.MX) < 1 {
			fmt.Printf("%s No MX records found for domain: %s.\n", yellow("[!]"), yellow(domain))
			fmt.Printf("%s Finished checks on domain: %s.\n", blue("[v]"), blue(domain))
			os.Exit(0) // success
		}

		if mx.AuthenticatedData == true {
			fmt.Printf("%s MX lookup DNSSEC validated: %s.\n", green("[+]"), green(mx.AuthenticatedData))
		} else {
			fmt.Printf("%s MX lookup DNSSEC validated: %s.\n", yellow("[!]"), yellow(mx.AuthenticatedData))
		}

		for _, mxr := range mx.MX {
			fmt.Printf("%s MX host %s preference %s.\n", green("[+]"), green(mxr.Mx), green(mxr.Preference))
		}

		fmt.Printf("%s Getting SPF records for domain %s.\n", blue("[+]"), blue(domain))
		spf, err := getSPF(domain, nameserver)
		if err != nil {
			fmt.Printf("%s Error: %s.\n", red("[x]"), red(err))
		}

		// Check for records
		if len(spf.SPF) > 0 {
			if spf.AuthenticatedData == true {
				fmt.Printf("%s SPF lookup DNSSEC validated: %s.\n", green("[+]"), green(spf.AuthenticatedData))
			} else {
				fmt.Printf("%s SPF lookup DNSSEC validated: %s.\n", yellow("[!]"), yellow(spf.AuthenticatedData))
			}
			for _, spfr := range spf.SPF {
				fmt.Printf("%s SPF record: %s.\n", green("[+]"), green(spfr))
			}
		} else {
			fmt.Printf("%s No SPF records found for domain: %s.\n", yellow("[!]"), yellow(domain))
		}

		// getSPF(domain string, nameserver string) (*spfrecords, error)

		fmt.Printf("%s Getting DMARC records for domain %s.\n", blue("[+]"), blue(domain))
		dmarc, err := getDMARC(domain, nameserver)
		if err != nil {
			fmt.Printf("%s Error: %s.\n", red("[x]"), red(err))
		}

		// Check for records
		if len(dmarc.DMARC) > 0 {
			if dmarc.AuthenticatedData == true {
				fmt.Printf("%s DMARC lookup DNSSEC validated: %s.\n", green("[+]"), green(spf.AuthenticatedData))
			} else {
				fmt.Printf("%s DMARC lookup DNSSEC validated: %s.\n", yellow("[!]"), yellow(spf.AuthenticatedData))
			}
			for _, dmarcr := range dmarc.DMARC {
				fmt.Printf("%s DMARC record: %s.\n", green("[+]"), green(dmarcr))
			}
		} else {
			fmt.Printf("%s No DMARC records found for domain: %s.\n", yellow("[!]"), yellow(domain))
		}

		/*
			json, err := json.MarshalIndent(mx, "", "  ")
			if err != nil {
				fmt.Println(err)
			}
			fmt.Printf("%s\n", json)
		*/
		fmt.Printf("%s Finished checks on domain: %s.\n", blue("[+]"), blue(domain))
	},
}
