package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var Version = "2.0.1"

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "展示版本",
	Run:   runVersion,
}

func runVersion(cmd *cobra.Command, args []string) {
	fmt.Println(Version)
}
