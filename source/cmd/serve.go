package cmd

import (
	"github.com/akhilgarg07/golitely/source/server"
	"github.com/spf13/cobra"
)

func init() {
	RootCmd.AddCommand(newServeCmd())
}

func newServeCmd() *cobra.Command {
	var serveCmd = &cobra.Command{
		Use:   "serve",
		Short: "Start running the golitely server",
		Run: func(cmd *cobra.Command, args []string) {
			server.Serve()
		},
	}
	return serveCmd
}