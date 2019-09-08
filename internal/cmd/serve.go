package cmd

import (
	"github.com/go-shiori/shiori/internal/ldap"
	"github.com/go-shiori/shiori/internal/webserver"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func serveCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve web interface for managing bookmarks",
		Long: "Run a simple annd performant web server which " +
			"serves the site for managing bookmarks. If --port " +
			"flag is not used, it will use port 8080 by default.",
		Run: serveHandler,
	}

	cmd.Flags().IntP("port", "p", 8080, "Port that used by server")
	cmd.Flags().StringP("address", "a", "", "Address the server listens to")
	cmd.Flags().String("ldap", "", "Path to config file for connecting with LDAP server")

	return cmd
}

func serveHandler(cmd *cobra.Command, args []string) {
	port, _ := cmd.Flags().GetInt("port")
	address, _ := cmd.Flags().GetString("address")
	ldapConfigPath, _ := cmd.Flags().GetString("ldap")

	options := webserver.Options{
		DB:         db,
		DataDir:    dataDir,
		Address:    address,
		Port:       port,
		LDAPClient: nil,
	}

	if ldapConfigPath != "" {
		cfg, err := ldap.ParseConfigFile(ldapConfigPath)
		if err != nil {
			logrus.Fatalf("Failed to open LDAP config: %v\n", err)
		}

		options.LDAPClient, err = ldap.NewClient(cfg)
		if err != nil {
			logrus.Fatalf("Failed to create LDAP client: %v\n", err)
		}
	}

	err := webserver.ServeApp(options)
	if err != nil {
		logrus.Fatalf("Server error: %v\n", err)
	}
}
