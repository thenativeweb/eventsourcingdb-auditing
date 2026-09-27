package main

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"

	"github.com/spf13/cobra"
	"github.com/thenativeweb/eventsourcingdb-auditing/check"
	"github.com/thenativeweb/eventsourcingdb-auditing/receipt"
	"github.com/thenativeweb/eventsourcingdb-auditing/report"
	"github.com/thenativeweb/eventsourcingdb-client-golang/eventsourcingdb"
)

func newRootCommand(stdout io.Writer, exitCode *int) *cobra.Command {
	root := &cobra.Command{
		Use:   "eventsourcingdb-auditing",
		Short: "Verifies that the events in an EventSourcingDB have not been changed",
		Long:  "Verifies that the events in an EventSourcingDB have not been changed, using the receipts, anchors, and time stamps of an external custodian.",

		// run prints the error itself, so cobra does not print it a second
		// time.
		SilenceErrors: true,
	}

	root.AddCommand(newVerifyCommand(stdout, exitCode))
	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Prints the version",
		RunE: func(command *cobra.Command, args []string) error {
			_, err := fmt.Fprintf(stdout, "eventsourcingdb-auditing %s\n", Version)
			return err
		},
	})

	return root
}

func newVerifyCommand(stdout io.Writer, exitCode *int) *cobra.Command {
	var (
		serverURL         string
		auditorToken      string
		rootPublicKey     string
		backupPath        string
		esdbURL           string
		esdbAPIToken      string
		receiptsDirectory string
		output            string
	)

	command := &cobra.Command{
		Use:   "verify",
		Short: "Verifies an instance",
		Long: `Verifies an instance: what the custodian has recorded about it, its events,
either from a backup or from the running database, and, if given, the receipts
its client has kept.

The exit code is 0 if nothing was found, 1 if a manipulation was found, 2 if
only gaps in protection were found, and 3 if the verification could not be run.`,
		RunE: func(command *cobra.Command, args []string) error {
			switch {
			case serverURL == "":
				return errors.New("--server-url is required")
			case auditorToken == "":
				return errors.New("--auditor-token is required")
			case rootPublicKey == "":
				return errors.New("--root-public-key is required")
			case (backupPath == "") == (esdbURL == ""):
				return errors.New("either --backup or --esdb-url is required, but not both")
			case esdbURL != "" && esdbAPIToken == "":
				return errors.New("--esdb-api-token is required with --esdb-url")
			case output != "text" && output != "json":
				return fmt.Errorf("--output must be text or json, got %q", output)
			}

			decodedRootPublicKey, err := receipt.DecodeRawPublicKey(rootPublicKey)
			if err != nil {
				return fmt.Errorf("--root-public-key: %w", err)
			}

			// From here on, errors happen at runtime, so printing the usage
			// would only bury the actual error message.
			command.SilenceUsage = true

			options := check.Options{
				ServerURL:         serverURL,
				AuditorToken:      auditorToken,
				RootPublicKey:     decodedRootPublicKey,
				BackupPath:        backupPath,
				ReceiptsDirectory: receiptsDirectory,
				ToolVersion:       Version,
			}

			if esdbURL != "" {
				parsedURL, err := url.Parse(esdbURL)
				if err != nil {
					return fmt.Errorf("--esdb-url: %w", err)
				}

				options.Database, err = eventsourcingdb.NewClient(parsedURL, esdbAPIToken)
				if err != nil {
					return err
				}
				options.DatabaseURL = esdbURL
			}

			built, err := check.Run(command.Context(), options)
			if err != nil {
				return err
			}

			if output == "json" {
				err = report.WriteJSON(stdout, built)
			} else {
				err = report.WriteText(stdout, built)
			}
			if err != nil {
				return err
			}

			*exitCode = built.ExitCode()

			return nil
		},
	}

	flags := command.Flags()
	flags.StringVar(&serverURL, "server-url", os.Getenv("SERVER_URL"), "sets the URL of the custodian")
	flags.StringVar(&auditorToken, "auditor-token", os.Getenv("AUDITOR_TOKEN"), "sets the auditor token the customer has granted")
	flags.StringVar(&rootPublicKey, "root-public-key", os.Getenv("ROOT_PUBLIC_KEY"), "sets the root public key of the custodian, in base64url")
	flags.StringVar(&backupPath, "backup", "", "sets the path of a backup of the database, as written on /api/v1/backup")
	flags.StringVar(&esdbURL, "esdb-url", os.Getenv("ESDB_URL"), "sets the URL of the running database, instead of a backup")
	flags.StringVar(&esdbAPIToken, "esdb-api-token", os.Getenv("ESDB_API_TOKEN"), "sets the API token of the running database")
	flags.StringVar(&receiptsDirectory, "receipts-directory", "", "sets the receipts directory of the client, to check the custodian against it")
	flags.StringVar(&output, "output", "text", "sets the format of the report, text or json")

	return command
}
