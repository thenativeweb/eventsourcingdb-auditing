package main

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thenativeweb/eventsourcingdb-auditing/check"
	"github.com/thenativeweb/eventsourcingdb-auditing/receipt"
	"github.com/thenativeweb/eventsourcingdb-auditing/report"
	"github.com/thenativeweb/eventsourcingdb-auditing/trustedlists"
	"github.com/thenativeweb/eventsourcingdb-client-golang/eventsourcingdb"
)

// newTrustedListsSource returns where the EU trusted lists are fetched from.
// Tests replace it, so that they need no network.
var newTrustedListsSource = func() trustedlists.Source {
	return trustedlists.NewHTTPSource()
}

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
	root.AddCommand(newDownloadTrustedListsCommand(stdout))
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

		trustedListsDirectory string
		skipTrustedLists      bool
	)

	command := &cobra.Command{
		Use:   "verify",
		Short: "Verifies an instance",
		Long: `Verifies an instance: what the custodian has recorded about it, its events,
either from a backup or from the running database, and, if given, the receipts
its client has kept.

The time stamps of the anchors are checked against the EU trusted lists, which
are fetched from where they are published, or read from a directory that
download-trusted-lists has filled.

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
			case skipTrustedLists && trustedListsDirectory != "":
				return errors.New("either --skip-trusted-lists or --trusted-lists-directory, but not both")
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

			if !skipTrustedLists {
				source := newTrustedListsSource()
				if trustedListsDirectory != "" {
					source = trustedlists.DirectorySource{Path: trustedListsDirectory}
				}

				checker, err := trustedlists.NewChecker(command.Context(), source)
				if err != nil {
					return fmt.Errorf("failed to read the EU trusted lists, so the time stamps can not be checked (use --trusted-lists-directory to read them from a directory, or --skip-trusted-lists to leave them out): %w", err)
				}
				options.TrustedLists = checker
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
	flags.StringVar(&trustedListsDirectory, "trusted-lists-directory", "", "reads the EU trusted lists from a directory that download-trusted-lists has filled, instead of fetching them")
	flags.BoolVar(&skipTrustedLists, "skip-trusted-lists", false, "leaves out checking the time stamps against the EU trusted lists")

	return command
}

func newDownloadTrustedListsCommand(stdout io.Writer) *cobra.Command {
	var directory string

	command := &cobra.Command{
		Use:   "download-trusted-lists",
		Short: "Downloads the EU trusted lists, for verifying without network",
		Long: `Downloads the list of the trusted lists of the European Commission, and the
trusted list of every member state it points to, into a directory, from which
verify --trusted-lists-directory reads them without network. Every list is
checked before it is written.`,
		RunE: func(command *cobra.Command, args []string) error {
			if directory == "" {
				return errors.New("--directory is required")
			}

			command.SilenceUsage = true

			err := os.MkdirAll(directory, 0o755)
			if err != nil {
				return err
			}

			countries, err := trustedlists.Download(command.Context(), newTrustedListsSource(), directory)
			if len(countries) == 0 && err != nil {
				return err
			}

			_, writeErr := fmt.Fprintf(stdout, "Downloaded the trusted lists of %d countries into %s: %s\n", len(countries), directory, strings.Join(countries, ", "))
			if writeErr != nil {
				return writeErr
			}
			if err != nil {
				fmt.Fprintf(command.ErrOrStderr(), "Some trusted lists could not be downloaded, which only matters if a time stamping authority of these countries is to be checked:\n%v\n", err)
			}

			return nil
		},
	}

	command.Flags().StringVar(&directory, "directory", "", "sets the directory to write the trusted lists into")

	return command
}
