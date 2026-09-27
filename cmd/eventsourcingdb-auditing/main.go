// Command eventsourcingdb-auditing verifies that the events in an
// EventSourcingDB have not been changed, using the receipts, anchors, and time
// stamps of an external custodian.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/thenativeweb/eventsourcingdb-auditing/report"
)

// Version is set when building a release, with -ldflags "-X main.Version=…".
var Version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	exitCode := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()

	os.Exit(exitCode)
}

// run runs the command line with the given arguments, and returns the exit
// code: that of the report for a verification, or report.ExitCodeFailure if
// the verification could not be run at all.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	exitCode := report.ExitCodeNoFindings

	root := newRootCommand(stdout, &exitCode)
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)

	err := root.ExecuteContext(ctx)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return report.ExitCodeFailure
	}

	return exitCode
}
