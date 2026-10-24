package check

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/thenativeweb/eventsourcingdb-auditing/audit"
	"github.com/thenativeweb/eventsourcingdb-auditing/database"
	"github.com/thenativeweb/eventsourcingdb-auditing/receipt"
	"github.com/thenativeweb/eventsourcingdb-auditing/receiptsdir"
	"github.com/thenativeweb/eventsourcingdb-auditing/report"
	"github.com/thenativeweb/eventsourcingdb-auditing/verify"
	"github.com/thenativeweb/eventsourcingdb-client-golang/v2/eventsourcingdb"
)

// Options say what to verify.
type Options struct {
	// ServerURL and AuditorToken are where and how the auditor reads from the
	// custodian.
	ServerURL    string
	AuditorToken string

	// RootPublicKey is the key that certifies the keys of the custodian.
	RootPublicKey ed25519.PublicKey

	// Either BackupPaths name the backups of the database of the customer,
	// of either format, a full backup and incremental ones that follow on
	// it, or several full ones, in any order, or Database and DatabaseURL
	// name the running database.
	BackupPaths []string
	Database    *eventsourcingdb.Client
	DatabaseURL string

	// ReceiptsDirectory names the receipts directory of the client, if the
	// custodian is to be checked against it.
	ReceiptsDirectory string

	// TrustedLists checks the time stamps against the EU trusted lists, or
	// is nil if they are not to be checked.
	TrustedLists TrustedLists

	ToolVersion string

	// Now returns the time of the verification. It defaults to time.Now.
	Now func() time.Time
}

// TrustedLists tells whether a time stamping service was qualified, and on
// which state of the trusted lists. trustedlists.Checker is one.
type TrustedLists interface {
	verify.QualificationChecker
	ListOfTheListsIssuedAt() time.Time
}

// Run runs a verification, and returns its report. It only fails if something
// can not be read or checked at all, in which case nothing can be said.
func Run(ctx context.Context, options Options) (report.Report, error) {
	if (len(options.BackupPaths) == 0) == (options.Database == nil) {
		return report.Report{}, errors.New("either a backup or a database must be given, not both and not none")
	}

	now := options.Now
	if now == nil {
		now = time.Now
	}
	checkedAt := now()

	client, err := audit.NewClient(options.ServerURL, options.AuditorToken)
	if err != nil {
		return report.Report{}, err
	}

	custodian, err := readCustodian(ctx, client)
	if err != nil {
		return report.Report{}, err
	}

	custodianResult, err := verify.VerifyCustodian(custodian, options.RootPublicKey, checkedAt)
	if err != nil {
		return report.Report{}, err
	}

	built := report.Report{
		ToolVersion: options.ToolVersion,
		CheckedAt:   checkedAt,
		Instance: report.Instance{
			ID:           custodian.Instance.InstanceID,
			Name:         custodian.Instance.Name,
			RegisteredAt: custodian.Instance.RegisteredAt,
		},
		Sources:  report.Sources{Custodian: options.ServerURL},
		Receipts: len(custodianResult.Fingerprints),
		Anchors:  len(custodian.Anchors),
		Findings: custodianResult.Findings,
	}

	eventsResult, err := verifyEvents(ctx, options, custodianResult, checkedAt, &built.Sources)
	if err != nil {
		return report.Report{}, err
	}
	built.Events.Count = eventsResult.EventCount
	if eventsResult.EventCount > 0 {
		built.Events.FirstAt = &eventsResult.FirstEventAt
		built.Events.LastAt = &eventsResult.LastEventAt
	}
	built.Findings = append(built.Findings, eventsResult.Findings...)

	if options.ReceiptsDirectory != "" {
		kept, err := receiptsdir.Read(options.ReceiptsDirectory)
		if err != nil {
			return report.Report{}, err
		}

		built.Sources.ReceiptsDirectory = options.ReceiptsDirectory
		built.ReceiptsDirectoryChecked = true
		built.Findings = append(built.Findings, verify.VerifyKept(kept, custodian, options.RootPublicKey)...)
	}

	if options.TrustedLists != nil {
		qualification, err := verify.VerifyQualification(ctx, custodian.Anchors, options.TrustedLists)
		if err != nil {
			return report.Report{}, fmt.Errorf("failed to check the time stamps against the trusted lists: %w", err)
		}

		built.TrustedListsChecked = true
		built.TrustedLists = &report.TrustedLists{
			ListOfTheListsIssuedAt: options.TrustedLists.ListOfTheListsIssuedAt(),
			StampedAnchors:         qualification.Stamped,
			QualifiedAnchors:       qualification.Qualified,
		}
		built.Findings = append(built.Findings, qualification.Findings...)
	}

	if built.Findings == nil {
		built.Findings = []verify.Finding{}
	}
	built.Result = report.ResultOf(built.Findings)

	return built, nil
}

// readCustodian reads everything the custodian hands out about the instance,
// page by page. The public chain of anchors is read last, so that it is at
// least as long as the chain of anchors of the auditor.
func readCustodian(ctx context.Context, client *audit.Client) (verify.Custodian, error) {
	var custodian verify.Custodian

	instance, err := client.ReadInstance(ctx)
	if err != nil {
		return verify.Custodian{}, fmt.Errorf("failed to read the instance from the custodian: %w", err)
	}
	custodian.Instance = instance

	after := ""
	for {
		entries, err := client.ReadChain(ctx, after)
		if err != nil {
			return verify.Custodian{}, fmt.Errorf("failed to read the chain from the custodian: %w", err)
		}
		custodian.Chain = append(custodian.Chain, entries...)
		if len(entries) < audit.MaxChainEntriesPerResponse {
			break
		}
		after = entries[len(entries)-1].ID
	}

	var afterHour time.Time
	for {
		payload, err := client.ReadAnchors(ctx, afterHour)
		if err != nil {
			return verify.Custodian{}, fmt.Errorf("failed to read the anchors from the custodian: %w", err)
		}
		custodian.Anchors = append(custodian.Anchors, payload.Anchors...)
		if len(payload.Anchors) < audit.MaxAnchorsPerResponse {
			break
		}

		afterHour, err = hourOf(payload.Anchors[len(payload.Anchors)-1].Anchor)
		if err != nil {
			return verify.Custodian{}, err
		}
	}

	afterHour = time.Time{}
	for {
		payload, err := client.ListAnchors(ctx, afterHour)
		if err != nil {
			return verify.Custodian{}, fmt.Errorf("failed to read the public anchors from the custodian: %w", err)
		}
		custodian.PublicAnchors = append(custodian.PublicAnchors, payload.Anchors...)
		if len(payload.Anchors) < audit.MaxAnchorsPerResponse {
			break
		}

		afterHour, err = hourOf(payload.Anchors[len(payload.Anchors)-1].Anchor)
		if err != nil {
			return verify.Custodian{}, err
		}
	}

	return custodian, nil
}

func hourOf(anchorJWS string) (time.Time, error) {
	anchor, err := receipt.ParseAnchorUnverified(anchorJWS)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to page through the anchors: %w", err)
	}

	return anchor.Hour, nil
}

// verifyEvents reads the events from the backups or the database, and checks
// them. For backups, it names every one of them with its SHA-256, in the
// order of the chain, so that the report names exactly which backups were
// checked.
func verifyEvents(ctx context.Context, options Options, custodianResult verify.CustodianResult, now time.Time, sources *report.Sources) (verify.EventsResult, error) {
	if options.Database != nil {
		sources.Database = options.DatabaseURL
		return verify.VerifyEvents(database.ReadDatabase(ctx, options.Database), custodianResult, now)
	}

	backups := make([]verify.BackupSource, 0, len(options.BackupPaths))
	for _, path := range options.BackupPaths {
		backups = append(backups, verify.BackupSource{
			Name: path,
			Open: func() (io.ReadCloser, error) {
				return os.Open(path)
			},
		})
	}

	result, err := verify.VerifyBackups(backups, custodianResult, now)
	if err != nil {
		return verify.EventsResult{}, err
	}

	for _, backup := range result.Backups {
		sources.Backups = append(sources.Backups, report.Backup{Path: backup.Name, SHA256: backup.SHA256})
	}

	return result.EventsResult, nil
}
