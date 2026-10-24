package databasetest

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-client-golang/v2/eventsourcingdb"
	"github.com/thenativeweb/eventsourcingdb-client-golang/v2/eventsourcingdbtest"
)

// ImageTagEnvironmentVariable names the environment variable that sets the
// tag of the image of EventSourcingDB the tests run against, such as latest
// or preview, as for the tests of the client SDKs.
const ImageTagEnvironmentVariable = "EVENTSOURCINGDB_IMAGE_TAG"

// defaultImageTag is the tag of the image the tests run against if the
// environment variable sets none.
const defaultImageTag = "latest"

// ImageTag returns the tag of the image of EventSourcingDB the tests run
// against: the value of EVENTSOURCINGDB_IMAGE_TAG if it is set and not empty,
// and latest otherwise.
//
// It must be called while a test runs, not before, as in TestMain before
// m.Run, since the test cache only sees the environment variables a test
// reads while it runs. Otherwise, a run against another image would reuse the
// results of the run before.
func ImageTag() string {
	imageTag := os.Getenv(ImageTagEnvironmentVariable)
	if imageTag == "" {
		return defaultImageTag
	}

	return imageTag
}

// Start starts an EventSourcingDB for a single test, from the image ImageTag
// names, and stops it once the test is over. It returns the container and a
// client for it.
func Start(t testing.TB) (*eventsourcingdbtest.Container, *eventsourcingdb.Client) {
	t.Helper()

	container := eventsourcingdbtest.NewContainer().WithImageTag(ImageTag())
	require.NoError(t, container.Start(t.Context()))
	t.Cleanup(func() {
		_ = container.Stop(context.Background())
	})

	client, err := container.GetClient(t.Context())
	require.NoError(t, err)

	return container, client
}
