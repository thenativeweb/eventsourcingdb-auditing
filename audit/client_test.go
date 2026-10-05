package audit_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thenativeweb/eventsourcingdb-auditing/audit"
)

const testAuditorToken = "test-auditor-token"

// newTestServer starts a custodian for a single test that answers every
// request with the given handler, and returns a client for it.
func newTestServer(t *testing.T, handler http.HandlerFunc) *audit.Client {
	t.Helper()

	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	client, err := audit.NewClient(server.URL, testAuditorToken)
	require.NoError(t, err)

	return client
}

func writeJSON(t *testing.T, writer http.ResponseWriter, body any) {
	t.Helper()

	assert.NoError(t, json.NewEncoder(writer).Encode(body))
}

func TestNewClient(t *testing.T) {
	t.Run("rejects a server URL that is not http or https", func(t *testing.T) {
		_, err := audit.NewClient("ftp://example.com", testAuditorToken)

		assert.Error(t, err)
	})
}

func TestReadInstance(t *testing.T) {
	t.Run("reads the audited instance with the auditor token", func(t *testing.T) {
		registeredAt := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
		instance := audit.ReadInstanceResponseBodyPayload{
			InstanceID:   "instance-1",
			Name:         "production",
			RegisteredAt: registeredAt,
			Intervals: []audit.Intervals{
				{ValidFrom: registeredAt, MinimumIntervalInMilliseconds: 60_000, HeartbeatIntervalInMilliseconds: 600_000},
			},
			SigningKeyCertificates: []string{"certificate"},
			AuditAccess:            audit.AuditAccess{ID: "access-1", GrantedAt: registeredAt, ValidUntil: registeredAt.AddDate(0, 3, 0)},
		}

		client := newTestServer(t, func(writer http.ResponseWriter, request *http.Request) {
			assert.Equal(t, "QUERY", request.Method)
			assert.Equal(t, audit.ReadInstancePath, request.URL.Path)
			assert.Equal(t, "Bearer "+testAuditorToken, request.Header.Get("Authorization"))

			writeJSON(t, writer, audit.ReadInstanceResponseBody{Type: audit.ReadInstanceResponseType, Payload: instance})
		})

		read, err := client.ReadInstance(context.Background())

		require.NoError(t, err)
		assert.Equal(t, instance, read)
	})
}

func TestReadChain(t *testing.T) {
	t.Run("reads from the start without an ID", func(t *testing.T) {
		client := newTestServer(t, func(writer http.ResponseWriter, request *http.Request) {
			assert.Equal(t, audit.ReadChainPath, request.URL.Path)
			assert.False(t, request.URL.Query().Has(audit.ChainAfterParameter))

			writeJSON(t, writer, audit.ReadChainResponseBody{
				Type: audit.ReadChainResponseType,
				Payload: audit.ReadChainResponseBodyPayload{Entries: []audit.ChainEntry{{
					ID:   "7",
					Type: audit.FingerprintRecordedType,
					FingerprintRecorded: &audit.FingerprintRecorded{
						EventID: "5", EventHash: "hash-5", Sequence: 1, Receipt: "receipt-1",
					},
				}}},
			})
		})

		entries, err := client.ReadChain(context.Background(), "")

		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, "receipt-1", entries[0].FingerprintRecorded.Receipt)
		assert.Nil(t, entries[0].BaselineReset)
	})

	t.Run("reads after the given ID", func(t *testing.T) {
		client := newTestServer(t, func(writer http.ResponseWriter, request *http.Request) {
			assert.Equal(t, "7", request.URL.Query().Get(audit.ChainAfterParameter))

			writeJSON(t, writer, audit.ReadChainResponseBody{Type: audit.ReadChainResponseType})
		})

		entries, err := client.ReadChain(context.Background(), "7")

		require.NoError(t, err)
		assert.Empty(t, entries)
	})
}

func TestReadAnchors(t *testing.T) {
	t.Run("reads the anchors with the proofs after the given hour", func(t *testing.T) {
		hour := time.Date(2026, 9, 1, 10, 0, 0, 0, time.FixedZone("CEST", 2*60*60))

		client := newTestServer(t, func(writer http.ResponseWriter, request *http.Request) {
			assert.Equal(t, "QUERY", request.Method)
			assert.Equal(t, audit.ReadAnchorsPath, request.URL.Path)
			assert.Equal(t, "2026-09-01T08:00:00Z", request.URL.Query().Get(audit.AnchorsAfterParameter))

			writeJSON(t, writer, audit.ReadAnchorsResponseBody{
				Type: audit.ReadAnchorsResponseType,
				Payload: audit.ReadAnchorsResponseBodyPayload{Anchors: []audit.AnchorWithProof{{
					StampedAnchor: audit.StampedAnchor{Anchor: "anchor", TimestampToken: "token"},
					Proof:         &audit.AnchorProof{Receipt: "receipt", Salt: "salt", Siblings: []audit.ProofSibling{{Hash: "hash", Position: "left"}}},
				}}},
			})
		})

		payload, err := client.ReadAnchors(context.Background(), hour)

		require.NoError(t, err)
		require.Len(t, payload.Anchors, 1)
		assert.Equal(t, "receipt", payload.Anchors[0].Proof.Receipt)
	})
}

func TestListAnchors(t *testing.T) {
	t.Run("reads the public chain of anchors without a token", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			assert.Equal(t, "QUERY", request.Method)
			assert.Equal(t, audit.ListAnchorsPath, request.URL.Path)
			assert.Empty(t, request.Header.Get("Authorization"))
			assert.False(t, request.URL.Query().Has(audit.AnchorsAfterParameter))

			writeJSON(t, writer, audit.ListAnchorsResponseBody{
				Type:    audit.ListAnchorsResponseType,
				Payload: audit.ListAnchorsResponseBodyPayload{Anchors: []audit.StampedAnchor{{Anchor: "anchor"}}},
			})
		}))
		t.Cleanup(server.Close)

		client, err := audit.NewClient(server.URL, "")
		require.NoError(t, err)

		payload, err := client.ListAnchors(context.Background(), time.Time{})

		require.NoError(t, err)
		assert.Equal(t, []audit.StampedAnchor{{Anchor: "anchor"}}, payload.Anchors)
	})
}

func TestErrors(t *testing.T) {
	for _, statusCode := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run("reports a refused token for status code "+http.StatusText(statusCode), func(t *testing.T) {
			client := newTestServer(t, func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(statusCode)
			})

			_, err := client.ReadInstance(context.Background())

			assert.ErrorIs(t, err, audit.ErrAccessDenied)
		})
	}

	for _, statusCode := range []int{http.StatusInternalServerError, http.StatusServiceUnavailable, http.StatusTooManyRequests} {
		t.Run("reports a transient failure for status code "+http.StatusText(statusCode), func(t *testing.T) {
			client := newTestServer(t, func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(statusCode)
			})

			_, err := client.ReadChain(context.Background(), "")

			assert.ErrorIs(t, err, audit.ErrTransient)
		})
	}

	t.Run("reports an unreachable custodian as transient", func(t *testing.T) {
		client, err := audit.NewClient("http://127.0.0.1:1", testAuditorToken)
		require.NoError(t, err)

		_, err = client.ReadInstance(context.Background())

		assert.ErrorIs(t, err, audit.ErrTransient)
	})

	t.Run("reports a cancelled context as it is, not as transient", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		client := newTestServer(t, func(writer http.ResponseWriter, request *http.Request) {})

		_, err := client.ReadInstance(ctx)

		assert.ErrorIs(t, err, context.Canceled)
		assert.NotErrorIs(t, err, audit.ErrTransient)
	})

	t.Run("rejects an answer of an unexpected type", func(t *testing.T) {
		client := newTestServer(t, func(writer http.ResponseWriter, request *http.Request) {
			writeJSON(t, writer, audit.ReadChainResponseBody{Type: "io.thenativeweb.custody.something-else"})
		})

		_, err := client.ReadChain(context.Background(), "")

		assert.ErrorContains(t, err, "unexpected response type")
	})

	t.Run("rejects an answer that is not JSON", func(t *testing.T) {
		client := newTestServer(t, func(writer http.ResponseWriter, request *http.Request) {
			_, _ = writer.Write([]byte("not json"))
		})

		_, err := client.ReadChain(context.Background(), "")

		assert.Error(t, err)
		assert.NotErrorIs(t, err, audit.ErrTransient)
	})

	t.Run("reports any other status code as a failure that trying again will not fix", func(t *testing.T) {
		client := newTestServer(t, func(writer http.ResponseWriter, request *http.Request) {
			writer.WriteHeader(http.StatusBadRequest)
		})

		_, err := client.ReadChain(context.Background(), "")

		assert.Error(t, err)
		assert.NotErrorIs(t, err, audit.ErrTransient)
		assert.NotErrorIs(t, err, audit.ErrAccessDenied)
	})
}
