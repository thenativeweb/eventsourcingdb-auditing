package verifytest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/thenativeweb/eventsourcingdb-auditing/audit"
)

// NewServer serves what the custodian hands out to an auditor with the given
// auditor token, for a single test, and returns its URL.
func NewServer(t testing.TB, custodian *Custodian, auditorToken string) string {
	t.Helper()

	data := custodian.Data()
	writeJSON := func(writer http.ResponseWriter, body any) {
		assert.NoError(t, json.NewEncoder(writer).Encode(body))
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != audit.ListAnchorsPath && request.Header.Get("Authorization") != "Bearer "+auditorToken {
			writer.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch request.URL.Path {
		case audit.ReadInstancePath:
			writeJSON(writer, audit.ReadInstanceResponseBody{Type: audit.ReadInstanceResponseType, Payload: data.Instance})

		case audit.ReadChainPath:
			after := request.URL.Query().Get(audit.ChainAfterParameter)
			entries := []audit.ChainEntry{}
			isAfter := after == ""
			for _, entry := range data.Chain {
				if isAfter {
					entries = append(entries, entry)
				}
				if entry.ID == after {
					isAfter = true
				}
			}
			writeJSON(writer, audit.ReadChainResponseBody{Type: audit.ReadChainResponseType, Payload: audit.ReadChainResponseBodyPayload{Entries: entries}})

		case audit.ReadAnchorsPath:
			writeJSON(writer, audit.ReadAnchorsResponseBody{Type: audit.ReadAnchorsResponseType, Payload: audit.ReadAnchorsResponseBodyPayload{Anchors: data.Anchors}})

		case audit.ListAnchorsPath:
			writeJSON(writer, audit.ListAnchorsResponseBody{Type: audit.ListAnchorsResponseType, Payload: audit.ListAnchorsResponseBodyPayload{Anchors: data.PublicAnchors}})

		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)

	return server.URL
}
