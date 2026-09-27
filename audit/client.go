package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// methodQuery is the HTTP method the custodian answers reads with, since a
// read with parameters is neither a GET nor a POST.
const methodQuery = "QUERY"

// clientTimeout bounds every request, so that a custodian that does not answer
// fails the read instead of stalling it.
const clientTimeout = 30 * time.Second

// ErrAccessDenied means that the custodian has refused the auditor token,
// because it is unknown, has expired, or has been revoked.
var ErrAccessDenied = errors.New("the custodian has refused the auditor token")

// ErrTransient means that reading failed for a reason that may go away by
// itself, so that trying again later may succeed.
var ErrTransient = errors.New("the custodian is temporarily unavailable")

// Client reads from the custodian with an auditor token.
type Client struct {
	serverURL    *url.URL
	auditorToken string
	httpClient   *http.Client
}

// NewClient returns a client for the custodian at the given URL. The auditor
// token may be empty, which only allows reading the public chain of anchors.
func NewClient(serverURL, auditorToken string) (*Client, error) {
	parsedURL, err := url.Parse(serverURL)
	if err != nil {
		return nil, fmt.Errorf("invalid server URL: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("invalid server URL: the scheme must be http or https, got %q", parsedURL.Scheme)
	}

	return &Client{
		serverURL:    parsedURL,
		auditorToken: auditorToken,
		httpClient:   &http.Client{Timeout: clientTimeout},
	}, nil
}

// ReadInstance reads what the custodian knows about the audited instance,
// apart from its chain.
func (c *Client) ReadInstance(ctx context.Context) (ReadInstanceResponseBodyPayload, error) {
	return read[ReadInstanceResponseBodyPayload](ctx, c, methodQuery, ReadInstancePath, nil, ReadInstanceResponseType)
}

// ReadChain reads the entries of the chain after the one with the given ID, at
// most MaxChainEntriesPerResponse of them. An empty ID reads from the start.
func (c *Client) ReadChain(ctx context.Context, after string) ([]ChainEntry, error) {
	parameters := url.Values{}
	if after != "" {
		parameters.Set(ChainAfterParameter, after)
	}

	payload, err := read[ReadChainResponseBodyPayload](ctx, c, methodQuery, ReadChainPath, parameters, ReadChainResponseType)

	return payload.Entries, err
}

// ReadAnchors reads the anchors after the given hour, together with the proofs
// of the audited instance, at most MaxAnchorsPerResponse of them. A zero hour
// reads from the start.
func (c *Client) ReadAnchors(ctx context.Context, after time.Time) (ReadAnchorsResponseBodyPayload, error) {
	return read[ReadAnchorsResponseBodyPayload](ctx, c, methodQuery, ReadAnchorsPath, anchorsAfter(after), ReadAnchorsResponseType)
}

// ListAnchors reads the public chain of anchors after the given hour, at most
// MaxAnchorsPerResponse of them. A zero hour reads from the start.
func (c *Client) ListAnchors(ctx context.Context, after time.Time) (ListAnchorsResponseBodyPayload, error) {
	return read[ListAnchorsResponseBodyPayload](ctx, c, http.MethodGet, ListAnchorsPath, anchorsAfter(after), ListAnchorsResponseType)
}

func anchorsAfter(after time.Time) url.Values {
	parameters := url.Values{}
	if !after.IsZero() {
		parameters.Set(AnchorsAfterParameter, after.UTC().Format(time.RFC3339))
	}

	return parameters
}

// responseBody is the shape of every answer of the custodian: a type, and a
// payload that depends on it.
type responseBody[TPayload any] struct {
	Type    string   `json:"type"`
	Payload TPayload `json:"payload"`
}

// read sends a request, and returns the payload of the answer, after checking
// that the answer has the expected type.
func read[TPayload any](ctx context.Context, c *Client, method, path string, parameters url.Values, expectedType string) (TPayload, error) {
	var body responseBody[TPayload]

	requestURL := c.serverURL.JoinPath(path)
	requestURL.RawQuery = parameters.Encode()

	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), nil)
	if err != nil {
		return body.Payload, err
	}
	if c.auditorToken != "" {
		request.Header.Set("Authorization", "Bearer "+c.auditorToken)
	}

	response, err := c.httpClient.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return body.Payload, err
		}

		return body.Payload, fmt.Errorf("%w: %v", ErrTransient, err)
	}
	defer response.Body.Close()

	switch {
	case response.StatusCode == http.StatusOK:
	case response.StatusCode == http.StatusUnauthorized, response.StatusCode == http.StatusForbidden:
		return body.Payload, ErrAccessDenied
	case response.StatusCode >= http.StatusInternalServerError, response.StatusCode == http.StatusTooManyRequests, response.StatusCode == http.StatusRequestTimeout:
		return body.Payload, fmt.Errorf("%w: got HTTP status code %d", ErrTransient, response.StatusCode)
	default:
		return body.Payload, fmt.Errorf("failed to read %s, got HTTP status code %d", path, response.StatusCode)
	}

	err = json.NewDecoder(response.Body).Decode(&body)
	if err != nil {
		return body.Payload, fmt.Errorf("failed to read %s: %w", path, err)
	}
	if body.Type != expectedType {
		return body.Payload, fmt.Errorf("failed to read %s, got unexpected response type %q", path, body.Type)
	}

	return body.Payload, nil
}
