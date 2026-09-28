package timestamping

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/digitorus/timestamp"
)

// Stamper obtains time stamps. Authority is the one that speaks RFC 3161 over
// HTTP.
type Stamper interface {
	Stamp(ctx context.Context, digest [sha256.Size]byte) (Token, error)
}

// Authority is a time stamping authority that speaks RFC 3161 over HTTP.
type Authority struct {
	URL string

	// Username and Password are sent with Basic authentication, if the
	// authority requires it.
	Username string
	Password string

	HTTPClient *http.Client
}

// maxResponseSize bounds the answer of an authority, which carries a token
// and a few certificates.
const maxResponseSize = 1 << 20

// Stamp asks the authority for a time stamp over the given digest, and checks
// the answer before returning it.
func (a Authority) Stamp(ctx context.Context, digest [sha256.Size]byte) (Token, error) {
	nonce, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	if err != nil {
		return Token{}, err
	}

	requestBody, err := (&timestamp.Request{
		HashAlgorithm: crypto.SHA256,
		HashedMessage: digest[:],
		Certificates:  true,
		Nonce:         nonce,
	}).Marshal()
	if err != nil {
		return Token{}, err
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, a.URL, bytes.NewReader(requestBody))
	if err != nil {
		return Token{}, err
	}
	request.Header.Set("Content-Type", "application/timestamp-query")
	request.Header.Set("Accept", "application/timestamp-reply")
	if a.Username != "" {
		request.SetBasicAuth(a.Username, a.Password)
	}

	httpClient := a.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	response, err := httpClient.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return Token{}, err
		}
		return Token{}, fmt.Errorf("%w: %w", ErrTransient, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		err := fmt.Errorf("the time stamping authority answered with HTTP status code '%d'", response.StatusCode)
		if response.StatusCode >= http.StatusInternalServerError || response.StatusCode == http.StatusTooManyRequests {
			return Token{}, fmt.Errorf("%w: %w", ErrTransient, err)
		}
		return Token{}, err
	}

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, maxResponseSize))
	if err != nil {
		return Token{}, fmt.Errorf("%w: %w", ErrTransient, err)
	}

	rawToken, err := tokenOf(responseBody)
	if err != nil {
		return Token{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}

	token, info, err := verify(rawToken, digest)
	if err != nil {
		return Token{}, err
	}

	// The nonce makes sure that the answer belongs to this request, and is
	// not an older time stamp played back.
	if info.Nonce == nil || info.Nonce.Cmp(nonce) != 0 {
		return Token{}, fmt.Errorf("%w: the time stamp does not answer this request", ErrInvalid)
	}

	return token, nil
}

type timeStampResponse struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type pkiStatusInfo struct {
	Status       int
	StatusString []string       `asn1:"optional,utf8"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// The statuses of RFC 3161 with which an authority hands out a time stamp.
const (
	statusGranted         = 0
	statusGrantedWithMods = 1
)

// tokenOf returns the time stamp token of an answer, if the authority has
// granted the request.
func tokenOf(responseBody []byte) ([]byte, error) {
	var response timeStampResponse
	rest, err := asn1.Unmarshal(responseBody, &response)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, errors.New("the answer of the time stamping authority is followed by other data")
	}

	if response.Status.Status != statusGranted && response.Status.Status != statusGrantedWithMods {
		return nil, fmt.Errorf("the time stamping authority rejected the request with status %d: %s", response.Status.Status, strings.Join(response.Status.StatusString, ", "))
	}
	if len(response.TimeStampToken.FullBytes) == 0 {
		return nil, errors.New("the answer of the time stamping authority carries no time stamp")
	}

	return response.TimeStampToken.FullBytes, nil
}
