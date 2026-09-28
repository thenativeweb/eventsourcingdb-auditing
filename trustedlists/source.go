package trustedlists

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// maxListSize bounds a single trusted list. The largest ones have a few
// megabytes.
const maxListSize = 64 * 1024 * 1024

// Source provides trusted lists by their URL.
type Source interface {
	Fetch(ctx context.Context, url string) ([]byte, error)
}

// HTTPSource fetches trusted lists from where they are published.
type HTTPSource struct {
	Client *http.Client
}

// NewHTTPSource returns a source that fetches trusted lists over the network.
func NewHTTPSource() HTTPSource {
	return HTTPSource{Client: &http.Client{Timeout: 2 * time.Minute}}
}

func (s HTTPSource) Fetch(ctx context.Context, url string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	response, err := s.Client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", url, err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch %s, got HTTP status code %d", url, response.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(response.Body, maxListSize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %s: %w", url, err)
	}
	if len(data) > maxListSize {
		return nil, fmt.Errorf("the list at %s is larger than %d bytes", url, maxListSize)
	}

	return data, nil
}

// DirectorySource provides trusted lists from a directory, for verifying
// without network. Download fills such a directory.
type DirectorySource struct {
	Path string
}

func (s DirectorySource) Fetch(ctx context.Context, url string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(s.Path, fileNameFor(url)))
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("the trusted list %s is not in %s", url, s.Path)
	}

	return data, err
}

// fileNameFor names the file a trusted list is kept in, by the hash of its
// URL, since URLs make poor file names.
func fileNameFor(url string) string {
	hash := sha256.Sum256([]byte(url))
	return hex.EncodeToString(hash[:8]) + ".xml"
}

// recordingSource fetches from another source, and writes every list it
// fetches into a directory.
type recordingSource struct {
	source    Source
	directory string
}

func (s recordingSource) Fetch(ctx context.Context, url string) ([]byte, error) {
	data, err := s.source.Fetch(ctx, url)
	if err != nil {
		return nil, err
	}

	err = os.WriteFile(filepath.Join(s.directory, fileNameFor(url)), data, 0o644)
	if err != nil {
		return nil, err
	}

	return data, nil
}
