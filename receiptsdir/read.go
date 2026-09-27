package receiptsdir

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/thenativeweb/eventsourcingdb-auditing/audit"
)

const (
	receiptsFilePrefix    = "receipts-"
	anchorsFilePrefix     = "anchors-"
	filesSuffix           = ".jsonl"
	certificatesDirectory = "certificates"
	certificateFileSuffix = ".jws"
	maxLineSize           = 16 * 1024 * 1024
)

// Directory is what the client has kept.
type Directory struct {
	// Receipts are the receipts in the order they were kept.
	Receipts []string

	// Anchors are the anchors in the order they were kept, each with its
	// time stamp and the proof of the instance.
	Anchors []audit.AnchorWithProof

	// Certificates are the certificates of the keys that signed them.
	Certificates []string
}

// Read reads a receipts directory.
func Read(path string) (Directory, error) {
	var directory Directory

	err := eachLineOfFiles(path, receiptsFilePrefix, func(line []byte) error {
		var kept struct {
			Receipt string `json:"receipt"`
		}
		err := json.Unmarshal(line, &kept)
		if err != nil || kept.Receipt == "" {
			return fmt.Errorf("the line does not name a receipt")
		}

		directory.Receipts = append(directory.Receipts, kept.Receipt)
		return nil
	})
	if err != nil {
		return Directory{}, err
	}

	err = eachLineOfFiles(path, anchorsFilePrefix, func(line []byte) error {
		var anchor audit.AnchorWithProof
		err := json.Unmarshal(line, &anchor)
		if err != nil || anchor.Anchor == "" {
			return fmt.Errorf("the line does not hold an anchor")
		}

		directory.Anchors = append(directory.Anchors, anchor)
		return nil
	})
	if err != nil {
		return Directory{}, err
	}

	directory.Certificates, err = readCertificates(filepath.Join(path, certificatesDirectory))
	if err != nil {
		return Directory{}, err
	}

	return directory, nil
}

// eachLineOfFiles calls the function for every line of the files with the
// given prefix, in the order of the days they are named after.
func eachLineOfFiles(path, prefix string, handle func(line []byte) error) error {
	entries, err := os.ReadDir(path)
	if err != nil {
		return fmt.Errorf("failed to read the receipts directory: %w", err)
	}

	var names []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), prefix) && strings.HasSuffix(entry.Name(), filesSuffix) {
			names = append(names, entry.Name())
		}
	}

	// The names hold the day as 2006-01-02, so sorting them by name sorts
	// them by day.
	slices.Sort(names)

	for _, name := range names {
		err := eachLine(filepath.Join(path, name), handle)
		if err != nil {
			return err
		}
	}

	return nil
}

func eachLine(path string, handle func(line []byte) error) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), maxLineSize)

	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}

		err := handle(scanner.Bytes())
		if err != nil {
			return fmt.Errorf("line %d of %s: %w", lineNumber, filepath.Base(path), err)
		}
	}

	return scanner.Err()
}

func readCertificates(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var certificates []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), certificateFileSuffix) {
			continue
		}

		data, err := os.ReadFile(filepath.Join(path, entry.Name()))
		if err != nil {
			return nil, err
		}
		certificates = append(certificates, strings.TrimSpace(string(data)))
	}

	return certificates, nil
}
