package trustedlists

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"
)

// ListOfTheListsURL is where the European Commission publishes the list of
// the trusted lists.
const ListOfTheListsURL = "https://ec.europa.eu/tools/lotl/eu-lotl.xml"

// officialJournalCertificates are the SHA-256 fingerprints of the certificates
// that may sign the list of the lists, as the European Commission has
// announced them in the Official Journal of the European Union, C/2026/1944.
// A later change of these certificates is announced by pivot lists, which the
// checker follows from here.
var officialJournalCertificates = []string{
	"c0641c4f7d56c431b1c924742db7fce9c1eef7d7fd212113a2768486b3abcdc5",
	"e0a620fbb6747362bb933ac44169d676a553444716cf5f31605f12a22b8396b1",
	"df7e29360c34b2b8d6d5f40325c1d4d12c9922cecd33b7407674a74b2b3ca1e5",
	"b63d416744e7098bf9ec2caa596a93bc2468e37f8284ba65ecc061711bcbaa18",
	"236103f03a8031ae8f47f9059bf8de38564cdbfebedde4a597d50f8980aa653b",
	"d2064fdd70f6982dcc516b86d9d5c56aea939417c624b2e478c0b29de54f8474",
}

// ErrUntrustedList means that a trusted list is signed with a certificate it
// may not be signed with.
var ErrUntrustedList = errors.New("the trusted list is not signed with a certificate it may be signed with")

// Checker tells whether a time stamping service was qualified, using the EU
// trusted lists. It checks the list of the lists once, and every trusted list
// of a member state the first time it needs it.
type Checker struct {
	source         Source
	listOfTheLists trustedList

	mutex     sync.Mutex
	byCountry map[string]trustedList
}

// Option configures a checker.
type Option func(*checkerOptions)

type checkerOptions struct {
	url     string
	anchors []string
}

// WithListOfTheLists makes the checker start from another list of the lists,
// trusted by the given SHA-256 fingerprints of its signing certificates. It is
// meant for tests.
func WithListOfTheLists(url string, anchors ...string) Option {
	return func(options *checkerOptions) {
		options.url = url
		options.anchors = anchors
	}
}

// NewChecker fetches the list of the lists, and checks that it is signed with
// a certificate announced in the Official Journal, or in a pivot list that is
// itself trusted.
func NewChecker(ctx context.Context, source Source, options ...Option) (*Checker, error) {
	configured := checkerOptions{url: ListOfTheListsURL, anchors: officialJournalCertificates}
	for _, option := range options {
		option(&configured)
	}

	data, err := source.Fetch(ctx, configured.url)
	if err != nil {
		return nil, err
	}

	list, signer, err := readList(data)
	if err != nil {
		return nil, fmt.Errorf("the list of the lists: %w", err)
	}
	if list.SchemeInformation.TSLType != listTypeListOfTheLists {
		return nil, fmt.Errorf("the list of the lists has the type %q", list.SchemeInformation.TSLType)
	}

	trusted := slices.Clone(configured.anchors)
	if !slices.Contains(trusted, fingerprint(signer)) {
		trusted, err = followPivots(ctx, source, list, trusted)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(trusted, fingerprint(signer)) {
			return nil, fmt.Errorf("the list of the lists: %w", ErrUntrustedList)
		}
	}

	return &Checker{source: source, listOfTheLists: list, byCountry: map[string]trustedList{}}, nil
}

// readList checks the signature of a trusted list, reads it, and checks that
// its certificate was valid when the list was issued.
func readList(data []byte) (trustedList, *x509.Certificate, error) {
	signer, err := verifySignature(data)
	if err != nil {
		return trustedList{}, nil, err
	}

	list, err := parseList(data)
	if err != nil {
		return trustedList{}, nil, err
	}

	issuedAt := list.SchemeInformation.ListIssueDateTime
	if issuedAt.Before(signer.NotBefore) || issuedAt.After(signer.NotAfter) {
		return trustedList{}, nil, fmt.Errorf("%w: the certificate was not valid when the list was issued", ErrUntrustedList)
	}

	return list, signer, nil
}

// followPivots follows the pivot lists the list of the lists names, from the
// oldest to the newest. Every pivot that is signed with a trusted certificate
// announces the certificates for the lists after it, in its pointer to the
// list of the lists.
func followPivots(ctx context.Context, source Source, list trustedList, trusted []string) ([]string, error) {
	var pivots []string
	for _, uri := range list.SchemeInformation.SchemeInformationURIs {
		if strings.Contains(uri, "pivot") && strings.HasSuffix(uri, ".xml") {
			pivots = append(pivots, uri)
		}
	}

	// The list names the pivots from the newest to the oldest.
	slices.Reverse(pivots)

	for _, url := range pivots {
		data, err := source.Fetch(ctx, url)
		if err != nil {
			return nil, err
		}

		pivot, signer, err := readList(data)
		if err != nil || !slices.Contains(trusted, fingerprint(signer)) {
			continue
		}

		announced := announcedCertificates(pivot)
		if len(announced) > 0 {
			trusted = announced
		}
	}

	return trusted, nil
}

// announcedCertificates returns the fingerprints of the certificates a list
// of the lists announces for itself.
func announcedCertificates(list trustedList) []string {
	var announced []string
	for _, pointer := range list.SchemeInformation.Pointers {
		if pointer.information().TSLType != listTypeListOfTheLists {
			continue
		}

		for _, identity := range pointer.Identities {
			for _, certificate := range identity.certificates() {
				announced = append(announced, fingerprint(certificate))
			}
		}
	}

	return announced
}

func fingerprint(certificate *x509.Certificate) string {
	hash := sha256.Sum256(certificate.Raw)
	return hex.EncodeToString(hash[:])
}

// ListOfTheListsIssuedAt returns when the list of the lists was issued, which
// names the state of the trusted lists a check relies on.
func (c *Checker) ListOfTheListsIssuedAt() time.Time {
	return c.listOfTheLists.SchemeInformation.ListIssueDateTime
}

// errNoList means that the list of the lists points to no trusted list for a
// country.
var errNoList = errors.New("the list of the lists points to no trusted list for this country")

// listOf returns the trusted list of a country, after checking that it is
// signed with one of the certificates the list of the lists names for it.
func (c *Checker) listOf(ctx context.Context, country string) (trustedList, error) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if list, isKnown := c.byCountry[country]; isKnown {
		return list, nil
	}

	for _, pointer := range c.listOfTheLists.SchemeInformation.Pointers {
		information := pointer.information()
		if information.SchemeTerritory != country || information.TSLType != listTypeGeneric || information.MimeType != mimeTypeXML {
			continue
		}

		data, err := c.source.Fetch(ctx, pointer.Location)
		if err != nil {
			return trustedList{}, err
		}

		list, signer, err := readList(data)
		if err != nil {
			return trustedList{}, fmt.Errorf("the trusted list of %s: %w", country, err)
		}

		isAllowed := false
		for _, identity := range pointer.Identities {
			for _, certificate := range identity.certificates() {
				isAllowed = isAllowed || certificate.Equal(signer)
			}
		}
		if !isAllowed {
			return trustedList{}, fmt.Errorf("the trusted list of %s: %w", country, ErrUntrustedList)
		}
		if list.SchemeInformation.SchemeTerritory != country {
			return trustedList{}, fmt.Errorf("the trusted list of %s is the one of %s", country, list.SchemeInformation.SchemeTerritory)
		}

		c.byCountry[country] = list
		return list, nil
	}

	return trustedList{}, errNoList
}

// Qualification tells whether a certificate belonged to a qualified time
// stamping service at a point in time, and names the service.
type Qualification struct {
	IsQualified bool
	Country     string
	Provider    string
	Service     string

	// ListIssuedAt is when the trusted list that tells was issued.
	ListIssuedAt time.Time

	// Reason says why the certificate does not count as qualified.
	Reason string
}

// Qualification tells whether the certificate a time stamp was signed with
// belonged to a qualified time stamping service at the time of the time
// stamp: whether it, or the certificate that issued it, is the digital
// identity of a QTST service in the trusted list of its country, and whether
// that service was granted then.
//
// It fails only if a trusted list can not be fetched or checked.
func (c *Checker) Qualification(ctx context.Context, certificate *x509.Certificate, at time.Time) (Qualification, error) {
	var countries []string
	for _, country := range append(slices.Clone(certificate.Subject.Country), certificate.Issuer.Country...) {
		if !slices.Contains(countries, country) {
			countries = append(countries, country)
		}
	}
	if len(countries) == 0 {
		return Qualification{Reason: "the certificate names no country, so no trusted list applies to it"}, nil
	}

	reasons := []string{}
	for _, country := range countries {
		list, err := c.listOf(ctx, country)
		if errors.Is(err, errNoList) {
			reasons = append(reasons, fmt.Sprintf("there is no trusted list for %s", country))
			continue
		}
		if err != nil {
			return Qualification{}, err
		}

		qualification, isListed := qualificationIn(list, certificate, at)
		qualification.Country = country
		qualification.ListIssuedAt = list.SchemeInformation.ListIssueDateTime
		if isListed {
			return qualification, nil
		}
		reasons = append(reasons, fmt.Sprintf("the trusted list of %s names no qualified time stamping service with this certificate", country))
	}

	return Qualification{Reason: strings.Join(reasons, ", and ")}, nil
}

// qualificationIn looks for a QTST service in a trusted list whose digital
// identity is the certificate, or the one that issued it, and tells whether
// it was granted at the time. It returns false if no such service is listed.
func qualificationIn(list trustedList, certificate *x509.Certificate, at time.Time) (Qualification, bool) {
	var found Qualification
	isListed := false

	for _, provider := range list.Providers {
		for _, listed := range provider.Services {
			if !identifies(listed, certificate) {
				continue
			}

			status, existed := listed.statusAt(at)
			if !existed || status.TypeIdentifier != serviceTypeQTST {
				continue
			}

			qualification := Qualification{
				Provider: firstName(provider.Names),
				Service:  firstName(status.Names),
			}
			if status.Status == serviceStatusGranted {
				qualification.IsQualified = true
				return qualification, true
			}

			qualification.Reason = fmt.Sprintf("the service %q of %q had the status %q then", qualification.Service, qualification.Provider, status.Status)
			found, isListed = qualification, true
		}
	}

	return found, isListed
}

// identifies reports whether a service names the certificate, or the one that
// issued it, as its digital identity, now or in its history.
func identifies(listed service, certificate *x509.Certificate) bool {
	for _, information := range append([]serviceInformation{listed.Information}, listed.History...) {
		for _, identity := range information.Identity.certificates() {
			if identity.Equal(certificate) || certificate.CheckSignatureFrom(identity) == nil {
				return true
			}
		}
	}

	return false
}

// Download fetches the list of the lists, the pivot lists it needs, and every
// trusted list of a member state it points to, and writes them into a
// directory, from which DirectorySource provides them without network. It
// returns the countries whose lists it has written. A list that can not be
// fetched or checked does not stop it, but ends up in the error it returns.
func Download(ctx context.Context, source Source, directory string, options ...Option) ([]string, error) {
	recording := recordingSource{source: source, directory: directory}

	checker, err := NewChecker(ctx, recording, options...)
	if err != nil {
		return nil, err
	}

	var countries []string
	var failures []error
	for _, pointer := range checker.listOfTheLists.SchemeInformation.Pointers {
		information := pointer.information()
		if information.TSLType != listTypeGeneric || information.MimeType != mimeTypeXML {
			continue
		}

		_, err := checker.listOf(ctx, information.SchemeTerritory)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", information.SchemeTerritory, err))
			continue
		}
		countries = append(countries, information.SchemeTerritory)
	}

	return countries, errors.Join(failures...)
}
