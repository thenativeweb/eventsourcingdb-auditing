package trustedlists

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"time"
)

// The URIs a trusted list uses for what matters here.
const (
	serviceTypeQTST        = "http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST"
	serviceStatusGranted   = "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted"
	listTypeListOfTheLists = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUlistofthelists"
	listTypeGeneric        = "http://uri.etsi.org/TrstSvc/TrustedList/TSLType/EUgeneric"
	mimeTypeXML            = "application/vnd.etsi.tsl+xml"
)

// trustedList is a trusted list according to ETSI TS 119 612, the list of
// the lists as well as the one of a member state, as far as it matters here.
// The names of the elements are matched without their namespace.
type trustedList struct {
	SchemeInformation struct {
		TSLType               string    `xml:"TSLType"`
		SchemeTerritory       string    `xml:"SchemeTerritory"`
		ListIssueDateTime     time.Time `xml:"ListIssueDateTime"`
		SchemeInformationURIs []string  `xml:"SchemeInformationURI>URI"`
		Pointers              []pointer `xml:"PointersToOtherTSL>OtherTSLPointer"`
	} `xml:"SchemeInformation"`

	Providers []provider `xml:"TrustServiceProviderList>TrustServiceProvider"`
}

// pointer points to another trusted list, and names the certificates it may
// be signed with.
type pointer struct {
	Identities  []digitalIdentity  `xml:"ServiceDigitalIdentities>ServiceDigitalIdentity"`
	Location    string             `xml:"TSLLocation"`
	Information []otherInformation `xml:"AdditionalInformation>OtherInformation"`
}

type otherInformation struct {
	TSLType         string `xml:"TSLType"`
	SchemeTerritory string `xml:"SchemeTerritory"`
	MimeType        string `xml:"MimeType"`
}

func (p pointer) information() otherInformation {
	var merged otherInformation
	for _, information := range p.Information {
		if information.TSLType != "" {
			merged.TSLType = information.TSLType
		}
		if information.SchemeTerritory != "" {
			merged.SchemeTerritory = information.SchemeTerritory
		}
		if information.MimeType != "" {
			merged.MimeType = information.MimeType
		}
	}

	return merged
}

type digitalIdentity struct {
	IDs []digitalID `xml:"DigitalId"`
}

type digitalID struct {
	X509Certificate string `xml:"X509Certificate"`
}

// certificates returns the certificates a digital identity names. Names and
// key identifiers alone are not used, since they can not be checked.
func (i digitalIdentity) certificates() []*x509.Certificate {
	var certificates []*x509.Certificate
	for _, id := range i.IDs {
		if id.X509Certificate == "" {
			continue
		}

		der, err := base64.StdEncoding.DecodeString(stripWhitespace(id.X509Certificate))
		if err != nil {
			continue
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			continue
		}
		certificates = append(certificates, certificate)
	}

	return certificates
}

type provider struct {
	Names    []string  `xml:"TSPInformation>TSPName>Name"`
	Services []service `xml:"TSPServices>TSPService"`
}

type service struct {
	Information serviceInformation   `xml:"ServiceInformation"`
	History     []serviceInformation `xml:"ServiceHistory>ServiceHistoryInstance"`
}

type serviceInformation struct {
	TypeIdentifier     string          `xml:"ServiceTypeIdentifier"`
	Names              []string        `xml:"ServiceName>Name"`
	Identity           digitalIdentity `xml:"ServiceDigitalIdentity"`
	Status             string          `xml:"ServiceStatus"`
	StatusStartingTime time.Time       `xml:"StatusStartingTime"`
}

// statusAt returns the status a service had at a point in time, which is the
// latest status that started before it, or false if the service did not exist
// yet.
func (s service) statusAt(at time.Time) (serviceInformation, bool) {
	var current serviceInformation
	found := false

	for _, information := range append([]serviceInformation{s.Information}, s.History...) {
		if information.StatusStartingTime.After(at) {
			continue
		}
		if !found || information.StatusStartingTime.After(current.StatusStartingTime) {
			current, found = information, true
		}
	}

	return current, found
}

// parseList reads a trusted list, whose signature must have been checked.
func parseList(data []byte) (trustedList, error) {
	var list trustedList

	err := xml.Unmarshal(data, &list)
	if err != nil {
		return trustedList{}, fmt.Errorf("the trusted list is malformed: %w", err)
	}

	return list, nil
}

// firstName returns the first of several names, which is the English one in
// most trusted lists.
func firstName(names []string) string {
	if len(names) == 0 {
		return ""
	}

	return names[0]
}
