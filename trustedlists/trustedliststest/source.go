package trustedliststest

import (
	"bytes"
	"compress/gzip"
	"context"
	"embed"
	"fmt"
	"io"
)

//go:embed lists/*.xml.gz
var lists embed.FS

// The names of the lists this package holds.
const (
	ListOfTheLists = "eu-lotl.xml.gz"
	Germany        = "de.xml.gz"
	Hungary        = "hu.xml.gz"
	Slovenia       = "si.xml.gz"
	Iceland        = "is.xml.gz"
)

// byURL maps the URLs the lists are published at to the lists.
var byURL = map[string]string{
	"https://ec.europa.eu/tools/lotl/eu-lotl.xml":              ListOfTheLists,
	"https://tl.bundesnetzagentur.de/TL-DE.xml":                Germany,
	"https://www.nmhh.hu/tl/pub/HU_TL.xml":                     Hungary,
	"https://www.tl.gov.si/SI_TL.xml":                          Slovenia,
	"https://tsl.fjarskiptastofa.is/library/skrar/tsl/tsl.xml": Iceland,
}

// Read returns a list by its name, decompressed.
func Read(name string) ([]byte, error) {
	compressed, err := lists.ReadFile("lists/" + name)
	if err != nil {
		return nil, err
	}

	reader, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, err
	}

	return io.ReadAll(reader)
}

// Source provides the lists by the URLs they are published at, and any other
// list from Extra. It fails for any other URL, as a list that can not be
// reached does.
type Source struct {
	Extra map[string][]byte
}

func (s Source) Fetch(ctx context.Context, url string) ([]byte, error) {
	if data, isKnown := s.Extra[url]; isKnown {
		return data, nil
	}
	if name, isKnown := byURL[url]; isKnown {
		return Read(name)
	}

	return nil, fmt.Errorf("%s is not among the lists of trustedliststest", url)
}
