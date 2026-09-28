// Package trustedlists checks whether a time stamp was issued by a qualified
// time stamping service, using the EU trusted lists.
//
// The European Commission publishes a list of the trusted lists (LOTL), which
// points to the trusted list of every member state. Both are XML documents
// with an enveloped XAdES signature. The LOTL is trusted if it is signed with
// one of the certificates the Commission has announced in the Official
// Journal of the European Union, or with one announced by a pivot LOTL that
// is itself trusted. A trusted list of a member state is trusted if it is
// signed with one of the certificates the LOTL names for it.
//
// A time stamp counts as qualified if the certificate it was signed with, or
// the one that issued it, is the digital identity of a service of the type
// QTST in the trusted list of the country of the time stamping authority, and
// if that service was granted at the time of the time stamp.
package trustedlists
