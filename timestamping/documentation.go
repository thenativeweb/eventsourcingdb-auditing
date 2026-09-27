// Package timestamping obtains and checks time stamps according to RFC 3161,
// which is the protocol qualified trust service providers (QTSP) offer
// qualified electronic time stamps under eIDAS with.
//
// The check here is a basic one: that the time stamp covers the expected
// digest, and that its signature matches the certificate of the time stamping
// authority it carries. Whether that certificate belongs to a qualified trust
// service provider is up to the tools an auditor uses, since that needs the
// EU trusted lists.
package timestamping
