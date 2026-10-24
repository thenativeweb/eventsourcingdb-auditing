// Package databasetest provides an EventSourcingDB for tests, in a container,
// from the image that the environment variable EVENTSOURCINGDB_IMAGE_TAG
// names, so that the tests run against every version that matters, such as
// latest and preview, and backups that a real EventSourcingDB wrote, with the
// hashes it computed, among them a chain of a full backup and incremental
// ones, in both formats.
package databasetest
