// Package database reads the events of the EventSourcingDB of a customer,
// either from a backup, in the format of /api/v1/backup or in the one of
// /api/v2/management/create-backup, full or incremental, or from the running
// database, and checks for every event whether its content still hashes to
// the hash it was written with.
package database
