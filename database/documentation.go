// Package database reads the events of the EventSourcingDB of a customer,
// either from a backup or from the running database, and checks for every
// event whether its content still hashes to the hash it was written with.
package database
