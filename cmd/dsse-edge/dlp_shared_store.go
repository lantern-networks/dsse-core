package main

import (
	"context"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
)

type dlpSharedUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

func isDLPSharedPersister(p blobstore.Persister) bool { _, ok := p.(dlpSharedUpdater); return ok }

// Only used to run the same complete restore validation on a transaction's row.
type dlpSnapshotReader []byte

func (p dlpSnapshotReader) Load() ([]byte, error) { return p, nil }
func (p dlpSnapshotReader) Save([]byte) error     { return fmt.Errorf("read-only DLP snapshot") }
func loadDLPSharedCandidate(raw []byte, populated bool, next interface {
	SetPersister(blobstore.Persister) error
}) error {
	if raw == nil && populated {
		return fmt.Errorf("shared DLP authority is missing")
	}
	if err := next.SetPersister(dlpSnapshotReader(raw)); err != nil {
		return err
	}
	return next.SetPersister(nil)
}
