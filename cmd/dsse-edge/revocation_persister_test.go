package main

import (
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"sync/atomic"
)

// Replace real candidate bytes before reporting uncertain flush, distinct from a refused save.
type revocationAuditPersister struct {
	base               blobstore.FilePersister
	fail               atomic.Bool
	replaceBeforeError bool
}

func (p *revocationAuditPersister) Load() ([]byte, error) { return p.base.Load() }
func (p *revocationAuditPersister) Save(b []byte) error {
	if p.fail.Load() && !p.replaceBeforeError {
		return errors.New("private-runtime-location")
	}
	if e := p.base.Save(b); e != nil {
		return e
	}
	if p.fail.Load() {
		return errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
	}
	return nil
}
