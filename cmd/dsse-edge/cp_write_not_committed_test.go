package main

import (
	"context"
	"errors"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// A refusal returned by the edit callback is shown to administrators (API error
// bodies), written into audit reasons and reported on a health surface. The
// not-committed classification must survive for errors.Is, and must not change
// the text those readers see.
func TestWriteNotCommittedKeepsCallerText(t *testing.T) {
	refusal := errors.New("that CA already identifies tenant \"a\"")
	err := error(writeNotCommittedError{refusal})
	if err.Error() != refusal.Error() {
		t.Fatalf("classification leaked into text: %q", err.Error())
	}
	if !errors.Is(err, blobstore.ErrWriteNotCommitted) || !errors.Is(err, refusal) {
		t.Fatal("classification or the original error is no longer matchable")
	}
}

func TestPostgresBlobCallbackRefusalTextIsUnchanged(t *testing.T) {
	d, _, _, _ := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	p.key = "refusal_text"
	refusal := errors.New("invalid fingerprint dataset: supply at least one value")
	err := p.UpdateContext(captureCPWriteLease(context.Background()), func([]byte) ([]byte, error) { return nil, refusal })
	if err == nil || err.Error() != refusal.Error() {
		t.Fatalf("callback refusal text changed: %v", err)
	}
	if !errors.Is(err, blobstore.ErrWriteNotCommitted) || !errors.Is(err, refusal) {
		t.Fatalf("refusal lost its classification: %v", err)
	}
}
