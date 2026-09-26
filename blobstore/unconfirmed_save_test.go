package blobstore

import (
	"errors"
	"testing"
)

func TestUnconfirmedSaveKeepsOnlyRealFailures(t *testing.T) {
	other := errors.New("disk full")
	for _, c := range []struct {
		in   error
		fail bool
	}{
		{nil, false},
		{ErrSavedWithoutAtomicity, false}, // written in place: a confirmed save
		{ErrDurabilityUnconfirmed, true},
		{savedDurabilityWarning{}, true}, // answers Is() to both: unconfirmed wins
		{other, true},
	} {
		got := UnconfirmedSave(c.in)
		if (got != nil) != c.fail {
			t.Fatalf("UnconfirmedSave(%v) = %v", c.in, got)
		}
		if c.fail && !errors.Is(got, c.in) {
			t.Fatalf("failure identity lost for %v", c.in)
		}
	}
}
