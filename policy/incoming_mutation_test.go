package policy

import (
	"github.com/lantern-networks/dsse-core/model"
	"sync"
	"testing"
)

func TestConcurrentIncomingMutationPreservesIndependentFields(t *testing.T) {
	s := NewStore(nil)
	ex := model.LegacyException{ID: "same", TenantID: "a", Port: 22, Status: "disabled"}
	if err := s.UpsertLegacyExceptionConfirmed("a", ex); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, change := range []func(*model.LegacyException){func(x *model.LegacyException) { x.BusinessOwner = "new owner" }, func(x *model.LegacyException) { x.ExpiresAt = "2027-01-01T00:00:00Z" }} {
		wg.Add(1)
		go func(change func(*model.LegacyException)) {
			defer wg.Done()
			_, err := s.MutateLegacyExceptionConfirmed("a", "same", func(x model.LegacyException) (model.LegacyException, error) { change(&x); return x, nil })
			if err != nil {
				t.Error(err)
			}
		}(change)
	}
	wg.Wait()
	got := s.LegacyExceptionsFor("a")[0]
	if got.BusinessOwner != "new owner" || got.ExpiresAt == "" || got.Port != 22 || got.Status != "disabled" {
		t.Fatalf("lost update: %+v", got)
	}
}
