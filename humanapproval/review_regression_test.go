package humanapproval

import (
	"encoding/json"
	"github.com/lantern-networks/dsse-core/model"
	"testing"
)

func TestLegacyUnattributedApprovalSkipped(t *testing.T) {
	raw, _ := json.Marshal(map[string]model.HumanApprovalEvent{"old": {ID: "old"}, "good": {ID: "good", TenantID: "tenant", ApprovalResult: "approved"}})
	s := NewStore(0)
	if err := s.SetPersister(loadedApprovalPersister{data: raw}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.GetForTenant("tenant", "good"); !ok {
		t.Fatal("valid approval dropped")
	}
	if _, ok := s.Get("old"); ok {
		t.Fatal("unattributed approval accepted")
	}
}
func TestAuthorizationTenantCollision(t *testing.T) {
	s := NewStore(0)
	for _, tenant := range []string{"a", "b"} {
		if _, e := s.Upsert(model.HumanApprovalEvent{ID: "same", TenantID: tenant, ApprovalResult: "approved"}); e != nil {
			t.Fatal(e)
		}
	}
	for _, tenant := range []string{"a", "b"} {
		v, ok := s.GetForAuthorization(tenant, "same")
		if !ok || v.TenantID != tenant {
			t.Fatal("tenant collision")
		}
	}
}
