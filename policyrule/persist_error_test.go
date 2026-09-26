package policyrule

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

type failingPersister struct {
	data  []byte
	fail  bool
	saves int
}

func (p *failingPersister) Load() ([]byte, error) { return append([]byte(nil), p.data...), nil }
func (p *failingPersister) Save(b []byte) error {
	p.saves++
	if p.fail {
		return fmt.Errorf("private disk failure")
	}
	p.data = append([]byte(nil), b...)
	return nil
}
func TestRejectedRuleChangesKeepSavedStateGenerationAndRetry(t *testing.T) {
	for _, operation := range []string{"create", "edit", "disable", "delete", "replace", "clear", "tenant_delete"} {
		t.Run(operation, func(t *testing.T) {
			s := NewStore()
			p := &failingPersister{}
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			initial := ewRule()
			initial.ID = "retained"
			initial.Name = "before"
			saved, err := s.Upsert(initial)
			if err != nil {
				t.Fatal(err)
			}
			before, gen, seq, disk := s.Snapshot(), s.ConfigGeneration(), s.seq, string(p.data)
			change := func() error {
				r := saved
				switch operation {
				case "create":
					r.ID = ""
					r.Name = "new"
					_, e := s.Upsert(r)
					return e
				case "edit":
					r.Name = "after"
					_, e := s.Upsert(r)
					return e
				case "disable":
					r.Status = StatusDisabled
					_, e := s.Upsert(r)
					return e
				case "delete":
					_, e := s.Delete(r.TenantID, r.ID)
					return e
				case "replace":
					r.Name = "replacement"
					return s.ReplaceAll([]Rule{r})
				case "clear":
					return s.ReplaceAll(nil)
				default:
					_, e := s.RemoveTenantChecked(r.TenantID)
					return e
				}
			}
			p.fail = true
			if err := change(); !errors.Is(err, ErrPersistence) {
				t.Fatal("rejected save was not reported", err)
			}
			if !reflect.DeepEqual(before, s.Snapshot()) || gen != s.ConfigGeneration() || seq != s.seq || disk != string(p.data) {
				t.Fatal("rejected mutation changed committed state")
			}
			p.fail = false
			foreign := ewRule()
			foreign.TenantID = "other"
			foreign.ID = "unrelated"
			if _, e := s.Upsert(foreign); e != nil {
				t.Fatal(e)
			}
			restart := NewStore()
			if e := restart.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			if got := restart.List(saved.TenantID, ""); !reflect.DeepEqual(got, before) {
				t.Fatal("unrelated save persisted rejected change")
			}
			if e := change(); e != nil {
				t.Fatal("retry failed", e)
			}
			restart = NewStore()
			if e := restart.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(restart.Snapshot(), s.Snapshot()) {
				t.Fatal("successful retry not durable")
			}
		})
	}
}
func TestRuleSnapshotsDoNotAliasPolicyInputs(t *testing.T) {
	s := NewStore()
	r := ewRule()
	r.Action.RequiredAMR = []string{"mfa"}
	r.AllowedToolIDs = []string{"tool"}
	r.Action.DLP = &model.DLPSpec{Identifiers: []string{"test"}, OnMatch: "observe"}
	saved, e := s.Upsert(r)
	if e != nil {
		t.Fatal(e)
	}
	r.Source[0] = "mutated"
	saved.Action.RequiredAMR[0] = "mutated"
	for _, item := range []Rule{s.List(saved.TenantID, "")[0], s.Snapshot()[0]} {
		item.Destination[0] = "mutated"
		item.AllowedToolIDs[0] = "mutated"
		item.Action.DLP.Identifiers[0] = "mutated"
	}
	got, _ := s.Get(saved.TenantID, saved.ID)
	got.Source[0] = "mutated"
	final, _ := s.Get(saved.TenantID, saved.ID)
	if final.Source[0] == "mutated" || final.Destination[0] == "mutated" || final.AllowedToolIDs[0] != "tool" || final.Action.RequiredAMR[0] != "mfa" || final.Action.DLP.Identifiers[0] != "test" {
		t.Fatal("alias changed live policy")
	}
}
func TestDistributedRuleIDsDoNotOverwriteOrDuplicate(t *testing.T) {
	s := NewStore()
	r := ewRule()
	r.ID = "rule-1"
	if e := s.ReplaceAll([]Rule{r}); e != nil {
		t.Fatal(e)
	}
	before := s.Snapshot()
	if e := s.ReplaceAll([]Rule{r, r}); e == nil || !reflect.DeepEqual(before, s.Snapshot()) {
		t.Fatal("duplicate distributed ID accepted")
	}
	r.ID = ""
	created, e := s.Upsert(r)
	if e != nil || created.ID == "rule-1" || len(s.Snapshot()) != 2 {
		t.Fatal("generated ID replaced distributed rule", e)
	}
}
func TestBadRuleLoadKeepsOriginalWriter(t *testing.T) {
	s := NewStore()
	p := &failingPersister{}
	s.SetPersister(p)
	s.Upsert(ewRule())
	before := s.Snapshot()
	bad := &failingPersister{data: []byte("{")}
	if e := s.SetPersister(bad); e == nil || !reflect.DeepEqual(before, s.Snapshot()) {
		t.Fatal("failed load changed live")
	}
	writes := p.saves
	s.Upsert(ewRule())
	if p.saves != writes+1 || bad.saves != 0 {
		t.Fatal("failed load replaced writer")
	}
}
