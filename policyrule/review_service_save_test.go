package policyrule

import (
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"testing"
)

type reviewServiceResolver struct{}

func (reviewServiceResolver) SourceDeviceTokens(string, []string) []string { return []string{"device"} }
func (reviewServiceResolver) EndpointAddresses(string, []string) []string {
	return []string{"example.test"}
}
func (reviewServiceResolver) ServicePorts(string, string) []int                     { return nil }
func (reviewServiceResolver) ServiceTransportPorts(string, string) map[string][]int { return nil }
func TestUnresolvedServicePreservesRestrictiveEgress(t *testing.T) {
	for _, access := range []string{AccessAllow, AccessDeny, AccessAuthenticate} {
		r := Rule{ID: "r", TenantID: "t", Plane: PlaneEgress, Status: StatusActive, Source: []string{"device"}, Destination: []string{"target"}, ServiceID: "deleted", Action: Action{Access: access}}
		rules := CompileEgressPolicies("t", []Rule{r}, reviewServiceResolver{})
		if len(rules) != 2 {
			t.Fatalf("%s: policies=%d", access, len(rules))
		}
		for _, p := range rules {
			_, protocol := p.Conditions["protocol"]
			if access == AccessAllow && !protocol {
				t.Fatal("unresolved allow widened")
			}
			if access != AccessAllow && protocol {
				t.Fatalf("%s became a nonmatching rule", access)
			}
			if _, ok := p.Conditions["device_id"]; !ok {
				t.Fatal("source restriction lost")
			}
		}
	}
}

type reviewSaveFixture struct {
	data []byte
	err  error
}

func (p *reviewSaveFixture) Load() ([]byte, error) { return p.data, nil }
func (p *reviewSaveFixture) Save(b []byte) error {
	if p.err == nil || errors.Is(p.err, blobstore.ErrSavedWithoutAtomicity) || errors.Is(p.err, blobstore.ErrDurabilityUnconfirmed) {
		p.data = append([]byte(nil), b...)
	}
	return p.err
}
func TestRuleSaveWarningKeepsReloadAndLiveConsistent(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		wantErr bool
	}{{"confirmed fallback", blobstore.ErrSavedWithoutAtomicity, false}, {"unconfirmed replacement", blobstore.ErrDurabilityUnconfirmed, true}} {
		t.Run(tc.name, func(t *testing.T) {
			p := &reviewSaveFixture{}
			s := NewStore()
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			r := Rule{ID: "r", TenantID: "t", Plane: PlaneEgress, Status: StatusActive, Source: []string{"*"}, Destination: []string{"*"}, Action: Action{Access: AccessDeny}}
			if _, err := s.Upsert(r); err != nil {
				t.Fatal(err)
			}
			p.err = tc.err
			r.Name = "changed"
			before := s.ConfigGeneration()
			_, err := s.Upsert(r)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error=%v", err)
			}
			got, _ := s.Get("t", "r")
			if got.Name != "changed" || s.ConfigGeneration() <= before {
				t.Fatal("applied replacement not reflected live")
			}
			fresh := NewStore()
			if err := fresh.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			got, _ = fresh.Get("t", "r")
			if got.Name != "changed" {
				t.Fatal("replacement not saved")
			}
			_, err = s.Delete("t", "r")
			if (err != nil) != tc.wantErr {
				t.Fatalf("delete error=%v", err)
			}
			if _, ok := s.Get("t", "r"); ok {
				t.Fatal("replaced deletion rolled back live")
			}
		})
	}
}
