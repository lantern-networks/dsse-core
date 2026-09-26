package steerexclusion

import (
	"reflect"
	"testing"
	"time"
)

func TestReplaceTenantCheckedValidatesBeforeRemoving(t *testing.T) {
	base := policyForSave("new", "own", "com.example.new")
	base.Status = "active"
	for _, name := range []string{"nil", "duplicate", "foreign", "blank-id", "scope", "tenant-scope-id", "device-scope-id", "status", "apps", "duplicate-app", "blank-app"} {
		t.Run(name, func(t *testing.T) {
			s := NewStore()
			if _, err := s.Upsert(policyForSave("keep", "own", "com.example.keep"), time.Now()); err != nil {
				t.Fatal(err)
			}
			before := s.List("own")
			p := clonePolicy(base)
			set := []Policy{p}
			switch name {
			case "nil":
				set = nil
			case "duplicate":
				set = append(set, p)
			case "foreign":
				set[0].TenantID = "other"
			case "blank-id":
				set[0].ID = " "
			case "scope":
				set[0].ScopeType = "bad"
			case "tenant-scope-id":
				set[0].ScopeID = "unexpected"
			case "device-scope-id":
				set[0].ScopeType = "device"
			case "status":
				set[0].Status = ""
			case "apps":
				set[0].ExcludedAppSigningIDs = nil
			case "duplicate-app":
				set[0].ExcludedAppSigningIDs = []string{"a", "a"}
			case "blank-app":
				set[0].ExcludedAppSigningIDs = []string{" "}
			}
			if err := s.ReplaceTenantChecked("own", set); err == nil {
				t.Fatal("invalid replacement accepted")
			}
			if !reflect.DeepEqual(before, s.List("own")) {
				t.Fatal("invalid set removed prior policies")
			}
		})
	}
}
func TestReplaceTenantCheckedCopiesAndClearsExplicitly(t *testing.T) {
	s := NewStore()
	p := policyForSave("new", "own", "com.example.new")
	p.Status = "active"
	if err := s.ReplaceTenantChecked("own", []Policy{p}); err != nil {
		t.Fatal(err)
	}
	p.ExcludedAppSigningIDs[0] = "modified"
	if got := s.ResolveForDevice("own", "", ""); !reflect.DeepEqual(got, []string{"com.example.new"}) {
		t.Fatal("aliased input", got)
	}
	if err := s.ReplaceTenantChecked("own", []Policy{}); err != nil {
		t.Fatal(err)
	}
	if len(s.List("own")) != 0 {
		t.Fatal("explicit empty did not clear")
	}
}

func TestAuthoredPolicySatisfiesSnapshotIdentityContract(t *testing.T) {
	for _, which := range []string{"id", "tenant"} {
		t.Run(which, func(t *testing.T) {
			s := NewStore()
			p := policyForSave("id", "own", "com.example.app")
			if which == "id" {
				p.ID = " id "
			} else {
				p.TenantID = " own "
			}
			if _, err := s.Upsert(p, time.Now()); err == nil {
				t.Fatal("writer accepted an identity readers reject")
			}
			if len(s.List("own")) != 0 || len(s.List(" own ")) != 0 {
				t.Fatal("invalid write published")
			}
		})
	}
	s := NewStore()
	p := policyForSave(" ", "own", "com.example.app")
	got, err := s.Upsert(p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTenantPolicies("own", []Policy{got}); err != nil {
		t.Fatal("generated identity rejected", err)
	}
}
