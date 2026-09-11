package assetcatalog

import (
	"strings"
	"testing"
)

func ep(tenant, id, addr, source string) Endpoint {
	kind := KindNetwork
	if source == SourceEnrolled {
		kind = KindSteeredDevice
	}
	return Endpoint{ID: id, TenantID: tenant, Alias: id, Address: addr, Kind: kind, Source: source}
}

// ★ The defect this exists for: an asset deleted on the control plane stayed on every Edge, because the bundle
// apply only ever upserted. The CP answered 200 {"status":"deleted"} and the Edge kept it — verified live.
func TestReplaceAuthoredRemovesWhatTheControlPlaneNoLongerSends(t *testing.T) {
	s := NewStore()
	if _, err := s.UpsertEndpoint(ep("t1", "certpin-ep-1", "pinned.example", SourceManual)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertEndpoint(ep("t1", "keep-1", "kept.example", SourceManual)); err != nil {
		t.Fatal(err)
	}

	removed, err := s.ReplaceAuthored([]Endpoint{ep("t1", "keep-1", "kept.example", SourceManual)}, nil, nil)
	if err != nil {
		t.Fatalf("ReplaceAuthored: %v", err)
	}
	if len(removed) != 1 || removed[0] != "endpoint:certpin-ep-1" {
		t.Fatalf("removed = %v, want exactly the endpoint the CP stopped sending", removed)
	}
	if _, ok := s.GetEndpoint("t1", "certpin-ep-1"); ok {
		t.Error("the endpoint the control plane deleted is still here — this is the whole bug")
	}
	if _, ok := s.GetEndpoint("t1", "keep-1"); !ok {
		t.Error("an endpoint the control plane still authors was removed")
	}
}

// ★ Enrolled-derived endpoints are each Edge's own derivation from the enrolled ledger, not the CP's authored
// catalog. Removing them for being absent from the incoming set would delete a correct local derivation and
// re-add it on the next ledger pass — churn at best, and a device silently missing from policy in between.
func TestReplaceAuthoredKeepsEnrolledDerivedEndpoints(t *testing.T) {
	s := NewStore()
	if _, err := s.UpsertEndpoint(ep("t1", "dev-mac-1", "10.0.0.5", SourceEnrolled)); err != nil {
		t.Fatal(err)
	}
	removed, err := s.ReplaceAuthored(nil, nil, nil)
	if err != nil {
		t.Fatalf("ReplaceAuthored: %v", err)
	}
	if len(removed) != 0 {
		t.Fatalf("removed = %v, want nothing: enrolled-derived endpoints are not the control plane's to delete", removed)
	}
	if _, ok := s.GetEndpoint("t1", "dev-mac-1"); !ok {
		t.Error("an enrolled-derived endpoint was deleted by a bundle that never carried it")
	}
}

// The pair must be exact: whatever AuthoredSnapshot exports, ReplaceAuthored must take back unchanged. If they
// drift, every pull deletes something the other side thought it had sent.
func TestReplaceAuthoredIsTheInverseOfAuthoredSnapshot(t *testing.T) {
	src := NewStore()
	for _, e := range []Endpoint{
		ep("t1", "a", "a.example", SourceManual),
		ep("t2", "b", "b.example", SourceManual),
	} {
		if _, err := src.UpsertEndpoint(e); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := src.UpsertGroup(Group{ID: "g1", TenantID: "t1", Alias: "g"}); err != nil {
		t.Fatal(err)
	}
	endpoints, groups, services := src.AuthoredSnapshot()

	dst := NewStore()
	// Something the destination has and the source does not: it must go.
	if _, err := dst.UpsertEndpoint(ep("t1", "stale", "stale.example", SourceManual)); err != nil {
		t.Fatal(err)
	}
	removed, err := dst.ReplaceAuthored(endpoints, groups, services)
	if err != nil {
		t.Fatalf("ReplaceAuthored: %v", err)
	}
	if len(removed) != 1 || !strings.Contains(removed[0], "stale") {
		t.Fatalf("removed = %v, want only the stale entry", removed)
	}
	gotE, gotG, gotS := dst.AuthoredSnapshot()
	if len(gotE) != len(endpoints) || len(gotG) != len(groups) || len(gotS) != len(services) {
		t.Fatalf("after replace: %d/%d/%d, want %d/%d/%d — the pair is not exact",
			len(gotE), len(gotG), len(gotS), len(endpoints), len(groups), len(services))
	}
	// Applying the same set twice must remove nothing: a steady state that keeps deleting churns the fleet.
	again, err := dst.ReplaceAuthored(endpoints, groups, services)
	if err != nil {
		t.Fatal(err)
	}
	if len(again) != 0 {
		t.Errorf("a second identical apply removed %v — the apply is not idempotent", again)
	}
}
