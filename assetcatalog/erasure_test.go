package assetcatalog

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func TestTenantErasurePreservesPeersAndRetries(t *testing.T) {
	s, p := seedCatalogTransaction(t)
	s.SetBuiltInCatalog([]Endpoint{{ID: "built-in-endpoint"}}, []Group{{ID: "built-in-group"}})
	s.SetBuiltInServices([]Service{{ID: "built-in-service"}})
	builtIns, err := json.Marshal([]any{s.builtInEndpoints, s.builtInGroups, s.builtInServices})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertGroup(Group{ID: "peer", TenantID: "peer", Alias: "peer"}); err != nil {
		t.Fatal(err)
	}
	// Include a retired inventory alias which has no remaining live endpoint.
	s.enrolledAliases["t"] = map[string]string{"enrolled-retired": "retired"}
	s.aliases["t"]["retired"] = "enrolled-retired"
	if err := s.persistLocked(); err != nil {
		t.Fatal(err)
	}
	before := string(p.data)
	live := catalogState(t, s)
	p.fail = true
	if _, err := s.RemoveTenantContext(context.Background(), "t"); !errors.Is(err, ErrPersistence) {
		t.Fatal(err)
	}
	if string(p.data) != before || catalogState(t, s) != live {
		t.Fatal("failed erasure published state")
	}
	p.fail = false
	n, err := s.RemoveTenantContext(context.Background(), "t")
	if err != nil || n != 8 {
		t.Fatalf("%d %v", n, err)
	}
	var prior, after persistedCatalog
	json.Unmarshal([]byte(before), &prior)
	json.Unmarshal(p.data, &after)
	if countTenantCatalogRecords(after, "t") != 0 {
		t.Fatal("target records survived")
	}
	remainingBuiltIns, err := json.Marshal([]any{s.builtInEndpoints, s.builtInGroups, s.builtInServices})
	if err != nil || string(remainingBuiltIns) != string(builtIns) {
		t.Fatal("built-ins changed", err)
	}
	if !reflect.DeepEqual(prior.Groups["peer"], after.Groups["peer"]) || !reflect.DeepEqual(prior.Aliases["peer"], after.Aliases["peer"]) {
		t.Fatal("peer changed")
	}
	fresh := NewStore()
	if err := fresh.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if n, err := fresh.CountTenantRecords("t"); err != nil || n != 0 {
		t.Fatal(n, err)
	}
	if n, err := fresh.RemoveTenantContext(context.Background(), "t"); err != nil || n != 0 {
		t.Fatal("retry", n, err)
	}
}
