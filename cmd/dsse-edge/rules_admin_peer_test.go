package main

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
)

// Exercise the ordinary lifecycle through two CP handlers backed by one real DB.
func TestPostgresRuleAdminLifecycleAndPeerReadback(t *testing.T) {
	db := initialBlobDB(t)
	rp, ap := initialBlob(t, db, "rule_admin_rules"), initialBlob(t, db, "rule_admin_assets")
	handlers := make([]http.Handler, 2)
	for i := range handlers {
		rules, assets := policyrule.NewStore(), assetcatalog.NewStore()
		if err := rules.SetPersister(rp); err != nil {
			t.Fatal(err)
		}
		if err := assets.SetPersister(ap); err != nil {
			t.Fatal(err)
		}
		handlers[i] = newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: newAdminAuthStore(), RuleStore: rules, AssetStore: assets, PolicyStore: policy.NewStore(nil)})
	}
	base := policyrule.Rule{ID: "peer-rule", Name: "Created", Plane: policyrule.PlaneEgress, Source: []string{"*"}, Destination: []string{"*"}, Action: policyrule.Action{Access: policyrule.AccessDeny}}
	for i, status := range []string{"active", "disabled", "active"} {
		base.Status = status
		if i > 0 {
			base.Name = "Edited"
		}
		raw, _ := json.Marshal(base)
		w := doAdmin(t, handlers[i%2], "POST", "/admin/rules", string(raw))
		if w.Code != 200 {
			t.Fatalf("save %s: %d %s", status, w.Code, w.Body)
		}
		w = doAdmin(t, handlers[(i+1)%2], "GET", "/admin/rules", "")
		var got []policyrule.Rule
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != 200 || len(got) != 1 || got[0].Name != base.Name || got[0].Status != status {
			t.Fatalf("peer read: %d %s", w.Code, w.Body)
		}
	}
	w := doAdmin(t, handlers[1], "DELETE", "/admin/rules/peer-rule", "")
	if w.Code != 200 {
		t.Fatalf("delete: %d %s", w.Code, w.Body)
	}
	w = doAdmin(t, handlers[0], "GET", "/admin/rules", "")
	var got []policyrule.Rule
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != 200 || len(got) != 0 {
		t.Fatalf("deleted peer read: %d %s", w.Code, w.Body)
	}
	if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", rp.key); err != nil {
		t.Fatal(err)
	}
	w = doAdmin(t, handlers[0], "GET", "/admin/rules", "")
	if w.Code != 503 {
		t.Fatalf("missing source shown as current list: %d %s", w.Code, w.Body)
	}
}
