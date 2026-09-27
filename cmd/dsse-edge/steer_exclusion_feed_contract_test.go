package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/lantern-networks/dsse-core/steerexclusion"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

func validSteerFeed() map[string]any {
	return map[string]any{"schema_version": "admin_steer_exclusions.v1", "tenant_id": "own", "steer_exclusions": []any{map[string]any{"id": "new", "tenant_id": "own", "scope_type": "device", "scope_id": "target", "excluded_app_signing_ids": []string{"com.example.new"}, "status": "active"}}}
}
func TestSteerExclusionFeedRejectsIncompleteOrForeignData(t *testing.T) {
	for _, name := range []string{"null", "empty-object", "missing-array", "null-array", "object-array", "wrong-schema", "wrong-tenant", "foreign-row", "duplicate-id", "null-row", "empty-id", "bad-scope", "missing-scope-id", "tenant-scope-id", "empty-apps", "null-apps", "blank-app", "unknown-status", "blank-source-tenant", "over-limit", "read-error"} {
		t.Run(name, func(t *testing.T) {
			feed := validSteerFeed()
			row := feed["steer_exclusions"].([]any)[0].(map[string]any)
			var payload any = feed
			sourceTenant := "own"
			switch name {
			case "null":
				payload = nil
			case "empty-object":
				payload = map[string]any{}
			case "missing-array":
				delete(feed, "steer_exclusions")
			case "null-array":
				feed["steer_exclusions"] = nil
			case "object-array":
				feed["steer_exclusions"] = map[string]any{}
			case "wrong-schema":
				feed["schema_version"] = "unknown"
			case "wrong-tenant":
				feed["tenant_id"] = "other"
			case "foreign-row":
				row["tenant_id"] = "other"
			case "duplicate-id":
				feed["steer_exclusions"] = []any{row, row}
			case "null-row":
				feed["steer_exclusions"] = []any{nil}
			case "empty-id":
				row["id"] = ""
			case "bad-scope":
				row["scope_type"] = "unknown"
			case "missing-scope-id":
				row["scope_id"] = ""
			case "tenant-scope-id":
				row["scope_type"] = "tenant"
			case "empty-apps":
				row["excluded_app_signing_ids"] = []string{}
			case "null-apps":
				row["excluded_app_signing_ids"] = nil
			case "blank-app":
				row["excluded_app_signing_ids"] = []string{" "}
			case "unknown-status":
				row["status"] = "unknown"
			case "blank-source-tenant":
				sourceTenant = ""
			}
			raw, _ := json.Marshal(payload)
			if name == "over-limit" {
				raw = append(raw, []byte(strings.Repeat(" ", 4<<20))...)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if name == "read-error" {
					w.Header().Set("Content-Length", fmt.Sprint(len(raw)+20))
				}
				w.Write(raw)
			}))
			defer server.Close()
			store := steerexclusion.NewStore()
			for _, tenant := range []string{"own", "other"} {
				if _, err := store.Upsert(steerexclusion.Policy{ID: "keep-" + tenant, TenantID: tenant, ScopeType: "tenant", ExcludedAppSigningIDs: []string{"com.example." + tenant}}, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			before := store.List("own")
			foreign := store.List("other")
			src := steerExclusionSource{url: server.URL, token: "synthetic-pull", tenantID: sourceTenant, client: server.Client()}
			n, err := src.fetchAndReplace(context.Background(), store)
			if err == nil || n != 0 {
				t.Fatalf("invalid %s feed accepted: count=%d err=%v own=%+v", name, n, err, store.List("own"))
			}
			if !reflect.DeepEqual(before, store.List("own")) || !reflect.DeepEqual(foreign, store.List("other")) {
				t.Fatal("rejected feed changed cache")
			}
		})
	}
}

func TestSteerExclusionFeedReplacementAndExplicitEmpty(t *testing.T) {
	feed := validSteerFeed()
	raw, _ := json.Marshal(feed)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("expected_tenant_id") != "own" || r.Header.Get("Authorization") != "Bearer synthetic-pull" {
			http.Error(w, "wrong scope", 409)
			return
		}
		w.Write(raw)
	}))
	defer server.Close()
	store := steerexclusion.NewStore()
	for _, tenant := range []string{"own", "other"} {
		if _, err := store.Upsert(steerexclusion.Policy{ID: "keep-" + tenant, TenantID: tenant, ScopeType: "tenant", ExcludedAppSigningIDs: []string{"com.example." + tenant}}, time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	src := steerExclusionSource{url: server.URL, token: "synthetic-pull", tenantID: "own", client: server.Client()}
	n, err := src.fetchAndReplace(context.Background(), store)
	if n != 1 || err != nil {
		t.Fatal(n, err)
	}
	if got := store.ResolveForDevice("own", "target", ""); !reflect.DeepEqual(got, []string{"com.example.new"}) {
		t.Fatal("valid replacement", got)
	}
	row := feed["steer_exclusions"].([]any)[0].(map[string]any)
	row["id"] = "keep-other"
	raw, _ = json.Marshal(feed)
	n, err = src.fetchAndReplace(context.Background(), store)
	if n != 0 || err == nil {
		t.Fatal("cross-tenant ID conflict reported applied", n, err)
	}
	if len(store.List("own")) != 1 || len(store.List("other")) != 1 {
		t.Fatal("rejected conflict lost policy")
	}
	feed["steer_exclusions"] = []any{}
	raw, _ = json.Marshal(feed)
	n, err = src.fetchAndReplace(context.Background(), store)
	if n != 0 || err != nil {
		t.Fatal("explicit empty rejected", n, err)
	}
	if len(store.List("own")) != 0 || len(store.List("other")) != 1 {
		t.Fatal("empty replacement crossed tenant")
	}
}

func TestAdminSteerExclusionReadEnvelopeAndContext(t *testing.T) {
	h, _, _, _ := steerMutationFixture(t)
	for _, path := range []string{"/admin/steer-exclusions", "/admin/steer-exclusions?expected_tenant_id=tenant_lab_001", "/admin/steer-exclusions?tenant_id=tenant_other"} {
		r := steerMutationRequest(h, "GET", path, nil)
		if r.Code != 200 {
			t.Fatal(path, r.Code)
		}
		var body struct {
			Schema   string                  `json:"schema_version"`
			Tenant   string                  `json:"tenant_id"`
			Policies []steerexclusion.Policy `json:"steer_exclusions"`
		}
		if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if body.Schema != steerexclusion.ListSchema || body.Tenant != "tenant_lab_001" || len(body.Policies) != 1 || body.Policies[0].ID != "owned" {
			t.Fatal("scope or envelope", body)
		}
	}
	for _, path := range []string{"/admin/steer-exclusions?expected_tenant_id=tenant_other", "/admin/steer-exclusions/observed?expected_tenant_id=tenant_other"} {
		if r := steerMutationRequest(h, "GET", path, nil); r.Code != 409 {
			t.Fatal("context must fail before store read", path, r.Code, r.Body.String())
		}
	}
}
