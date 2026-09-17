package main

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/configversion"
	"github.com/lantern-networks/dsse-core/steerexclusion"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSteerExclusionEditorPinnedContext(t *testing.T) {
	for _, method := range []string{"POST", "DELETE"} {
		for _, expected := range []string{"", "tenant_lab_001", "tenant_other"} {
			t.Run(method+"/"+expected, func(t *testing.T) {
				h, s, _, path, outbox, versions := steerMutationFullFixture(t)
				before, _ := os.ReadFile(path)
				foreign := s.List("tenant_other")
				url := "/admin/steer-exclusions"
				if method == "DELETE" {
					url += "/owned"
				}
				if expected != "" {
					url += "?expected_tenant_id=" + expected
				}
				r := steerMutationRequest(h, method, url, map[string]any{"id": "owned", "scope_type": "device_group", "scope_id": " QA ", "excluded_app_signing_ids": []string{"two", "one", "one"}, "note": "context test"})
				want := 200
				if expected == "tenant_other" {
					want = 409
				}
				if r.Code != want {
					t.Fatalf("status=%d body=%s", r.Code, r.Body)
				}
				if !reflect.DeepEqual(foreign, s.List("tenant_other")) {
					t.Fatal("foreign policy changed")
				}
				history, err := versions.List(context.Background(), "tenant_lab_001", configversion.ResourceSteerExclusion, "owned")
				if err != nil {
					t.Fatal(err)
				}
				audits := inventoryMutationAudits(t, filepath.Dir(filepath.Dir(path)))
				if want == 409 {
					after, _ := os.ReadFile(path)
					if !bytes.Equal(before, after) || len(history) != 0 || len(outbox.insertedAudits) != 0 {
						t.Fatal("rejected context changed durable state, history or domain audit")
					}
					if len(audits) != 1 || audits[0]["result"] != "error" || audits[0]["actor_user_id"] != "steering-admin" {
						t.Fatal("missing rejection audit", audits)
					}
				} else {
					if len(history) != 1 || len(outbox.insertedAudits) != 1 || len(audits) != 2 {
						t.Fatal("missing mutation records", history, audits)
					}
					if method == "DELETE" {
						var body map[string]any
						if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
							t.Fatal(err)
						}
						if body["deleted"] != true || body["id"] != "owned" || body["tenant_id"] != "tenant_lab_001" {
							t.Fatal("delete ACK", body)
						}
					} else {
						var body steerexclusion.Policy
						if err := json.Unmarshal(r.Body.Bytes(), &body); err != nil {
							t.Fatal(err)
						}
						if body.TenantID != "tenant_lab_001" || body.ID != "owned" || body.ScopeID != "QA" || !reflect.DeepEqual(body.ExcludedAppSigningIDs, []string{"one", "two"}) {
							t.Fatal("save ACK", body)
						}
					}
				}
			})
		}
	}
}

func TestSteerExclusionEditorStableIDRetry(t *testing.T) {
	h, s, _, path, outbox, versions := steerMutationFullFixture(t)
	body := map[string]any{"id": "sx_00112233445566778899aabbccddeeff", "scope_type": "tenant", "excluded_app_signing_ids": []string{"com.example.retry"}, "note": "same form"}
	var first steerexclusion.Policy
	for i := 0; i < 2; i++ {
		r := steerMutationRequest(h, "POST", "/admin/steer-exclusions?expected_tenant_id=tenant_lab_001", body)
		if r.Code != 200 {
			t.Fatal(r.Code, r.Body)
		}
		var saved steerexclusion.Policy
		if err := json.Unmarshal(r.Body.Bytes(), &saved); err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = saved
		} else if saved.ID != first.ID || saved.CreatedAt != first.CreatedAt {
			t.Fatal("retry created another identity")
		}
	}
	if len(s.List("tenant_lab_001")) != 2 {
		t.Fatal("retry duplicated policy")
	}
	restored, err := steerexclusion.NewStoreWithPersistence(steerexclusion.NewFilePersistence(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.List("tenant_lab_001")) != 2 {
		t.Fatal("duplicate on restart")
	}
	history, err := versions.List(context.Background(), "tenant_lab_001", configversion.ResourceSteerExclusion, first.ID)
	if err != nil || len(history) != 2 || len(outbox.insertedAudits) != 2 {
		t.Fatal("both upserts must remain auditable", history, err)
	}
	if len(inventoryMutationAudits(t, filepath.Dir(filepath.Dir(path)))) != 4 {
		t.Fatal("missing original audits")
	}
}
