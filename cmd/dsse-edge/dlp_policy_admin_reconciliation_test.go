package main

import (
	"errors"
	"github.com/lantern-networks/dsse-core/model"
	"net/http"
	"strings"
	"testing"
)

func policyLibraryHandler(s *dlpPolicyObjectStore, c *dlpClassifierRuntimeStore, f *dlpFingerprintRuntimeStore) http.Handler {
	m := http.NewServeMux()
	registerDLPRoutes(m, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, testEvaluator(), nil, nil, nil, s, f, c, nil, nil, "")
	return m
}
func policyLibraryFixture(tenant, id string) model.DLPPolicyObject {
	return model.DLPPolicyObject{TenantID: tenant, ID: id, Name: "Protect", Identifiers: []string{"credit_card"}, OnMatch: "block", Status: "active"}
}
func TestDLPPolicyAdminFailedSave(t *testing.T) {
	for _, op := range []string{"create", "edit", "disable", "delete"} {
		t.Run(op, func(t *testing.T) {
			p := &allowlistSaveFixture{}
			s := newDLPPolicyObjectStore()
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if op != "create" {
				s.Upsert(policyLibraryFixture("own", "protect"))
				if err := s.PersistIfDirty(); err != nil {
					t.Fatal(err)
				}
			}
			p.err = errors.New("private store failure")
			method, path, body := "POST", "/admin/dlp-policies", `{"id":"protect","name":"Changed","identifiers":["credit_card"],"on_match":"observe","status":"active"}`
			if op == "disable" {
				body = `{"id":"protect","name":"Protect","identifiers":["credit_card"],"on_match":"block","status":"disabled"}`
			}
			if op == "delete" {
				method = "DELETE"
				path += "?id=protect"
				body = ""
			}
			w := libraryRequest(policyLibraryHandler(s, nil, nil), method, path, body, "own")
			if w.Code != 503 || strings.Contains(w.Body.String(), "private store failure") {
				t.Errorf("unconfirmed save returned %d %s", w.Code, w.Body)
			}
			got, exists := s.Get("own", "protect")
			if op == "create" && exists || op != "create" && (!exists || got.Name != "Protect" || got.Status != "active" || got.OnMatch != "block") {
				t.Error("failed save changed live policy")
			}
		})
	}
}
