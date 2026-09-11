package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// ★★★ "NOT MINE TO SAY" AND "THERE IS NONE" ARE DIFFERENT ANSWERS (2026-08-22, measured on the lab, and the
// third route in this repository to be caught giving the second when it meant the first).
//
//	GET /admin/interception-intermediate
//	  control plane  {"error": "interception is not enabled on this edge"}
//	  edge           {"mode":"own_offline_root","root_common_name":"Lab Tenant Interception Root 2029", ...}
//
// A control plane holds each organization's interception AUTHORITY and serves no traffic. Its answer read as
// "this organization has no interception", which is the opposite of true, and any screen that asked the
// control plane — the plane the Console asks for everything else about an organization's PKI — would have
// shown exactly that.
func TestAControlPlaneSaysInterceptionIsAnEdgesAnswerRatherThanThereIsNone(t *testing.T) {
	// A node that holds authorities and serves nothing: a control plane.
	cp := serverConfig{TenantInterceptionAuthority: &tenantInterceptionAuthority{}}
	rec := httptest.NewRecorder()
	if !interceptionIsNotThisNodesAnswer(rec, cp, "what this organization's traffic is inspected under") {
		t.Fatal("a node that serves no interception must not fall through to an answer about interception")
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("a control plane's refusal is a conflict of planes, not an outage: got %d", rec.Code)
	}
	var body struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unreadable answer: %v", err)
	}
	for _, want := range []string{"EDGE's answer", "/admin/tenant-interception-authority"} {
		if !strings.Contains(body.Error, want) {
			t.Errorf("the refusal must say whose answer it is and where to look; %q is missing from %q", want, body.Error)
		}
	}
	if strings.Contains(body.Error, "not enabled on this edge") {
		t.Errorf("a control plane is not an edge, and must not describe itself as one: %q", body.Error)
	}

	// ★ AND AN EDGE WITH INTERCEPTION GENUINELY OFF STILL SAYS SO. Widening the first case into "nobody may
	// ever answer" would replace one wrong answer with another.
	edgeOff := serverConfig{}
	rec2 := httptest.NewRecorder()
	if !interceptionIsNotThisNodesAnswer(rec2, edgeOff, "what this organization's traffic is inspected under") {
		t.Fatal("interception off must still stop the caller")
	}
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("an Edge with interception off is unavailable, not a plane conflict: got %d", rec2.Code)
	}

	// ★ And a node that DOES serve interception answers for itself — otherwise this guard would have silenced
	// every Edge and the test above would pass for the wrong reason.
	serving := serverConfig{NetworkExtensionLabTLS: &edgeplane.NetworkExtensionLabTLSInterception{}}
	rec3 := httptest.NewRecorder()
	if interceptionIsNotThisNodesAnswer(rec3, serving, "anything") {
		t.Fatal("an Edge that serves interception must answer, not refuse")
	}
	if rec3.Code != http.StatusOK || rec3.Body.Len() != 0 {
		t.Fatalf("the guard wrote to the response on a node that should have answered: %d %q", rec3.Code, rec3.Body.String())
	}
}
