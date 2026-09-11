package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/connector"
)

// The unified rule API on the product edge stores east-west/egress rules with the two-axis action and
// enforces the east-west inbound constraint (Windows-only) using receiver platforms resolved from the
// asset catalog — all through the real /admin/rules + /admin/assets handlers.
func TestAdminRulesAdminInboundValidation(t *testing.T) {
	handler := newServerWithConfig(serverConfig{
		Evaluator: testEvaluator(),
		Registry:  connector.NewRegistry(),
		AdminAuth: newAdminAuthStore(),
	})

	mkEndpoint := func(body string) string {
		t.Helper()
		rec := doAdmin(t, handler, http.MethodPost, "/admin/assets/endpoints", body)
		if rec.Code != http.StatusOK {
			t.Fatalf("create endpoint %s = %d, body=%s", body, rec.Code, rec.Body.String())
		}
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("decode endpoint: %v", err)
		}
		return m["id"].(string)
	}
	macID := mkEndpoint(`{"alias":"alice-mac","kind":"steered_device","platform":"macos","steered":true}`)
	winID := mkEndpoint(`{"alias":"bob-win","kind":"steered_device","platform":"windows","steered":true}`)
	dbID := mkEndpoint(`{"alias":"prod-db","kind":"network","address":"10.0.0.5"}`)

	// Egress allow+bypass: stored, no direction.
	if rec := doAdmin(t, handler, http.MethodPost, "/admin/rules", `{"plane":"egress","priority":10,"source":["`+macID+`"],"destination":["`+dbID+`"],"action":{"access":"allow","inspection":"bypass"}}`); rec.Code != http.StatusOK {
		t.Fatalf("egress rule = %d, body=%s", rec.Code, rec.Body.String())
	}

	// East-west outbound authenticate: stored.
	if rec := doAdmin(t, handler, http.MethodPost, "/admin/rules", `{"plane":"east_west","direction":"outbound","priority":100,"source":["`+macID+`"],"destination":["`+dbID+`"],"action":{"access":"authenticate"}}`); rec.Code != http.StatusOK {
		t.Fatalf("east-west outbound rule = %d, body=%s", rec.Code, rec.Body.String())
	}

	// East-west inbound, macOS-only receiver: hard error (inbound is Windows-only).
	if rec := doAdmin(t, handler, http.MethodPost, "/admin/rules", `{"plane":"east_west","direction":"inbound","priority":50,"source":["`+dbID+`"],"destination":["`+macID+`"],"action":{"access":"allow"}}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("inbound macOS-only = %d, want 400, body=%s", rec.Code, rec.Body.String())
	}

	// East-west inbound, mixed receivers: saved with a warning naming the macOS receiver.
	rec := doAdmin(t, handler, http.MethodPost, "/admin/rules", `{"plane":"east_west","direction":"inbound","priority":60,"source":["`+dbID+`"],"destination":["`+winID+`","`+macID+`"],"action":{"access":"allow"}}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("mixed inbound = %d, body=%s", rec.Code, rec.Body.String())
	}
	var stored map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &stored); err != nil {
		t.Fatalf("decode mixed inbound: %v", err)
	}
	if warn, _ := stored["warning"].(string); !strings.Contains(warn, "alice-mac") {
		t.Fatalf("mixed inbound warning = %q, want it to name alice-mac", stored["warning"])
	}

	// List filters by plane (egress excluded from the east-west list).
	listRec := doAdmin(t, handler, http.MethodGet, "/admin/rules?plane=east_west", "")
	if listRec.Code != http.StatusOK {
		t.Fatalf("list east-west = %d, body=%s", listRec.Code, listRec.Body.String())
	}
	var ewRules []map[string]any
	if err := json.Unmarshal(listRec.Body.Bytes(), &ewRules); err != nil {
		t.Fatalf("decode east-west list: %v", err)
	}
	if len(ewRules) != 2 {
		t.Fatalf("east-west rules = %d, want 2", len(ewRules))
	}
}
