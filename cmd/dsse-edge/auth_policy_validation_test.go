package main

import (
	"github.com/lantern-networks/dsse-core/idpregistry"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policyrule"
	"strings"
	"testing"
)

func TestRequestBoundPolicyCannotActivateOnWeb(t *testing.T) {
	policy := model.Policy{Status: "active", Action: model.PolicyAction{Decision: "require_reauthentication"}, Metadata: map[string]any{"max_age_seconds": float64(0)}, Conditions: map[string]any{"destination_port": float64(443)}}
	if err := validateRequestBoundPolicyTransport(policy); err == nil {
		t.Fatal("Web-capable request-bound policy activated")
	}
	policy.Conditions = map[string]any{"service_family": "https"}
	if err := validateRequestBoundPolicyTransport(policy); err == nil {
		t.Fatal("HTTPS request-bound policy activated")
	}
	policy.Conditions = map[string]any{"service_family": "ssh"}
	if err := validateRequestBoundPolicyTransport(policy); err != nil {
		t.Fatal("held native flow rejected:", err)
	}
	policy.Status = "draft"
	policy.Conditions = map[string]any{"service_family": "https"}
	if err := validateRequestBoundPolicyTransport(policy); err != nil {
		t.Fatal("inactive draft rejected:", err)
	}
}

func TestAuthoredRuleRejectsUnsupportedEntraRequirement(t *testing.T) {
	r := idpregistry.NewStore()
	_, err := r.Upsert(idpregistry.Connection{IdPID: "entra", TenantID: "tenant", Type: "entra", Issuer: "https://idp.example", AuthorizationEndpoint: "https://idp.example/auth", ClientID: "client", VerifiedDomains: []string{"example"}})
	if err != nil {
		t.Fatal(err)
	}
	rule := policyrule.Rule{TenantID: "tenant", Status: policyrule.StatusActive, Action: policyrule.Action{Access: policyrule.AccessAuthenticate, RequiredIdPID: "entra", MinACR: "phishing_resistant"}}
	if validateAuthoredRuleProvider(rule, r) == nil {
		t.Fatal("unsupported Entra context saved")
	}
	rule.Action.MinACR = "c3"
	if err := validateAuthoredRuleProvider(rule, r); err != nil {
		t.Fatal(err)
	}
	rule.TenantID = "other"
	if validateAuthoredRuleProvider(rule, r) == nil {
		t.Fatal("another tenant provider accepted")
	}
	rule.Status = policyrule.StatusDisabled
	if err := validateAuthoredRuleProvider(rule, r); err != nil {
		t.Fatal("disabled migration draft rejected")
	}
}

func TestAuthoredZeroCannotBypassTransportOrProviderValidation(t *testing.T) {
	registry := idpregistry.NewStore()
	if _, err := registry.Upsert(idpregistry.Connection{IdPID: "google", TenantID: "t", Type: "google", Issuer: "https://accounts.google.com", AuthorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth", ClientID: "test", VerifiedDomains: []string{"example.com"}}); err != nil {
		t.Fatal(err)
	}
	zero := 0
	r := policyrule.Rule{TenantID: "t", Plane: policyrule.PlaneEastWest, Action: policyrule.Action{Access: policyrule.AccessAuthenticate, RequiredIdPID: "google", MaxAgeSeconds: &zero}}
	if err := validateAuthoredRuleProvider(r, registry); err == nil {
		t.Fatal("Google fresh-auth capability requirement disappeared")
	}
	for _, plane := range []string{policyrule.PlaneEgress, " EGRESS "} {
		r.Plane = plane
		if err := validateAuthoredRuleProvider(r, registry); err == nil || !strings.Contains(err.Error(), "outbound Connector Access") {
			t.Fatalf("Web-capable rule accepted: %v", err)
		}
	}
	r.Plane, r.Direction = policyrule.PlaneEastWest, policyrule.DirectionInbound
	if err := validateAuthoredRuleProvider(r, registry); err == nil || !strings.Contains(err.Error(), "outbound Connector Access") {
		t.Fatalf("inbound rule accepted: %v", err)
	}
	r.Status = policyrule.StatusDisabled
	if err := validateAuthoredRuleProvider(r, registry); err != nil {
		t.Fatalf("disabled repair draft rejected: %v", err)
	}
}
