package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/model"
)

// adminRequestBy builds a request that carries a resolved administrator, the way adminEndpoint leaves it for
// the handler. A request built WITHOUT this is what a machine-driven door looks like: nobody is in the context.
func adminRequestBy(principal string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/admin/human-identities", nil)
	return r.WithContext(context.WithValue(r.Context(), adminIdentityContextKey{}, adminIdentity{
		PrincipalID: principal,
		TenantID:    "tenant_northwind",
	}))
}

// A customer reading their own audit must be able to see WHO changed their directory. The rows already said
// what changed and when; the acting administrator was absent, so the customer had to correlate by timestamp
// against a separate admin_config_change row to learn by whom.
//
// Four doors change a customer's identity records, and all four are checked here rather than the one that was
// found: an entry upsert, a directory import, a source policy, and a non-human identity registration.
func TestDirectoryChangeAuditsNameTheActor(t *testing.T) {
	now := time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC)
	const actor = "principal_operator_gate"

	byDoor := map[string]model.AuditLog{
		"human identity upsert": humanIdentityAuditLog(model.HumanIdentity{
			TenantID: "tenant_northwind", ID: "hi_actor_gate", Subject: "someone@northwind.example",
			Status: "active", Source: "scim",
		}, adminRequestBy(actor), testEvaluator(), now),
		"directory import": humanIdentityImportAuditLog(humanidentity.HumanIdentityDirectoryImportResponse{
			TenantID: "tenant_northwind", Source: "scim", ImportRunID: "run_actor_gate",
		}, adminRequestBy(actor), testEvaluator(), now),
		"source policy": humanIdentitySourcePolicyAuditLog(humanidentity.HumanIdentitySourcePolicy{
			TenantID: "tenant_northwind", Source: "scim", ConnectorType: "scim", Enabled: true,
		}, adminRequestBy(actor), testEvaluator(), now),
		"non-human identity registration": nonHumanIdentityAuditLog(model.NonHumanIdentity{
			TenantID: "tenant_northwind", ID: "nhi_actor_gate", Name: "batch job", Status: "active",
		}, adminRequestBy(actor), testEvaluator(), now),
	}

	for door, audit := range byDoor {
		if audit.ActorUserID == nil || *audit.ActorUserID != actor {
			t.Errorf("%s: the audit does not name who made the change: %#v", door, audit.ActorUserID)
		}
	}
}

// THE CONTROL, and it is the same decision seen from the other side: an import the CONNECTOR runs on its
// schedule has no administrator behind it, and it goes through the very same builder as the import an
// administrator starts. The actor is resolved from the request rather than passed in, so that door produces a
// row with the field ABSENT. Naming somebody there — the connector, the node, "system" — would be worse than
// an empty field, because a customer reading the row would believe a person acted.
//
// (An earlier version of this control asserted that nonHumanIdentityAuditLog must not take a request at all,
// on the theory that it is machine-raised. That was wrong: what is non-human there is the SUBJECT of the
// record, not the actor — an administrator registers it through POST /admin/non-human-identities.)
func TestMachineDrivenImportNamesNobody(t *testing.T) {
	now := time.Date(2026, 8, 19, 9, 0, 0, 0, time.UTC)
	result := humanidentity.HumanIdentityDirectoryImportResponse{
		TenantID: "tenant_northwind", Source: "scim", ImportRunID: "run_connector_gate",
	}

	// The connector door: authorised by the connector secret, so no administrator is in the context.
	connector := httptest.NewRequest(http.MethodPost, "/identity-sources/import", nil)
	if audit := humanIdentityImportAuditLog(result, connector, testEvaluator(), now); audit.ActorUserID != nil {
		t.Fatalf("a connector-driven import named a person as the actor: %q", *audit.ActorUserID)
	}

	// And an administrator's identity is never invented from an empty principal, nor from a missing request.
	blank := httptest.NewRequest(http.MethodPost, "/admin/human-identities/import", nil)
	blank = blank.WithContext(context.WithValue(blank.Context(), adminIdentityContextKey{}, adminIdentity{}))
	if audit := humanIdentityImportAuditLog(result, blank, testEvaluator(), now); audit.ActorUserID != nil {
		t.Fatalf("an empty principal was recorded as the actor: %q", *audit.ActorUserID)
	}
	if audit := humanIdentityImportAuditLog(result, nil, testEvaluator(), now); audit.ActorUserID != nil {
		t.Fatalf("an audit built with no request named an actor anyway: %q", *audit.ActorUserID)
	}
}
