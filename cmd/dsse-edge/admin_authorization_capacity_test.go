package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/delegatedgrant"
	"github.com/lantern-networks/dsse-core/humanapproval"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

func TestAdminAuthorizationCapacityRefusalPreservesRevocationAndAudits(t *testing.T) {
	for _, kind := range []string{"grant", "approval"} {
		t.Run(kind, func(t *testing.T) {
			now := time.Now()
			dir := t.TempDir()
			grants := delegatedgrant.NewStore(1)
			approvals := humanapproval.NewStore(1)
			writer, e := logs.NewWriter(dir)
			if e != nil {
				t.Fatal(e)
			}
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "capacity-admin", TenantID: "tenant_lab_001", Roles: []string{"admin"}, Status: "active"})
			auth.UpsertAPIToken(adminAPIToken{ID: "capacity-token", TenantID: "tenant_lab_001", TokenHash: adminTokenHash("private-capacity-token"), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "capacity-admin", Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, DelegatedGrants: grants, HumanApprovals: approvals})
			gp := blobstore.FilePersister{Path: filepath.Join(dir, "grants.json")}
			ap := blobstore.FilePersister{Path: filepath.Join(dir, "approvals.json")}
			if e := grants.SetPersister(gp); e != nil {
				t.Fatal(e)
			}
			if e := approvals.SetPersister(ap); e != nil {
				t.Fatal(e)
			}
			path := "/admin/delegated-grants"
			eventPrefix := "admin_delegated_access_grant_"
			input := `{"id":"retained","actor_nhi_id":"agent","subject_user_id":"person","tool_ids":["read_repo"],"status":"active"}`
			if kind == "approval" {
				path = "/admin/human-approval-events"
				eventPrefix = "admin_human_approval_event_"
				input = `{"id":"retained","approver_user_id":"person","actor_nhi_id":"agent","action_type":"read","approval_result":"approved"}`
			}
			for _, step := range []struct {
				suffix, body string
				status       int
			}{{"", input, 200}, {"/retained/revoke", `{}`, 200}, {"", strings.Replace(input, "retained", "pressure", 1), 503}, {"", input, 409}} {
				beforeG, _ := gp.Load()
				beforeA, _ := ap.Load()
				gen := grants.ConfigGeneration()
				req := httptest.NewRequest("POST", path+step.suffix, strings.NewReader(step.body))
				req.Header.Set("Authorization", "Bearer private-capacity-token")
				req.Header.Set("Content-Type", "application/json")
				r := httptest.NewRecorder()
				h.ServeHTTP(r, req)
				if r.Code != step.status {
					t.Fatalf("response %d want %d: %s", r.Code, step.status, r.Body)
				}
				if step.status >= 400 {
					afterG, _ := gp.Load()
					afterA, _ := ap.Load()
					if string(beforeG) != string(afterG) || string(beforeA) != string(afterA) || gen != grants.ConfigGeneration() {
						t.Fatal("refused mutation altered stored state or generation")
					}
				}
			}
			domains, commonErrors := 0, 0
			for _, a := range readTransportAudits(t, writer) {
				if strings.HasPrefix(a.EventType, eventPrefix) {
					domains++
					if stringPtrValue(a.ActorUserID) != "capacity-admin" || a.TenantID != "tenant_lab_001" || stringPtrValue(a.TargetID) != "retained" {
						t.Fatalf("domain attribution: %+v", a)
					}
				}
				if a.EventType == "admin_config_change" && stringPtrValue(a.Result) == "error" {
					commonErrors++
				}
			}
			if domains != 2 || commonErrors != 2 {
				t.Fatalf("domain=%d common errors=%d; rejected writes must not emit accepted domain events", domains, commonErrors)
			}
			if kind == "grant" {
				reload := delegatedgrant.NewStore(1)
				if e := reload.SetPersister(gp); e != nil {
					t.Fatal(e)
				}
				g, ok := reload.GetForTenant("tenant_lab_001", "retained")
				if !ok || g.Status != "revoked" || reload.Count() != 1 {
					t.Fatal("saved revocation lost")
				}
			} else {
				reload := humanapproval.NewStore(1)
				if e := reload.SetPersister(ap); e != nil {
					t.Fatal(e)
				}
				a, ok := reload.GetForTenant("tenant_lab_001", "retained")
				if !ok || a.ApprovalResult != "revoked" || reload.Count() != 1 {
					t.Fatal("saved approval revocation lost")
				}
				r := httptest.NewRecorder()
				h.ServeHTTP(r, httptest.NewRequest("POST", "/human-approvals/events", strings.NewReader(`{"id":"runtime-pressure","tenant_id":"tenant_lab_001","approver_user_id":"person","actor_nhi_id":"agent","action_type":"read","approval_result":"approved"}`)))
				if r.Code != 503 {
					t.Fatalf("runtime admission: %d %s", r.Code, r.Body)
				}
			}
		})
	}
}

func TestConfigBundleGrantCapacityDoesNotHideIncompleteApplication(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "grants.json")
	s := delegatedgrant.NewStore(1)
	if e := s.SetStatePath(path); e != nil {
		t.Fatal(e)
	}
	retained := model.DelegatedAccessGrant{ID: "retained", TenantID: "tenant_lab_001", ActorNHIID: "agent", SubjectUserID: "person", Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	if _, e := s.Upsert(retained); e != nil {
		t.Fatal(e)
	}
	fresh := retained
	fresh.ID = "fresh"
	revoked := retained
	revoked.Status = "revoked"
	payload := configBundlePayload{Generation: 7, Epoch: "capacity-epoch", DelegatedGrants: &delegatedGrantBundle{Grants: []model.DelegatedAccessGrant{fresh, revoked}}}
	src := configBundleSource{tenantID: "tenant_lab_001"}
	targets := configApplyTargets{policyStore: policy.NewStore(nil), delegatedGrants: s}
	if _, e := src.apply(payload, targets); !errors.Is(e, delegatedgrant.ErrCapacity) {
		t.Fatalf("bundle must remain unapplied: %v", e)
	}
	got, ok := s.GetForTenant("tenant_lab_001", "retained")
	if !ok || got.Status != "revoked" {
		t.Fatal("new-ID refusal prevented retained-ID revocation")
	}
	// Increase the admission limit without replacing saved authorization state, then replay the same generation.
	raised := delegatedgrant.NewStore(2)
	if e := raised.SetStatePath(path); e != nil {
		t.Fatal(e)
	}
	targets.delegatedGrants = raised
	if _, e := src.apply(payload, targets); e != nil {
		t.Fatal(e)
	}
	if raised.Count() != 2 {
		t.Fatal("same generation did not converge after capacity increase")
	}
	// Storage refusal also remains an unapplied generation and can be retried.
	p := &riskAuditPersister{base: blobstore.FilePersister{Path: path}}
	if e := raised.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	p.fail.Store(true)
	if _, e := src.apply(payload, targets); !errors.Is(e, delegatedgrant.ErrPersistence) {
		t.Fatalf("storage refusal ignored: %v", e)
	}
	p.fail.Store(false)
	if _, e := src.apply(payload, targets); e != nil {
		t.Fatal(e)
	}
}

func TestConfigBundleGrantCapacityRetriesSameGeneration(t *testing.T) {
	s := delegatedgrant.NewStore(1)
	now := time.Now()
	g := model.DelegatedAccessGrant{ID: "retained", TenantID: "tenant_lab_001", ActorNHIID: "agent", SubjectUserID: "person", Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}
	if _, e := s.Upsert(g); e != nil {
		t.Fatal(e)
	}
	g.ID = "refused"
	payload := configBundlePayload{Generation: 9, Epoch: "retry-epoch", DelegatedGrants: &delegatedGrantBundle{Grants: []model.DelegatedAccessGrant{g}}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var polls atomic.Int32
	status := &configBundleSyncStatus{}
	observedErrors := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count := polls.Add(1)
		json.NewEncoder(w).Encode(payload)
		if count >= 3 {
			status.mu.RLock()
			previousError := status.lastError
			status.mu.RUnlock()
			select {
			case observedErrors <- previousError:
			default:
			}
			cancel()
		}
	}))
	defer server.Close()
	src := configBundleSource{tenantID: "tenant_lab_001", url: server.URL, client: server.Client(), interval: 10 * time.Millisecond, status: status}
	// Bound the test even if the retry loop changes or an HTTP handler stops responding.
	timer := time.AfterFunc(3*time.Second, cancel)
	defer timer.Stop()
	src.run(ctx, configApplyTargets{policyStore: policy.NewStore(nil), delegatedGrants: s})
	status.mu.RLock()
	defer status.mu.RUnlock()
	previousError := ""
	select {
	case previousError = <-observedErrors:
	default:
	}
	if polls.Load() < 3 || status.haveApplied || !strings.Contains(previousError, "capacity reached") {
		t.Fatalf("polls=%d applied=%v error=%s", polls.Load(), status.haveApplied, previousError)
	}
}
