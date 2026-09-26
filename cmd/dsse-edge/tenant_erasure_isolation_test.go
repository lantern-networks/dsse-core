package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

type isolatedTenantFailureStore struct {
	adminTenantModelAdminStore
	recovered  atomic.Bool
	failList   bool
	failPut    string
	failDelete string
}

func (s *isolatedTenantFailureStore) List(ctx context.Context) ([]adminTenantModel, error) {
	if !s.recovered.Load() && s.failList {
		return nil, fmt.Errorf("synthetic registry unavailable")
	}
	return s.adminTenantModelAdminStore.List(ctx)
}
func (s *isolatedTenantFailureStore) Put(ctx context.Context, row adminTenantModel, now time.Time) (adminTenantModel, error) {
	if !s.recovered.Load() && row.TenantID == s.failPut {
		return adminTenantModel{}, fmt.Errorf("synthetic tenant write refused")
	}
	return s.adminTenantModelAdminStore.Put(ctx, row, now)
}
func (s *isolatedTenantFailureStore) Delete(ctx context.Context, id string) error {
	if !s.recovered.Load() && id == s.failDelete {
		return fmt.Errorf("synthetic tenant deletion refused")
	}
	return s.adminTenantModelAdminStore.Delete(ctx, id)
}

func TestTenantErasureFailureIsolationAndRetry(t *testing.T) {
	for _, stage := range []string{"unrelated-upsert", "unrelated-delete", "target-delete", "registry-read"} {
		t.Run(stage, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now()
			targets, dir := purgeTargetsForTest(t, "tenant_edge")
			defer targets.logWriter.Close()
			statePath := filepath.Join(t.TempDir(), "tenants.json")
			base := newDurableAdminTenantModelStore(model.PolicyBundle{}, now, statePath)
			for _, id := range []string{"tenant_gone", "tenant_stays", "tenant_failed"} {
				if _, err := base.Put(ctx, adminTenantModel{TenantID: id, DisplayName: id, Status: "active"}, now); err != nil {
					t.Fatal(err)
				}
			}
			failedLogs := filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_failed"))
			if err := os.MkdirAll(failedLogs, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(failedLogs, "access.log.jsonl"), []byte("{}\n"), 0600); err != nil {
				t.Fatal(err)
			}
			store := &isolatedTenantFailureStore{adminTenantModelAdminStore: base}
			switch stage {
			case "unrelated-upsert":
				store.failPut = "tenant_stays"
			case "unrelated-delete":
				store.failDelete = "tenant_failed"
			case "target-delete":
				store.failDelete = "tenant_gone"
			case "registry-read":
				store.failList = true
			}
			targets.tenantModels = store
			targets.erasureOrders = &tenantErasureOrders{}
			payload := signedPayloadWithPurgeOrder("tenant_gone")
			payload.Tenants.Deleted = append(payload.Tenants.Deleted, tenantDeletion{TenantID: "tenant_failed"})
			payload.Tenants.PurgeOrders = append(payload.Tenants.PurgeOrders, tenantPurgeOrder{TenantID: "tenant_failed", OrderedAt: now.UTC().Format(time.RFC3339)})
			_, err := (configBundleSource{}).apply(payload, targets)
			if err == nil {
				t.Fatal("failed registry operation acknowledged")
			}
			if stage == "unrelated-delete" && !strings.Contains(err.Error(), `tenant erasure deferred for "tenant_failed"`) {
				t.Errorf("missing erasure status: %v", err)
			}
			if stage == "registry-read" && !strings.Contains(err.Error(), "tenant erasure deferred: registry unavailable") {
				t.Errorf("missing registry erasure status: %v", err)
			}
			goneBlocked := stage == "target-delete" || stage == "registry-read"
			failedBlocked := stage == "unrelated-delete" || stage == "registry-read"
			assertLogs := func(id string, kept bool) {
				t.Helper()
				_, e := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment(id)))
				if kept && e != nil {
					t.Errorf("%s lost protected logs: %v", id, e)
				}
				if !kept && !os.IsNotExist(e) {
					t.Errorf("%s erasure blocked by another tenant: %v", id, e)
				}
			}
			assertLogs("tenant_gone", goneBlocked)
			assertLogs("tenant_failed", failedBlocked)
			assertLogs("tenant_stays", true)
			if targets.enrolled.IsAdmitted("device-gone") != goneBlocked || (len(targets.localCredentials.List("tenant_gone")) != 0) != goneBlocked {
				t.Error("erasure boundary for device/credentials")
			}
			remembered := map[string]bool{}
			for _, order := range targets.erasureOrders.list() {
				remembered[order] = true
			}
			if remembered["tenant_gone"] == goneBlocked || remembered["tenant_failed"] == failedBlocked {
				t.Errorf("remembered blocked or omitted safe erasure: %v", remembered)
			}
			if len(payload.Tenants.PurgeOrders) != 2 {
				t.Fatal("filter mutated incoming bundle")
			}
			store.recovered.Store(true)
			for i := 0; i < 2; i++ {
				if _, err := (configBundleSource{}).apply(payload, targets); err != nil {
					t.Fatal(err)
				}
				assertLogs("tenant_gone", false)
				assertLogs("tenant_failed", false)
				assertLogs("tenant_stays", true)
				if len(targets.erasureOrders.list()) != 2 || targets.enrolled.IsAdmitted("device-gone") {
					t.Fatal("same bundle retry did not complete")
				}
			}
			restored := newDurableAdminTenantModelStore(model.PolicyBundle{}, now, statePath)
			if len(restored.DeletedTenants()) != 2 {
				t.Fatal("confirmed deletions not persisted")
			}
		})
	}
}

// The same signed generation must keep retrying the failed tenant even after
// another tenant has completed erasure. Status must name the deferred tenant.
func TestSignedTenantErasureIsolationRetriesSameGeneration(t *testing.T) {
	now := time.Now()
	targets, dir := purgeTargetsForTest(t, "tenant_edge")
	defer targets.logWriter.Close()
	base := newDurableAdminTenantModelStore(model.PolicyBundle{}, now, filepath.Join(t.TempDir(), "tenants.json"))
	for _, id := range []string{"tenant_gone", "tenant_failed"} {
		if _, err := base.Put(context.Background(), adminTenantModel{TenantID: id, DisplayName: id}, now); err != nil {
			t.Fatal(err)
		}
	}
	store := &isolatedTenantFailureStore{adminTenantModelAdminStore: base, failDelete: "tenant_failed"}
	targets.tenantModels = store
	targets.erasureOrders = &tenantErasureOrders{}
	payload := signedPayloadWithPurgeOrder("tenant_gone")
	payload.Tenants.Deleted = append(payload.Tenants.Deleted, tenantDeletion{TenantID: "tenant_failed"})
	payload.Tenants.PurgeOrders = append(payload.Tenants.PurgeOrders, tenantPurgeOrder{TenantID: "tenant_failed", OrderedAt: now.UTC().Format(time.RFC3339)})
	payload.Generation = 53
	payload.Epoch = "erasure-isolation"
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.SignTyped("config_bundle", payload, now)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	status := &configBundleSyncStatus{}
	checks := make(chan bool, 2)
	var polls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch polls.Add(1) {
		case 3:
			snap := status.snapshot()
			_, logErr := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_gone")))
			checks <- snap["have_applied"] == false && strings.Contains(fmt.Sprint(snap["last_error"]), `tenant erasure deferred for "tenant_failed"`) && os.IsNotExist(logErr) && !targets.enrolled.IsAdmitted("device-gone") && len(targets.erasureOrders.list()) == 1
			store.recovered.Store(true)
		case 4:
			snap := status.snapshot()
			checks <- snap["have_applied"] == true && snap["last_applied_generation"] == uint64(53) && snap["last_error"] == nil && len(targets.erasureOrders.list()) == 2
			cancel()
		}
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()
	source := configBundleSource{url: server.URL, client: server.Client(), verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true, interval: 10 * time.Millisecond, status: status}
	source.run(ctx, targets)
	if len(checks) != 2 || !<-checks || !<-checks {
		t.Fatal("signed partial erasure status/retry did not complete")
	}
}

func TestTenantErasureIsolationKeepsSafetyGates(t *testing.T) {
	for _, gate := range []string{"unsigned", "live", "enforcement"} {
		t.Run(gate, func(t *testing.T) {
			now := time.Now()
			targets, dir := purgeTargetsForTest(t, "tenant_edge")
			defer targets.logWriter.Close()
			base := newDurableAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_stays"}, now, filepath.Join(t.TempDir(), "tenants.json"))
			targets.tenantModels = &isolatedTenantFailureStore{adminTenantModelAdminStore: base, failPut: "tenant_stays"}
			payload := signedPayloadWithPurgeOrder("tenant_gone")
			switch gate {
			case "unsigned":
				payload.signatureVerified = false
			case "live":
				payload.Tenants.Tenants = append(payload.Tenants.Tenants, adminTenantModel{TenantID: "tenant_gone", DisplayName: "Gone", Status: "active"})
			case "enforcement":
				targets.enforcementTenantID = "tenant_gone"

			}
			if _, err := (configBundleSource{}).apply(payload, targets); err == nil {
				t.Fatal("unrelated failed upsert acknowledged")
			}
			if _, err := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_gone"))); err != nil {
				t.Fatal("protected logs erased", err)
			}
			if !targets.enrolled.IsAdmitted("device-gone") || len(targets.localCredentials.List("tenant_gone")) != 1 {
				t.Fatal("protected identities erased")
			}
		})
	}
}
