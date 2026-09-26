package main

import (
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestCarriedDeletionSaveFailureDoesNotEraseOrAcknowledge(t *testing.T) {
	now := time.Now()
	targets, dir := purgeTargetsForTest(t, "tenant_edge")
	path := filepath.Join(t.TempDir(), "tenants.json")
	tenants := newDurableAdminTenantModelStore(model.PolicyBundle{}, now, path)
	if _, err := tenants.Put(context.Background(), adminTenantModel{TenantID: "tenant_gone", DisplayName: "Gone"}, now); err != nil {
		t.Fatal(err)
	}
	targets.tenantModels = tenants
	targets.erasureOrders = &tenantErasureOrders{}
	payload := signedPayloadWithPurgeOrder("tenant_gone")
	payload.Tenants.Tenants = nil
	payload.Tenants.Deleted = []tenantDeletion{{TenantID: "tenant_gone", DeletedAt: now.UTC().Format(time.RFC3339)}}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	_, err := (configBundleSource{}).apply(payload, targets)
	if err == nil {
		t.Error("failed deletion acknowledged")
	}
	if _, err := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_gone"))); err != nil {
		t.Error("failed deletion erased logs", err)
	}
	if !targets.enrolled.IsAdmitted("device-gone") || len(targets.localCredentials.List("tenant_gone")) != 1 || len(targets.erasureOrders.list()) != 0 {
		t.Error("failed deletion erased or remembered")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".saved", path); err != nil {
		t.Fatal(err)
	}
	if _, err := (configBundleSource{}).apply(payload, targets); err != nil {
		t.Fatal(err)
	}
	if targets.enrolled.IsAdmitted("device-gone") || len(targets.erasureOrders.list()) != 1 {
		t.Fatal("retry did not apply")
	}
}

func TestTenantBundleUpsertFailurePreservesErasure(t *testing.T) {
	targets, dir := purgeTargetsForTest(t, "tenant_edge")
	path := filepath.Join(t.TempDir(), "tenants.json")
	tenants := newDurableAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_stays"}, time.Now(), path)
	targets.tenantModels = tenants
	targets.erasureOrders = &tenantErasureOrders{}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	payload := signedPayloadWithPurgeOrder("tenant_gone")
	payload.Tenants.Deleted = nil
	if _, err := (configBundleSource{}).apply(payload, targets); err == nil {
		t.Fatal("failed upsert accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_gone"))); err != nil {
		t.Fatal("upsert failure erased logs")
	}
	if !targets.enrolled.IsAdmitted("device-gone") || len(targets.erasureOrders.list()) != 0 {
		t.Fatal("upsert failure erased or remembered")
	}
}

func TestSignedTenantDeletionRetriesSameGeneration(t *testing.T) {
	now := time.Now()
	targets, dir := purgeTargetsForTest(t, "tenant_edge")
	path := filepath.Join(t.TempDir(), "tenants.json")
	tenants := newDurableAdminTenantModelStore(model.PolicyBundle{}, now, path)
	if _, err := tenants.Put(context.Background(), adminTenantModel{TenantID: "tenant_gone", DisplayName: "Gone"}, now); err != nil {
		t.Fatal(err)
	}
	targets.tenantModels = tenants
	targets.erasureOrders = &tenantErasureOrders{}
	payload := signedPayloadWithPurgeOrder("tenant_gone")
	payload.Tenants.Tenants = nil
	payload.Generation = 42
	payload.Epoch = "tenant-save-retry"
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.SignTyped("config_bundle", payload, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	var polls atomic.Int32
	status := &configBundleSyncStatus{}
	checks := make(chan bool, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := polls.Add(1)
		if n == 3 {
			status.mu.RLock()
			failed := !status.haveApplied && status.lastError != ""
			status.mu.RUnlock()
			_, logErr := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_gone")))
			checks <- failed && logErr == nil && targets.enrolled.IsAdmitted("device-gone") && len(targets.erasureOrders.list()) == 0
			if err := os.Remove(path); err != nil {
				cancel()
				return
			}
			if err := os.Rename(path+".saved", path); err != nil {
				cancel()
				return
			}
		}
		if n == 4 {
			status.mu.RLock()
			applied := status.haveApplied && status.lastAppliedGeneration == 42 && status.lastError == ""
			status.mu.RUnlock()
			checks <- applied && !targets.enrolled.IsAdmitted("device-gone") && len(targets.erasureOrders.list()) == 1
			cancel()
		}
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	defer server.Close()
	source := configBundleSource{url: server.URL, client: server.Client(), verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true, interval: 10 * time.Millisecond, status: status}
	source.run(ctx, targets)
	if len(checks) != 2 || !<-checks || !<-checks {
		t.Fatal("same signed generation was not safely retried")
	}
	restored := newDurableAdminTenantModelStore(model.PolicyBundle{}, now, path)
	if len(restored.DeletedTenants()) != 1 {
		t.Fatal("retry lost tombstone")
	}
}
