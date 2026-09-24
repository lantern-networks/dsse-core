package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
)

func TestTenantStartupDoesNotOverwriteMalformedSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tenants.json")
	original := []byte(`{"tenants":`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if store, err := openAdminTenantModelStore(model.PolicyBundle{TenantID: "seed"}, time.Now(), path, ""); err == nil || store != nil {
		t.Fatal("corrupt startup was accepted")
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(original) {
		t.Fatal("startup overwrote malformed snapshot")
	}
}
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

func TestTenantStartupSnapshotFailureAndRecovery(t *testing.T) {
	for _, kind := range []string{"empty", "null", "missing-map", "directory", "dangling-link", "seed-save"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "tenants.json")
			write := func(raw []byte) {
				t.Helper()
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "empty":
				write([]byte{})
			case "null":
				write([]byte(`null`))
			case "missing-map":
				write([]byte(`{"deleted":{"gone":"2026-09-19T00:00:00Z"}}`))
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "dangling-link":
				if err := os.Symlink(filepath.Join(dir, "missing"), path); err != nil {
					t.Fatal(err)
				}
			case "seed-save":
				if os.Geteuid() == 0 {
					t.Skip("directory permissions do not deny root")
				}
				if err := os.Chmod(dir, 0500); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(dir, 0700)
			}
			if store, err := openAdminTenantModelStore(model.PolicyBundle{TenantID: "seed"}, time.Now(), path, ""); err == nil || store != nil {
				t.Fatal("unknown/unsaved state accepted")
			}
			if kind == "seed-save" {
				if err := os.Chmod(dir, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			}
			s, err := openAdminTenantModelStore(model.PolicyBundle{TenantID: "seed"}, time.Now(), path, "operator")
			if err != nil {
				t.Fatal(err)
			}
			rows, err := s.List(context.Background())
			if err != nil || len(rows) != 2 {
				t.Fatal("recovery seed", rows, err)
			}
			if _, err := s.Put(context.Background(), adminTenantModel{TenantID: "removed", DisplayName: "Removed"}, time.Now()); err != nil {
				t.Fatal(err)
			}
			if err := s.Delete(context.Background(), "removed"); err != nil {
				t.Fatal(err)
			}
			if err := s.OrderPurge("removed", time.Now()); err != nil {
				t.Fatal(err)
			}
			s, err = openAdminTenantModelStore(model.PolicyBundle{TenantID: "different-seed"}, time.Now(), path, "operator")
			if err != nil {
				t.Fatal(err)
			}
			rows, _ = s.List(context.Background())
			if len(rows) != 2 || len(s.DeletedTenants()) != 1 || len(s.PurgeOrders()) != 1 {
				t.Fatal("restart changed saved catalog or lifecycle")
			}
		})
	}
}

func TestTenantRegistryProductionStartup(t *testing.T) {
	module, _ := filepath.Abs("../..")
	for _, kind := range []string{"malformed", "empty", "missing-map"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			seedCertPinStartup(t, dir)
			path := filepath.Join(dir, "tenants.json")
			raw := map[string][]byte{"malformed": []byte(`{"tenants":`), "empty": {}, "missing-map": []byte(`{"deleted":{}}`)}[kind]
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"-listen", "127.0.0.1:0", "-no-control-plane", "-lab-mode", "-policy", filepath.Join(dir, "policy.json"), "-bundle", filepath.Join(dir, "bundle.json"), "-schema-dir", filepath.Join(module, "schemas"), "-log-dir", filepath.Join(dir, "logs"), "-edge-region-id", "region-a", "-tenant-model-store", path}
			argBytes, _ := json.Marshal(args)
			argPath := filepath.Join(dir, "args.json")
			if err := os.WriteFile(argPath, argBytes, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCertPinProductionStartupKeepsAuthoredIntent$")
			cmd.Env = append(os.Environ(), "DSSE_CERTPIN_STARTUP_ARGS="+argPath)
			out, err := cmd.CombinedOutput()
			if err == nil || ctx.Err() != nil || !strings.Contains(string(out), "setup tenant model store: load tenant registry") {
				t.Fatalf("startup not refused at tenant gate: %v %s", err, out)
			}
			got, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(got, raw) {
				t.Fatal("startup altered input")
			}
		})
	}
	t.Run("first-boot-and-restart", func(t *testing.T) {
		dir := t.TempDir()
		seedCertPinStartup(t, dir)
		path := filepath.Join(dir, "tenants.json")
		for i := 0; i < 2; i++ {
			base, stop := startCertPinMain(t, dir, false, "-tenant-model-store", path)
			var tenant adminTenantModel
			certPinStartupGet(t, base, "/admin/tenant", &tenant)
			stop()
			if tenant.TenantID != "startup-own" {
				t.Fatal("wrong tenant", tenant.TenantID)
			}
		}
	})
}

type unreadableTenantList struct{ adminTenantModelAdminStore }

func (s unreadableTenantList) List(context.Context) ([]adminTenantModel, error) {
	return nil, errors.New("registry unavailable")
}
func TestTenantBundleReadFailurePreservesData(t *testing.T) {
	targets, dir := purgeTargetsForTest(t, "tenant_edge")
	targets.tenantModels = unreadableTenantList{newAdminTenantModelStore(model.PolicyBundle{}, time.Now())}
	targets.erasureOrders = &tenantErasureOrders{}
	if _, err := (configBundleSource{}).apply(signedPayloadWithPurgeOrder("tenant_gone"), targets); err == nil {
		t.Fatal("unknown tenant set accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "tenants", logs.SafeTenantSegment("tenant_gone"))); err != nil {
		t.Fatal("read failure erased logs")
	}
	if len(targets.erasureOrders.list()) != 0 {
		t.Fatal("unapplied orders remembered")
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
	restored, err := openAdminTenantModelStore(model.PolicyBundle{}, now, path, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(restored.DeletedTenants()) != 1 {
		t.Fatal("retry lost tombstone")
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
