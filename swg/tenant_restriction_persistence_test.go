package swg

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/swghttprewrite"
	"os"
	"path/filepath"
	"testing"
)

func legacyRestrictionFixture(t *testing.T) (RuntimeConfig, model.PolicyBundle, *policy.Store) {
	t.Helper()
	ref := "operator_config_ref:allowed"
	rule := model.SWGTenantRestrictionRule{ID: "rule", TenantID: "tenant", SaaSApplicationID: "app", Provider: "google_workspace", HeaderName: "X-GoogApps-Allowed-Domains", HeaderValueRef: ref, HeaderValueKind: "configured_allowed_domains", Status: "active"}
	bundle := model.PolicyBundle{TenantID: "tenant", SWGTenantRestrictionRules: []model.SWGTenantRestrictionRule{rule}}
	config := swghttprewrite.OperatorManagedHeaderValueConfig{SchemaVersion: swghttprewrite.SWGOperatorConfigSchemaVersion, Status: "active", TenantID: "tenant", Metadata: map[string]any{"designated_operator_config_file": true}, HeaderValues: []swghttprewrite.OperatorManagedHeaderValue{{Ref: ref, TenantID: "tenant", SaaSApplicationID: "app", Provider: rule.Provider, HeaderName: rule.HeaderName, HeaderValueKind: rule.HeaderValueKind, Value: "old.example", Status: "active", Metadata: map[string]any{"operator_managed": true}}}}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "operator.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	runtime, err := LoadRuntimeConfig(RuntimeConfigInput{PolicyBundle: bundle, TenantRestrictionOperatorConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	s := policy.NewStore(nil)
	if err = s.SetRuntimeStatePath(filepath.Join(t.TempDir(), "runtime.json")); err != nil {
		t.Fatal(err)
	}
	return runtime, bundle, s
}
func TestLegacyRestrictionRejectsBeforeLiveMutation(t *testing.T) {
	for _, mode := range []string{"file_unavailable", "invalid_toggle", "missing_file_ref"} {
		t.Run(mode, func(t *testing.T) {
			runtime, bundle, s := legacyRestrictionFixture(t)
			req := TenantRestrictionUpdateRequest{HeaderValueUpdates: map[string]string{"operator_config_ref:allowed": "new.example"}}
			if mode == "file_unavailable" {
				os.Remove(runtime.TenantRestrictionOperatorConfigPath)
			}
			if mode == "invalid_toggle" {
				req.SaaSEnablement = map[string]bool{"missing": true}
			}
			if mode == "missing_file_ref" {
				os.WriteFile(runtime.TenantRestrictionOperatorConfigPath, []byte(`{"header_values":[]}`), 0600)
			}
			_, err := ApplyTenantRestrictionUpdateContext(context.Background(), runtime, bundle, s, req)
			if err == nil {
				t.Fatal("unpersisted or invalid update reported success")
			}
			if v, _ := runtime.TenantRestrictionResolver.ResolveHeaderValue("operator_config_ref:allowed"); v != "old.example" {
				t.Fatal("rejected update changed live value")
			}
		})
	}
}

type legacyRestrictionRejectedSave struct{}

func (legacyRestrictionRejectedSave) Load() ([]byte, error) { return nil, nil }
func (legacyRestrictionRejectedSave) Save([]byte) error     { return errors.New("save rejected") }

func TestLegacyRestrictionFailedStatusRestoresHeadersAndRetry(t *testing.T) {
	runtime, bundle, s := legacyRestrictionFixture(t)
	raw, err := os.ReadFile(runtime.TenantRestrictionOperatorConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	runtime.TenantRestrictionOperatorValueStorePath = filepath.Join(t.TempDir(), "values.json")
	if err = os.WriteFile(runtime.TenantRestrictionOperatorValueStorePath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.SetRuntimeStatePersister(legacyRestrictionRejectedSave{}); err != nil {
		t.Fatal(err)
	}
	req := TenantRestrictionUpdateRequest{HeaderValueUpdates: map[string]string{"operator_config_ref:allowed": "new.example"}, SaaSEnablement: map[string]bool{"app": false}}
	resp, err := ApplyTenantRestrictionUpdateContext(context.Background(), runtime, bundle, s, req)
	if err == nil || resp.PersistedToOperatorConfig || resp.PersistedToValueStore || len(resp.AppliedRefs) != 0 || len(resp.AppliedSaaS) != 0 || resp.HotApplied {
		t.Fatalf("unreported partial: %+v %v", resp, err)
	}
	if v, _ := runtime.TenantRestrictionResolver.ResolveHeaderValue("operator_config_ref:allowed"); v != "old.example" {
		t.Fatal("failed status save changed live header")
	}
	if len(s.TenantRestrictionRuleStatusOverrides()) != 0 {
		t.Fatal("failed status published")
	}
	for _, path := range []string{runtime.TenantRestrictionOperatorConfigPath, runtime.TenantRestrictionOperatorValueStorePath} {
		restored, err := swghttprewrite.LoadOperatorManagedHeaderValueResolver(path, bundle)
		if err != nil {
			t.Fatal(err)
		}
		if v, _ := restored.ResolveHeaderValue("operator_config_ref:allowed"); v != "old.example" {
			t.Fatal("failed request changed saved header")
		}
	}
	runtimePath := filepath.Join(t.TempDir(), "runtime.json")
	if err = s.SetRuntimeStatePath(runtimePath); err != nil {
		t.Fatal(err)
	}
	resp, err = ApplyTenantRestrictionUpdateContext(context.Background(), runtime, bundle, s, req)
	if err != nil || !resp.HotApplied || len(resp.AppliedSaaS) != 1 {
		t.Fatal(resp, err)
	}
	fresh := policy.NewStore(nil)
	if err = fresh.SetRuntimeStatePath(runtimePath); err != nil {
		t.Fatal(err)
	}
	if fresh.TenantRestrictionRuleStatusOverrides()["rule"] != "inactive" {
		t.Fatal("retry not persisted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req.HeaderValueUpdates["operator_config_ref:allowed"] = "never.example"
	if _, err = ApplyTenantRestrictionUpdateContext(ctx, runtime, bundle, s, req); err == nil {
		t.Fatal("canceled write accepted")
	}
	if v, _ := runtime.TenantRestrictionResolver.ResolveHeaderValue("operator_config_ref:allowed"); v != "new.example" {
		t.Fatal("canceled value published")
	}
}
