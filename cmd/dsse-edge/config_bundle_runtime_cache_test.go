package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policyrule"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"
)

type receivedCacheFailAfter struct {
	blobstore.FilePersister
	saves     int
	failAfter int
}

func (p *receivedCacheFailAfter) Save(raw []byte) error {
	p.saves++
	if p.saves >= p.failAfter {
		return errors.New("cache disk refused")
	}
	return p.FilePersister.Save(raw)
}

func receivedCacheRules(t *testing.T) *policyrule.Store {
	t.Helper()
	rules := policyrule.NewStore()
	_, err := rules.Upsert(policyrule.Rule{ID: "removed-allow", TenantID: "own", Plane: policyrule.PlaneEgress, Priority: 10, Name: "removed at authority", Source: []string{"*"}, Destination: []string{"ep-x"}, Action: policyrule.Action{Access: policyrule.AccessAllow, Inspection: policyrule.InspectionBypass}, Status: policyrule.StatusActive})
	if err != nil {
		t.Fatal(err)
	}
	return rules
}

func receivedCacheRestrictiveBundle() configBundlePayload {
	cfg := policy.TenantConfigBundle{EastWestEnabled: true, EastWestAllowUnmatched: false, EastWestRules: []decision.EastWestRule{{ID: "deny", Mode: "deny", Destinations: []string{"db.invalid"}}}}
	return configBundlePayload{Generation: 31, Epoch: "cache-retry", TenantConfig: &cfg, TenantPolicies: []tenantPolicySection{{TenantID: "peer", Config: &cfg}, {TenantID: "last", Config: &cfg}}, Rules: &authoredRuleBundle{}}
}

func TestReceivedRuntimeCacheFailureContinuesLaterSections(t *testing.T) {
	for _, failureAt := range []int{1, 2} {
		t.Run(fmt.Sprint(failureAt), func(t *testing.T) {
			p := &receivedCacheFailAfter{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "cache.json")}, failAfter: failureAt}
			s := policy.NewStore(nil)
			if err := s.SetRuntimeStatePersister(p); err != nil {
				t.Fatal(err)
			}
			rules := receivedCacheRules(t)
			_, err := (configBundleSource{tenantID: "own"}).apply(receivedCacheRestrictiveBundle(), configApplyTargets{policyStore: s, rules: rules})
			if !errors.Is(err, policy.ErrPolicyPersistence) || !errors.Is(err, policy.ErrReceivedRuntimeCache) {
				t.Fatal("cache failure not reported", err)
			}
			for _, tenant := range []string{"own", "peer", "last"} {
				if !s.SnapshotTenantConfig(tenant).EastWestEnabled {
					t.Fatal("restrictive config frozen", tenant)
				}
			}
			if len(rules.Snapshot()) != 0 {
				t.Fatal("later allow deletion was skipped")
			}
		})
	}
}

func TestReceivedRuntimeCacheSyncRetriesUntilDurable(t *testing.T) {
	p := &riskAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "cache.json")}}
	s := policy.NewStore(nil)
	if err := s.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	p.fail.Store(true)
	rules := receivedCacheRules(t)
	status := &configBundleSyncStatus{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var polls atomic.Int32
	checks := make(chan bool, 2)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch polls.Add(1) {
		case 3:
			status.mu.RLock()
			failed := !status.haveApplied && status.lastError != ""
			status.mu.RUnlock()
			checks <- failed && s.SnapshotTenantConfig("last").EastWestEnabled && len(rules.Snapshot()) == 0
			p.fail.Store(false)
		case 4:
			status.mu.RLock()
			ok := status.haveApplied && status.lastAppliedGeneration == 31 && status.lastError == ""
			status.mu.RUnlock()
			checks <- ok
			cancel()
		}
		json.NewEncoder(w).Encode(receivedCacheRestrictiveBundle())
	}))
	defer srv.Close()
	src := configBundleSource{tenantID: "own", url: srv.URL, client: srv.Client(), interval: 10 * time.Millisecond, status: status}
	src.run(ctx, configApplyTargets{policyStore: s, rules: rules})
	if len(checks) != 2 || !<-checks || !<-checks {
		t.Fatal("live apply, degraded status or same-generation retry failed")
	}
	fresh := policy.NewStore(nil)
	if err := fresh.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"own", "peer", "last"} {
		if !reflect.DeepEqual(fresh.SnapshotTenantConfig(tenant), s.SnapshotTenantConfig(tenant)) {
			t.Fatal("recovered cache differs", tenant)
		}
	}
}

func TestReceivedRuntimeControlsSurviveRestartWithoutPull(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	s := policy.NewStore(nil)
	if err := s.SetRuntimeStatePath(path); err != nil {
		t.Fatal(err)
	}
	cfg := policy.TenantConfigBundle{EastWestEnabled: true, EastWestAllowUnmatched: false, EastWestMaxGrantTTL: 37, ServerInitiatedEnabled: true, EastWestRules: []decision.EastWestRule{{ID: "deny", Mode: "deny", Destinations: []string{"db.invalid"}}}, TenantRestrictionRuleStatus: map[string]string{"rule": "disabled"}}
	src := configBundleSource{tenantID: "own"}
	if _, err := src.apply(configBundlePayload{TenantConfig: &cfg, TenantPolicies: []tenantPolicySection{{TenantID: "peer", Config: &cfg}}}, configApplyTargets{policyStore: s}); err != nil {
		t.Fatal(err)
	}
	r := policy.NewStore(nil)
	if err := r.SetRuntimeStatePath(path); err != nil {
		t.Fatal(err)
	}
	for _, tenant := range []string{"own", "peer"} {
		if !reflect.DeepEqual(r.SnapshotTenantConfig(tenant), s.SnapshotTenantConfig(tenant)) {
			t.Fatalf("cold restart weakened %s controls: %+v", tenant, r.SnapshotTenantConfig(tenant))
		}
	}
}
