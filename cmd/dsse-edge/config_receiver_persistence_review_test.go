package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/humanidentity"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/nhi"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/tenantca"
)

type receiverReviewPersister struct {
	data []byte
	fail bool
}

func (p *receiverReviewPersister) Load() ([]byte, error) { return p.data, nil }
func (p *receiverReviewPersister) Save(b []byte) error {
	if p.fail {
		return errors.New("test storage unavailable")
	}
	p.data = append([]byte(nil), b...)
	return nil
}

func TestConfigReceiverIdentityPersistenceRetry(t *testing.T) {
	for _, kind := range []string{"nhi", "people"} {
		t.Run(kind, func(t *testing.T) {
			p := &ruleAuditPersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "identity.json")}}
			n := nhi.NewStore()
			h := humanidentity.NewHumanIdentityDirectoryStore()
			if err := n.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if err := h.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			payload := configBundlePayload{Generation: 42}
			targets := configApplyTargets{policyStore: policy.NewStore(nil)}
			if kind == "nhi" {
				targets.nhi = n
				payload.NHI = &nonHumanIdentityBundle{Identities: []model.NonHumanIdentity{{ID: "agent", Name: "Agent", NHIType: "ai_agent", OwnerUserID: "owner"}}}
			} else {
				targets.humanIdentities = h
				payload.HumanIdentities = &humanIdentityBundle{Identities: []model.HumanIdentity{{ID: "person", TenantID: "own", Subject: "person@example.invalid"}}}
			}
			p.fail.Store(true)
			status := &configBundleSyncStatus{}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			var polls atomic.Int32
			checks := make(chan bool, 2)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch polls.Add(1) {
				case 3:
					status.mu.RLock()
					checks <- !status.haveApplied && status.lastError != ""
					status.mu.RUnlock()
					p.fail.Store(false)
				case 4:
					status.mu.RLock()
					checks <- status.haveApplied && status.lastAppliedGeneration == 42
					status.mu.RUnlock()
					cancel()
				}
				json.NewEncoder(w).Encode(payload)
			}))
			defer server.Close()
			src := configBundleSource{tenantID: "own", url: server.URL, client: server.Client(), interval: 10 * time.Millisecond, status: status}
			src.run(ctx, targets)
			if len(checks) != 2 || !<-checks || !<-checks {
				t.Fatal("failed save was acknowledged or same-generation retry did not recover")
			}
			if kind == "nhi" {
				reload := nhi.NewStore()
				if err := reload.SetPersister(p); err != nil {
					t.Fatal(err)
				}
				rows, _ := reload.List(context.Background(), "own")
				if len(rows) != 1 {
					t.Fatal("NHI lost on restart")
				}
			} else {
				reload := humanidentity.NewHumanIdentityDirectoryStore()
				if err := reload.SetPersister(p); err != nil {
					t.Fatal(err)
				}
				rows, _ := reload.List(context.Background(), "own")
				if len(rows) != 1 {
					t.Fatal("person lost on restart")
				}
			}
		})
	}
}

type receiverSiteFailure struct {
	adminSiteStore
	failure string
}

func (s *receiverSiteFailure) List(c context.Context, tenant string) ([]adminSiteModel, error) {
	if s.failure == "read" {
		return nil, errors.New("read failed")
	}
	return s.adminSiteStore.List(c, tenant)
}
func (s *receiverSiteFailure) Delete(c context.Context, tenant, id string) error {
	if s.failure == "delete" {
		return errors.New("delete failed")
	}
	return s.adminSiteStore.Delete(c, tenant, id)
}
func (s *receiverSiteFailure) Upsert(c context.Context, v adminSiteModel, now time.Time) (adminSiteModel, error) {
	if s.failure == "save" {
		return adminSiteModel{}, errors.New("save failed")
	}
	return s.adminSiteStore.Upsert(c, v, now)
}
func TestConfigReceiverSitePersistenceRetry(t *testing.T) {
	for _, failure := range []string{"read", "delete", "save"} {
		t.Run(failure, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sites.json")
			store := newDurableAdminSiteStore(path)
			putSite(t, store, "own", "old", connectorRuntimeSecretHash("old"))
			putSite(t, store, "other", "keep", connectorRuntimeSecretHash("keep"))
			edge := &receiverSiteFailure{store, failure}
			src := configBundleSource{tenantID: "own"}
			payload := configBundlePayload{Generation: 42, Sites: &siteCatalogBundle{Complete: true, Tenants: []string{"own"}, Sites: []adminSiteModel{{TenantID: "own", SiteID: "new", Name: "new"}}}}
			targets := configApplyTargets{policyStore: policy.NewStore(nil), sites: edge}
			if _, err := src.apply(payload, targets); err == nil {
				t.Fatal("failed Site operation acknowledged")
			}
			edge.failure = ""
			if _, err := src.apply(payload, targets); err != nil {
				t.Fatal(err)
			}
			reload := newDurableAdminSiteStore(path)
			if rows := siteIDs(t, reload, "own"); len(rows) != 1 || rows[0] != "new" {
				t.Fatal("wrong own Sites after restart", rows)
			}
			if rows := siteIDs(t, reload, "other"); len(rows) != 1 || rows[0] != "keep" {
				t.Fatal("other tenant changed", rows)
			}
		})
	}
}
func TestDeviceCABundleRetriesSaveWithNoFurtherMemoryChange(t *testing.T) {
	cp := registryWith(t, map[string][][]byte{"own": {makeBundleTestCA(t, "new-ca")}})
	section := deviceCABundleSection(cp, nil)
	edge := tenantca.NewTenantCARegistry()
	fail := true
	calls := 0
	var saved []byte
	persist := func(r *tenantca.TenantCARegistry) error {
		calls++
		if fail {
			return errors.New("save failed")
		}
		var err error
		saved, err = r.Snapshot()
		return err
	}
	if added, _, err := applyDeviceCABundleSection(edge, section, persist, nil); added != 1 || err == nil {
		t.Fatalf("first add=%d err=%v", added, err)
	}
	if added, _, err := applyDeviceCABundleSection(edge, section, persist, nil); added != 0 || err == nil {
		t.Fatalf("retry must still report failed save, add=%d err=%v", added, err)
	}
	fail = false
	if _, _, err := applyDeviceCABundleSection(edge, section, persist, nil); err != nil {
		t.Fatal(err)
	}
	reload := tenantca.NewTenantCARegistry()
	if n, err := reload.Adopt(saved); err != nil || n != 1 {
		t.Fatalf("restart=%d %v", n, err)
	}
	if calls != 3 {
		t.Fatal("did not retry persistence", calls)
	}
}
