package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentrollout"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/delegatedgrant"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/grantstore"
	"github.com/lantern-networks/dsse-core/humanapproval"
	"github.com/lantern-networks/dsse-core/idpregistry"
)

var extraPurgeSeeds = map[string]string{
	"delegated":    `{"a":{"id":"a","tenant_id":"tenant_target"},"b":{"id":"b","tenant_id":"tenant_other"}}`,
	"human":        `{"a":{"id":"a","tenant_id":"tenant_target"},"b":{"id":"b","tenant_id":"tenant_other"}}`,
	"clientless":   `{"a":{"grant_id":"a","tenant_id":"tenant_target","user_id":"user","idp_id":"idp","issued_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z"},"b":{"grant_id":"b","tenant_id":"tenant_other","user_id":"user","idp_id":"idp","issued_at":"2026-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z"}}`,
	"idp":          `{"connections":{"tenant_target":{"a":{"id":"a","tenant_id":"tenant_target"}},"tenant_other":{"b":{"id":"b","tenant_id":"tenant_other"}}},"defaults":{"tenant_target":"a","tenant_other":"b"}}`,
	"routes":       `{"seen":{"tenant_target":{"a":true},"tenant_other":{"b":true}},"held":{},"approved":{},"authored":{}}`,
	"transport":    `[{"tenant_id":"tenant_target"},{"tenant_id":"tenant_other"}]`,
	"interception": `[{"tenant_id":"tenant_target"},{"tenant_id":"tenant_other"}]`,
	"rollout":      `{"tenant_target":{"intent":"freeze","frozen":true},"tenant_other":{"intent":"freeze","frozen":true}}`,
	"published":    `{"schema":"published_agent_updates.v2","active":{"tenant_target|windows/amd64":{},"tenant_other|windows/amd64":{},"deployment|windows/amd64":{}},"pending":{"tenant_target|darwin/arm64":{},"tenant_other|darwin/arm64":{}},"legacy":{}}`,
}

type extraPurgePersister struct {
	base      blobstore.FilePersister
	uncertain bool
}

func (p *extraPurgePersister) Load() ([]byte, error) { return p.base.Load() }
func (p *extraPurgePersister) Save(b []byte) error {
	if p.uncertain {
		return errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
	}
	return p.base.Save(b)
}
func loadExtraPurgeFixture(t *testing.T, kind string, p blobstore.Persister) adminTenantExtraStores {
	t.Helper()
	e := adminTenantExtraStores{}
	var err error
	switch kind {
	case "delegated":
		e.DelegatedGrants = delegatedgrant.NewStore(0)
		err = e.DelegatedGrants.SetPersister(p)
	case "human":
		e.HumanApprovals = humanapproval.NewStore(0)
		err = e.HumanApprovals.SetPersister(p)
	case "clientless":
		e.ClientlessGrants = grantstore.NewStore()
		err = e.ClientlessGrants.SetPersister(p)
	case "idp":
		e.IdPConnections = idpregistry.NewStore()
		err = e.IdPConnections.SetPersister(p)
	case "routes":
		e.ConnectorRoutes = newConnectorRouteGovernanceWithPersister("", true, p)
	case "transport", "interception":
		var raw []byte
		raw, err = p.Load()
		if err != nil {
			t.Fatal(err)
		}
		if kind == "transport" {
			e.TenantTransportAuthorities = newTenantTransportAuthority(raw, p.Save, time.Now)
		} else {
			e.TenantInterceptionAuthorities = newTenantInterceptionAuthority(raw, p.Save, time.Now)
		}
	case "rollout":
		e.AgentRolloutPlans = agentrollout.NewAgentRolloutStore()
		err = e.AgentRolloutPlans.LoadFromPersister(p)
	case "published":
		e.PublishedAgentUpdates = newPublishedAgentUpdateStore()
		err = e.PublishedAgentUpdates.LoadFromPersister(p, "")
	default:
		t.Fatal(kind)
	}
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func extraPurgeCount(e adminTenantExtraStores, tenant string) int64 {
	f := adminTenantFootprint{TenantID: tenant}
	e.count(&f)
	return f.Total
}
func TestExtraTenantPurgeSaveFailurePreservesRetry(t *testing.T) {
	for kind, seed := range extraPurgeSeeds {
		for _, mode := range []string{"filesystem", "unconfirmed"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				dir := t.TempDir()
				p := &extraPurgePersister{base: blobstore.FilePersister{Path: filepath.Join(dir, "store.json")}}
				if err := p.Save([]byte(seed)); err != nil {
					t.Fatal(err)
				}
				e := loadExtraPurgeFixture(t, kind, p)
				before, _ := p.Load()
				want := extraPurgeCount(e, "tenant_target")
				foreign := extraPurgeCount(e, "tenant_other")
				if want == 0 || foreign == 0 {
					t.Fatal("invalid fixture count")
				}
				ledger := enrolledinventory.NewLedger()
				ledger.Enroll("owned", "tenant_target", "", "now")
				if mode == "filesystem" {
					if err := os.Rename(p.base.Path, p.base.Path+".saved"); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(p.base.Path, 0700); err != nil {
						t.Fatal(err)
					}
				} else {
					p.uncertain = true
				}
				result := purgeAdminTenantData(context.Background(), "node", "tenant_target", nil, nil, nil, ledger, nil, nil, "", nil, nil, e, nil, time.Now())
				if len(result.Failures) == 0 || result.Complete {
					t.Errorf("unconfirmed erasure reported without failure: %+v", result)
				}
				if len(result.Erased) != 0 {
					t.Errorf("unconfirmed erasure counted: %+v", result.Erased)
				}
				if extraPurgeCount(e, "tenant_target") != want {
					t.Error("failed erasure lost retry state")
				}
				entries := ledger.Authoritative()
				if len(entries) != 1 || entries[0].RemovedAt == "" || entries[0].Enabled {
					t.Error("retired identity lost")
				}
				if strings.Contains(strings.Join(result.Failures, " "), dir) {
					t.Error("private persistence path leaked")
				}
				if mode == "filesystem" {
					os.Remove(p.base.Path)
					if err := os.Rename(p.base.Path+".saved", p.base.Path); err != nil {
						t.Fatal(err)
					}
				} else {
					p.uncertain = false
				}
				saved, _ := p.Load()
				if !bytes.Equal(saved, before) {
					t.Error("refused write changed persisted bytes")
				}
				// Repairing the same writer must allow a same-process retry, without first
				// discarding memory. Then reload independently to prove the deletion survives.
				result = purgeAdminTenantData(context.Background(), "node", "tenant_target", nil, nil, nil, ledger, nil, nil, "", nil, nil, e, nil, time.Now())
				if !result.Complete {
					t.Fatalf("same-process retry failed: %+v", result)
				}
				e = loadExtraPurgeFixture(t, kind, p)
				if extraPurgeCount(e, "tenant_target") != 0 || extraPurgeCount(e, "tenant_other") != foreign {
					t.Error("restart resurrected target or erased another tenant")
				}
			})
		}
	}
}

func TestPublishedArtifactErasureRetriesAfterManifestRemoval(t *testing.T) {
	p := &extraPurgePersister{base: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "store.json")}}
	if err := p.Save([]byte(extraPurgeSeeds["published"])); err != nil {
		t.Fatal(err)
	}
	e := loadExtraPurgeFixture(t, "published", p)
	refuse := true
	calls := 0
	shelf := &agentUpdateArtifactShelf{forget: func(tenant string) error {
		calls++
		if tenant != "tenant_target" {
			t.Fatal("wrong shelf")
		}
		if refuse {
			return errors.New("private shelf error")
		}
		return nil
	}}
	e.PublishedAgentUpdates.WithArtifactShelf(shelf)
	run := func() adminTenantPurgeResult {
		return purgeAdminTenantData(context.Background(), "node", "tenant_target", nil, nil, nil, nil, nil, nil, "", nil, nil, e, nil, time.Now())
	}
	result := run()
	if result.Complete || len(result.Failures) == 0 || calls != 1 {
		t.Fatal("artifact failure hidden")
	}
	if e.PublishedAgentUpdates.CountForTenant("tenant_target") != 0 {
		t.Fatal("manifest removal expected before shelf failure")
	}
	assertCleanup := func(result adminTenantPurgeResult, shared string) {
		t.Helper()
		b, _ := json.Marshal(result)
		var body map[string]any
		_ = json.Unmarshal(b, &body)
		cleanup, ok := body["artifact_cleanup"].(map[string]any)
		if !ok || cleanup["manifests"] != "absence_confirmed" || cleanup["shared"] != shared {
			t.Fatalf("cleanup state absent or inaccurate: %s", b)
		}
	}
	assertCleanup(result, "unconfirmed")
	if !strings.Contains(strings.Join(result.Failures, " "), "artifact cleanup") || strings.Contains(strings.Join(result.Failures, " "), "private shelf") {
		t.Fatalf("failure does not explain remaining bytes safely: %+v", result.Failures)
	}
	found := false
	for _, row := range result.Erased {
		if row.Store == "published_agent_releases" && row.Count == 2 {
			found = true
		}
	}
	if !found {
		t.Fatal("confirmed manifest removal was not reported")
	}
	e = loadExtraPurgeFixture(t, "published", p)
	e.PublishedAgentUpdates.WithArtifactShelf(shelf)
	refuse = false
	if result = run(); !result.Complete || calls != 2 {
		t.Fatalf("empty shelf not retried: %+v calls=%d", result, calls)
	}
	assertCleanup(result, "absence_confirmed")
	if e.PublishedAgentUpdates.CountForTenant("tenant_other") != 2 {
		t.Fatal("foreign shelf changed")
	}
}

func TestTenantPurgeCapturesInitializedConnectorRoutes(t *testing.T) {
	old, path := connectorRouteGov, connectorRouteGovPersistPath
	connectorRouteGov = nil
	connectorRouteGovPersistPath = filepath.Join(t.TempDir(), "routes.json")
	defer func() { connectorRouteGov, connectorRouteGovPersistPath = old, path }()
	if err := os.WriteFile(connectorRouteGovPersistPath, []byte(extraPurgeSeeds["routes"]), 0600); err != nil {
		t.Fatal(err)
	}
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "operator", TenantID: "tenant_operator", Roles: []string{"owner"}, Status: "active"})
	auth.UpsertAPIToken(adminAPIToken{ID: "token", TenantID: "tenant_operator", TokenHash: adminTokenHash("purge-fixture"), Roles: []string{"owner"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "operator", ExpiresAt: time.Now().Add(time.Hour).Format(time.RFC3339), Status: "active"})
	tenants := newOperatorAwareAdminTenantModelStore(testEvaluator().PolicyBundle, time.Now(), filepath.Join(t.TempDir(), "tenants.json"), "tenant_operator")
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), AdminAuth: auth, TenantModelStore: tenants, OperatorTenantID: "tenant_operator"})
	req := httptest.NewRequest(http.MethodPost, "/admin/tenants/tenant_target/purge", strings.NewReader(`{"confirm_tenant_id":"tenant_target"}`))
	req.Header.Set("Authorization", "Bearer purge-fixture")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("purge: %d %s", rec.Code, rec.Body.String())
	}
	var result adminTenantPurgeResult
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.Complete || connectorRouteGov.CountForTenant("tenant_target") != 0 || connectorRouteGov.CountForTenant("tenant_other") != 1 {
		t.Fatal("route governance omitted from purge")
	}
	fresh := newConnectorRouteGovernanceWithPersistence(connectorRouteGovPersistPath)
	if fresh.CountForTenant("tenant_target") != 0 {
		t.Fatal("route resurrected")
	}
}

func TestPublishedArtifactCleanupStages(t *testing.T) {
	for _, stage := range []string{"manifest", "local"} {
		t.Run(stage, func(t *testing.T) {
			root := t.TempDir()
			p := &extraPurgePersister{base: blobstore.FilePersister{Path: filepath.Join(root, "published.json")}}
			if err := p.Save([]byte(extraPurgeSeeds["published"])); err != nil {
				t.Fatal(err)
			}
			e := loadExtraPurgeFixture(t, "published", p)
			local := filepath.Join(root, "not-a-directory")
			if err := os.WriteFile(local, []byte("blocked parent"), 0600); err != nil {
				t.Fatal(err)
			}
			e.PublishedAgentUpdates.artifactDir = local
			sharedCalls := 0
			e.PublishedAgentUpdates.WithArtifactShelf(&agentUpdateArtifactShelf{forget: func(string) error { sharedCalls++; return nil }})
			p.uncertain = stage == "manifest"
			result := adminTenantPurgeResult{TenantID: "tenant_target"}
			e.erase(&result)
			if len(result.Failures) != 1 || sharedCalls != 0 {
				t.Fatalf("failed stage did not stop cleanup: %+v calls=%d", result, sharedCalls)
			}
			if stage == "manifest" {
				if result.ArtifactCleanup["manifests"] != "unconfirmed" || result.ArtifactCleanup["local"] != "not_attempted" || len(result.Erased) != 0 {
					t.Fatalf("unconfirmed manifest treated as removed: %+v", result)
				}
			} else if result.ArtifactCleanup["manifests"] != "absence_confirmed" || result.ArtifactCleanup["local"] != "unconfirmed" || result.ArtifactCleanup["shared"] != "not_attempted" {
				t.Fatalf("local failure hidden: %+v", result)
			}
			p.uncertain = false
			if err := os.Remove(local); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(local, "tenant_target"), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(local, "tenant_target", "artifact"), []byte("bytes"), 0600); err != nil {
				t.Fatal(err)
			}
			result = adminTenantPurgeResult{TenantID: "tenant_target"}
			e.erase(&result)
			if len(result.Failures) != 0 || result.ArtifactCleanup["local"] != "absence_confirmed" || result.ArtifactCleanup["shared"] != "absence_confirmed" || sharedCalls != 1 {
				t.Fatalf("repair failed: %+v", result)
			}
			if _, err := os.Stat(filepath.Join(local, "tenant_target")); !os.IsNotExist(err) {
				t.Fatal("local bytes remain", err)
			}
		})
	}
}
