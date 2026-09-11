package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/model"
)

func trustDistributorFixture(t *testing.T) (*tenantTrustDistributor, *tenantTransportAuthority) {
	t.Helper()
	tr := newTenantTransportAuthority(nil, nil, time.Now)
	if _, err := tr.EnsureCA("tenant_a", "a.dsse.invalid"); err != nil {
		t.Fatal(err)
	}
	signer, err := agentpolicy.LoadOrGenerateSigner(filepath.Join(t.TempDir(), "signer"), true)
	if err != nil {
		t.Fatal(err)
	}
	config := serverConfig{TenantTransportAuthority: tr, AgentPolicySigner: signer}
	return &tenantTrustDistributor{config: config, store: blobstore.NewSingleWriterFilePersister(blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "trust.json")}), now: time.Now}, tr
}
func publishTrustForTest(t *testing.T, d *tenantTrustDistributor, tr *tenantTransportAuthority) map[string]tenantTrustDistribution {
	t.Helper()
	snapshot, err := tr.materialSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	all, err := d.Publish(snapshot, nil)
	if err != nil {
		t.Fatal(err)
	}
	return all
}
func trustPayloadForTest(t *testing.T, d *tenantTrustDistributor, item tenantTrustDistribution) agentpolicy.TrustBundlePayload {
	t.Helper()
	p, err := agentpolicy.VerifyTrustBundle(item.Envelope, d.config.AgentPolicySigner.PublicKeyHex(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func TestTenantTrustDistributionDurableRevision(t *testing.T) {
	d, tr := trustDistributorFixture(t)
	first := publishTrustForTest(t, d, tr)
	p := trustPayloadForTest(t, d, first["tenant_a"])
	if p.Serial < 1000000000000 {
		t.Fatal("legacy counter migration floor missing")
	}
	// Restart on a different CP with a clock moving backwards does not re-sign.
	other := &tenantTrustDistributor{config: d.config, store: d.store, now: func() time.Time { return time.Unix(1, 0) }}
	second := publishTrustForTest(t, other, tr)
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if !bytes.Equal(a, b) {
		t.Fatal("unchanged publication was re-authored")
	}
	stale, _ := tr.materialSnapshot()
	if _, err := tr.RotateCA("tenant_a"); err != nil {
		t.Fatal(err)
	}
	next := publishTrustForTest(t, other, tr)
	q := trustPayloadForTest(t, other, next["tenant_a"])
	if q.Serial != p.Serial+1 {
		t.Fatal("clock rollback lost durable serial")
	}
	fps, _ := q.Fingerprints()
	if len(fps) != 2 {
		t.Fatal("overlap did not retain both authorities")
	}
	if next["tenant_a"].ActivateIncoming != "" {
		t.Fatal("empty population activated authority")
	}
	if _, err := d.Publish(stale, nil); !errors.Is(err, errAuthorityConflict) {
		t.Fatalf("stale authority published: %v", err)
	}
	// Corruption and failed persistence must never return a newly signed envelope.
	d.store = trustBrokenPersister{load: []byte("invalid")}
	if out, err := d.Publish(stale, nil); err == nil || out != nil {
		t.Fatal("corrupt state published")
	}
	snapshot, _ := tr.materialSnapshot()
	d.store = trustBrokenPersister{}
	if out, err := d.Publish(snapshot, nil); err == nil || out != nil {
		t.Fatal("failed commit published")
	}
}

type trustBrokenPersister struct{ load []byte }

func (p trustBrokenPersister) Load() ([]byte, error) { return p.load, nil }
func (p trustBrokenPersister) Save([]byte) error     { return fmt.Errorf("injected write failure") }

func TestTenantTrustDistributionCacheRejectsRollbackAndEquivocation(t *testing.T) {
	d, tr := trustDistributorFixture(t)
	first := publishTrustForTest(t, d, tr)
	caches := []*tenantTrustDistributionCache{{keys: []string{d.config.AgentPolicySigner.PublicKeyHex()}}, {keys: []string{d.config.AgentPolicySigner.PublicKeyHex()}}, {keys: []string{d.config.AgentPolicySigner.PublicKeyHex()}}}
	for _, c := range caches {
		if err := c.Adopt(first); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tr.RotateCA("tenant_a"); err != nil {
		t.Fatal(err)
	}
	second := publishTrustForTest(t, d, tr)
	for _, c := range caches {
		if err := c.Adopt(second); err != nil {
			t.Fatal(err)
		}
		if err := c.Adopt(first); err == nil {
			t.Fatal("accepted rollback")
		}
		p := trustPayloadForTest(t, d, second["tenant_a"])
		p.TransportCAPEM = tr.cas["tenant_a"].CACertPEM
		env, err := d.config.AgentPolicySigner.SignTrustBundlePayload(p, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Adopt(map[string]tenantTrustDistribution{"tenant_a": {Envelope: env}}); err == nil {
			t.Fatal("same serial changed contents")
		}
		if err := c.Adopt(nil); err == nil {
			t.Fatal("legacy response silently accepted")
		}
		got, _ := c.For("tenant_a")
		a, _ := json.Marshal(got)
		b, _ := json.Marshal(second["tenant_a"].Envelope)
		if !bytes.Equal(a, b) {
			t.Fatal("rejected response changed cache")
		}
	}
}

func TestTenantTrustDistributionActivationRequiresFreshWholePopulation(t *testing.T) {
	d, _ := trustDistributorFixture(t)
	now := time.Now()
	pop := []enrolledinventory.Entry{{Identity: "mac", TenantID: "tenant_a", Enabled: true}, {Identity: "win", TenantID: "tenant_a", Enabled: true}, {Identity: "connector", TenantID: "tenant_a", Enabled: true, Kind: enrolledinventory.KindService}}
	good := observedExclusionEntry{TenantID: "tenant_a", DeviceIdentity: "mac", ReportedAt: now, AdoptedTrustSerial: 50, TransportServerNameSent: "a.dsse.invalid", PinnedTransportCASHA256: []string{"root"}}
	win := good
	win.DeviceIdentity = "win"
	for _, bad := range []string{"none", "missing", "stale", "future", "old-serial", "old-root", "old-name", "unassigned", "before-rotation"} {
		t.Run(bad, func(t *testing.T) {
			population := append([]enrolledinventory.Entry(nil), pop...)
			r := win
			reports := []observedExclusionEntry{good}
			since := now.Add(-time.Minute)
			switch bad {
			case "none":
				population = nil
			case "missing":
			case "stale":
				r.ReportedAt = now.Add(-6 * time.Minute)
			case "future":
				r.ReportedAt = now.Add(time.Minute)
			case "old-serial":
				r.AdoptedTrustSerial = 49
			case "old-root":
				r.PinnedTransportCASHA256 = nil
			case "old-name":
				r.TransportServerNameSent = "shared.invalid"
			case "unassigned":
				population[1].TenantID = ""
			case "before-rotation":
				since = now.Add(time.Second)
			}
			if bad != "missing" {
				reports = append(reports, r)
			}
			if d.adopted(population, reports, "tenant_a", "a.dsse.invalid", "root", 50, since, now) {
				t.Fatal("incomplete evidence activated")
			}
		})
	}
	if !d.adopted(pop, []observedExclusionEntry{good, win}, "tenant_a", "a.dsse.invalid", "root", 50, now.Add(-time.Minute), now) {
		t.Fatal("complete fresh evidence refused")
	}
}

func TestTenantTrustDistributionIncludedInUnchangedMaterial(t *testing.T) {
	d, tr := trustDistributorFixture(t)
	mux := http.NewServeMux()
	registerTenantTransportMaterialRoute(mux, tr, nil, nil, "test", time.Hour, nil, true, d)
	call := func(generation uint64) map[string]json.RawMessage {
		r := httptest.NewRequest("POST", "/tenant-edge-material", strings.NewReader(fmt.Sprintf(`{"known_generation":%d}`, generation)))
		r.Header.Set("Authorization", "Bearer test")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
		}
		var out map[string]json.RawMessage
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	full := call(0)
	var generation uint64
	_ = json.Unmarshal(full["generation"], &generation)
	unchanged := call(generation)
	if string(unchanged["unchanged"]) != "true" || !bytes.Equal(full["trust_bundles"], unchanged["trust_bundles"]) {
		t.Fatal("cheap poll lost canonical trust")
	}
}

func TestTenantTrustDistributionPostgresConcurrentControlPlanes(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN not set")
	}
	base, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	schema := fmt.Sprintf("trust_test_%d", time.Now().UnixNano())
	if _, err := base.Exec("CREATE SCHEMA " + schema); err != nil {
		t.Fatal(err)
	}
	defer base.Exec("DROP SCHEMA " + schema + " CASCADE")
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE cp_state_blobs(store_key text PRIMARY KEY,payload bytea NOT NULL,updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	for _, schema := range [][]string{postgresObservedExclusionSchemaSQL(), postgresObservedTrustTelemetrySchemaSQL(), postgresObservedRecoveryNameSchemaSQL(), postgresObservedRecoveryTargetSchemaSQL(), postgresObservedInterceptionRefusalsSchemaSQL(), postgresObservedAgentPolicyKeysSchemaSQL()} {
		for _, q := range schema {
			if _, err := db.Exec(q); err != nil {
				t.Fatal(err)
			}
		}
	}
	d, tr := trustDistributorFixture(t)
	authorityStore := postgresBlobPersister{db: db, key: "tenant_transport_authorities"}
	if err := authorityStore.Save(encodeAuthoritySnapshot(tr.cas)); err != nil {
		t.Fatal(err)
	}
	d.store = postgresBlobPersister{db: db, key: "tenant_trust_distributions"}
	d.config.ObservedExclusions = &postgresObservedExclusionStore{db: db}
	// Three independent issuers start together; serialization conflicts may retry,
	// but successful responses must be byte-for-byte identical, including signature.
	var wg sync.WaitGroup
	results := make(chan []byte, 3)
	errs := make(chan error, 3)
	for n := 0; n < 3; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			other := &tenantTrustDistributor{config: d.config, store: d.store, now: time.Now}
			for attempt := 0; attempt < 8; attempt++ {
				all, err := other.Publish(tr, nil)
				if err == nil {
					raw, _ := json.Marshal(all)
					results <- raw
					return
				}
				if attempt == 7 {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	var expected []byte
	count := 0
	for result := range results {
		count++
		if expected == nil {
			expected = result
		} else if !bytes.Equal(expected, result) {
			t.Fatal("regions would serve different signed publications")
		}
	}
	if count != 3 {
		t.Fatal("not every CP published")
	}
	stale, _ := tr.materialSnapshot()
	if _, err := tr.RotateCA("tenant_a"); err != nil {
		t.Fatal(err)
	}
	if err := authorityStore.Save(encodeAuthoritySnapshot(tr.cas)); err != nil {
		t.Fatal(err)
	}
	newer := publishTrustForTest(t, d, tr)
	if out, err := d.Publish(stale, nil); !errors.Is(err, errAuthorityConflict) || out != nil {
		t.Fatalf("old CP republished withdrawn state: %v", err)
	}
	var old map[string]tenantTrustDistribution
	_ = json.Unmarshal(expected, &old)
	if trustPayloadForTest(t, d, newer["tenant_a"]).Serial <= trustPayloadForTest(t, d, old["tenant_a"]).Serial {
		t.Fatal("rotation did not advance durable revision")
	}
	db.Close()
	if out, err := d.Publish(tr, nil); err == nil || out != nil {
		t.Fatal("database outage returned signed publication")
	}
}

func TestTenantTrustDistributionErasureRetainsAnonymousSerialFloor(t *testing.T) {
	d, tr := trustDistributorFixture(t)
	first := publishTrustForTest(t, d, tr)
	old := trustPayloadForTest(t, d, first["tenant_a"])
	if n, err := d.CountForTenant("tenant_a"); err != nil || n != 1 {
		t.Fatalf("count %d: %v", n, err)
	}
	if n, err := d.RemoveTenant("tenant_a"); err != nil || n != 1 {
		t.Fatalf("erase %d: %v", n, err)
	}
	raw, err := d.store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("tenant_a")) || bytes.Contains(raw, []byte("envelope")) {
		t.Fatal("erasure retained tenant document")
	}
	if n, err := d.CountForTenant("tenant_a"); err != nil || n != 0 {
		t.Fatalf("remaining %d: %v", n, err)
	}
	d.now = func() time.Time { return time.Unix(1, 0) }
	next := publishTrustForTest(t, d, tr)
	if trustPayloadForTest(t, d, next["tenant_a"]).Serial <= old.Serial {
		t.Fatal("erasure reset serial floor")
	}
}

func TestTenantTrustDistributionActivationSurvivesRestartAndUnchangedPoll(t *testing.T) {
	useEmptyTenantCertificateIndex(t)
	d, tr := trustDistributorFixture(t)
	ledger := enrolledinventory.NewLedger()
	if _, err := ledger.Enroll("mac", "tenant_a", "", time.Now().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	observed := newObservedExclusionStore(10)
	d.config.EnrolledLedger = ledger
	d.config.ObservedExclusions = observed
	if _, err := tr.RotateCA("tenant_a"); err != nil {
		t.Fatal(err)
	}
	before := publishTrustForTest(t, d, tr)
	payload := trustPayloadForTest(t, d, before["tenant_a"])
	mats, err := tr.IssueAllFor("tenant_a", "edge", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, mat := range mats {
		if err := installTenantTransportMaterial(mat); err != nil {
			t.Fatal(err)
		}
	}
	cache := &tenantTrustDistributionCache{keys: []string{d.config.AgentPolicySigner.PublicKeyHex()}}
	if err := cache.Adopt(before); err != nil {
		t.Fatal(err)
	}
	incoming := fingerprintOfFirstCert(tr.cas["tenant_a"].Incoming.CACertPEM)
	if fp, _ := transportTenantCertificates.AnchorFingerprintFor("tenant_a"); fp == incoming {
		t.Fatal("activated before evidence")
	}
	observed.Record(observedExclusionEntry{TenantID: "tenant_a", DeviceIdentity: "mac", ReportedAt: time.Now(), AdoptedTrustSerial: payload.Serial, TransportServerNameSent: payload.TransportServerName, PinnedTransportCASHA256: []string{incoming}})
	after := publishTrustForTest(t, d, tr)
	if after["tenant_a"].ActivateIncoming != incoming {
		t.Fatal("fresh adoption did not authorize activation")
	}
	if trustPayloadForTest(t, d, after["tenant_a"]).Serial != payload.Serial {
		t.Fatal("activation unnecessarily changed trust revision")
	}
	if err := cache.Adopt(after); err != nil {
		t.Fatal(err)
	}
	if fp, _ := transportTenantCertificates.AnchorFingerprintFor("tenant_a"); fp != incoming {
		t.Fatal("canonical activation did not switch serving certificate")
	}
	// No report is necessary to reconstruct a decision already durably committed.
	restarted := &tenantTrustDistributor{config: d.config, store: d.store, now: time.Now}
	restarted.config.ObservedExclusions = nil
	again := publishTrustForTest(t, restarted, tr)
	if again["tenant_a"].ActivateIncoming != incoming {
		t.Fatal("restart forgot completed activation")
	}
	fps, _ := trustPayloadForTest(t, d, again["tenant_a"]).Fingerprints()
	if len(fps) != 2 {
		t.Fatal("Edge promotion prematurely withdrew the old CA")
	}
}

func TestTenantTrustDistributionIncludesOrganizationsUsingSharedTransport(t *testing.T) {
	d, tr := trustDistributorFixture(t)
	d.config.TrustBundleCAPEM = tr.cas["tenant_a"].CACertPEM
	d.config.TenantModelStore = newAdminTenantModelStore(model.PolicyBundle{TenantID: "tenant_shared"}, time.Now())
	all := publishTrustForTest(t, d, tr)
	shared, ok := all["tenant_shared"]
	if !ok {
		t.Fatal("organization without a dedicated transport CA lost its trust bundle")
	}
	p := trustPayloadForTest(t, d, shared)
	if p.TransportServerName != "" || strings.TrimSpace(p.TransportCAPEM) != strings.TrimSpace(d.config.TrustBundleCAPEM) {
		t.Fatal("shared organization received another organization's TLS name")
	}
	cache := &tenantTrustDistributionCache{keys: []string{d.config.AgentPolicySigner.PublicKeyHex()}}
	if err := cache.Adopt(all); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.For("tenant_shared"); !ok {
		t.Fatal("Edge discarded shared transport bundle")
	}
}

func TestTenantTrustDistributionAnnouncesConfiguredRecovery(t *testing.T) {
	d, tr := trustDistributorFixture(t)
	first := publishTrustForTest(t, d, tr)
	old := trustPayloadForTest(t, d, first["tenant_a"])
	if old.RenewalRecoverySNI != "" {
		t.Fatal("unconfigured recovery advertised")
	}
	d.config.RenewalRecoverySNI = "recovery.dsse.invalid"
	next := publishTrustForTest(t, d, tr)
	p := trustPayloadForTest(t, d, next["tenant_a"])
	if p.RenewalRecoverySNI != "recovery.a.dsse.invalid" || p.Serial <= old.Serial {
		t.Fatalf("recovery announcement did not advance: %+v", p)
	}
	d.config.RenewalRecoverySNI = ""
	last := publishTrustForTest(t, d, tr)
	q := trustPayloadForTest(t, d, last["tenant_a"])
	if q.RenewalRecoverySNI != "" || q.Serial <= p.Serial {
		t.Fatal("recovery withdrawal not distributed")
	}
}
