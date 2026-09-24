package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

func pkiTestAuthorities(t *testing.T) (*tenantTransportAuthority, *tenantDeviceAuthority, *tenantInterceptionAuthority) {
	t.Helper()
	tr := newTenantTransportAuthority(nil, nil, time.Now)
	if _, err := tr.EnsureCA("tenant_a", "a.dsse.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.RotateCA("tenant_a"); err != nil {
		t.Fatal(err)
	}
	de := newTenantDeviceAuthority(nil, nil, time.Now)
	if _, err := de.EnsureCA("tenant_a", "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := de.RotateCA("tenant_a"); err != nil {
		t.Fatal(err)
	}
	in := newTenantInterceptionAuthority(nil, nil, time.Now)
	for i := 0; i < 2; i++ {
		root, key := interceptionTestCA(t, "root", nil, nil, time.Now())
		issuer, ik := interceptionTestCA(t, "issuer", root, key, time.Now())
		if _, err := in.Import("tenant_a", certPEMForTest(root), certPEMForTest(issuer), ecKeyPEMForTest(t, ik)); err != nil {
			t.Fatal(err)
		}
	}
	return tr, de, in
}

// Exercise the actual six admin paths: rejection must preserve both authorities and generation.
func TestPKIAdminTransitionsRequireEvidence(t *testing.T) {
	for _, gateMode := range []string{"missing", "unavailable", "accepted"} {
		for _, route := range []string{"transport/retire-previous", "transport/abandon-rotation", "device/retire-previous", "device/abandon-rotation", "interception/promote", "interception/withdraw-incoming"} {
			t.Run(gateMode+"/"+route, func(t *testing.T) {
				tr, de, in := pkiTestAuthorities(t)
				before := string(encodeAuthoritySnapshot(tr.cas)) + string(encodeAuthoritySnapshot(de.cas)) + string(encodeAuthoritySnapshot(in.issuers))
				generation := tr.generation + de.generation + in.generation
				var gates []pkiTransitionAdmission
				called := false
				if gateMode != "missing" {
					gates = []pkiTransitionAdmission{func(c pkiAuthorityTransition) error {
						called = true
						if c.Tenant != "tenant_a" || c.Kind != strings.Split(route, "/")[0] {
							t.Fatalf("wrong transition: %s/%s", c.Kind, c.Tenant)
						}
						if gateMode == "unavailable" {
							return errors.New("pki_evidence_unavailable: injected read failure")
						}
						return nil
					}}
				}
				mux := http.NewServeMux()
				admin := func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }
				registerTenantTransportRotationAdminRoutes(mux, admin, tr, "", gates...)
				registerTenantDeviceAuthorityAdminRoute(mux, admin, de, "", nil, gates...)
				registerTenantInterceptionAuthorityAdminRoute(mux, admin, in, nil, nil, gates...)
				parts := strings.Split(route, "/")
				response := httptest.NewRecorder()
				mux.ServeHTTP(response, httptest.NewRequest("POST", "/admin/tenant-"+parts[0]+"-authority/"+parts[1], strings.NewReader(`{"tenant_id":"tenant_a"}`)))
				want := http.StatusConflict
				if gateMode == "accepted" {
					want = http.StatusOK
				}
				if response.Code != want {
					t.Fatalf("HTTP %d: %s", response.Code, response.Body.String())
				}
				if gateMode != "missing" && !called {
					t.Fatal("gate was not called")
				}
				after := string(encodeAuthoritySnapshot(tr.cas)) + string(encodeAuthoritySnapshot(de.cas)) + string(encodeAuthoritySnapshot(in.issuers))
				if gateMode != "accepted" && (before != after || generation != tr.generation+de.generation+in.generation) {
					t.Fatal("refused transition changed authority")
				}
				if gateMode == "accepted" && before == after {
					t.Fatal("accepted transition was not committed")
				}
			})
		}
	}
}

func TestPKIAdmissionCASBindsEvidenceToSnapshot(t *testing.T) {
	backend := &authorityMemoryCAS{}
	p := protectPKIAuthorityPersister(backend, "tenant_transport_authorities")
	seed, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	a := newTenantTransportAuthorityWithReload(seed, p.Save, p.Load, time.Now)
	if _, err := a.EnsureCA("tenant_a", "a.dsse.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RotateCA("tenant_a"); err != nil {
		t.Fatal(err)
	}
	competitor := authorityClient(t, "transport", backend)
	gate := func(c pkiAuthorityTransition) error {
		if c.TransportBefore.Incoming == nil || c.TransportAfter.Incoming != nil {
			t.Fatal("not judging the proposed transition")
		}
		return competitor.create("tenant_b")
	}
	row, err := a.admitTransition("tenant_a", "retire-previous", []pkiTransitionAdmission{gate}, func(a *tenantTransportAuthority, id string) (*storedTenantTransportCA, error) {
		return a.RetirePrevious(id)
	})
	if !errors.Is(err, errAuthorityConflict) || row != nil {
		t.Fatalf("uncommitted transition escaped: row=%t err=%v", row != nil, err)
	}
	if a.cas["tenant_a"].Incoming == nil || a.cas["tenant_b"] == nil {
		t.Fatal("conflict published the candidate or lost the concurrent winner")
	}
	if _, err := a.IssueAllFor("tenant_a", "edge", time.Hour); err != nil {
		t.Fatal(err)
	}
	if a.cas["tenant_a"].Incoming == nil || a.cas["tenant_b"] == nil {
		t.Fatal("concurrent winner lost")
	}
}

func TestPKITransitionEvidence(t *testing.T) {
	tr, de, in := pkiTestAuthorities(t)
	now := time.Now().UTC()
	for _, kind := range []string{"transport", "interception", "device"} {
		t.Run(kind, func(t *testing.T) {
			c := pkiAuthorityTransition{Kind: kind, Tenant: "tenant_a", Action: "retire-previous"}
			c.TransportBefore = copyAuthority(tr.cas["tenant_a"])
			c.TransportAfter = copyAuthority(c.TransportBefore.Incoming)
			c.DeviceBefore = copyAuthority(de.cas["tenant_a"])
			c.DeviceAfter = copyAuthority(c.DeviceBefore.Incoming)
			c.InterceptionBefore = copyAuthority(in.issuers["tenant_a"])
			c.InterceptionAfter = copyAuthority(c.InterceptionBefore.Incoming)
			if kind == "interception" {
				c.Action = "promote"
			}
			roots := []string{fingerprintOfFirstCert(c.InterceptionBefore.RootPEM), fingerprintOfFirstCert(c.InterceptionAfter.RootPEM)}
			bundle := agentpolicy.TrustBundlePayload{TenantID: "tenant_a", Serial: 9, TransportCAPEM: c.TransportAfter.CACertPEM, InterceptionRootSHA256: roots}
			report := observedExclusionEntry{TenantID: "tenant_a", DeviceIdentity: "mac", ReportedAt: now, AdoptedTrustSerial: 9, PinnedTransportCASHA256: []string{fingerprintOfFirstCert(c.TransportAfter.CACertPEM)}, PinnedInterceptionRootSHA256: roots, InterceptionRootPinSHA256: roots[1]}
			fact := deviceCertificateFact{TenantID: "tenant_a", Identity: "mac", LastSeenAt: now.Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339), AnchorSHA256: fingerprintOfFirstCert(deviceAnchorsOf(c.DeviceAfter))}
			check := func(pop []string, r observedExclusionEntry, f deviceCertificateFact, b []agentpolicy.TrustBundlePayload) error {
				return checkPKITransitionEvidence(c, pop, []observedExclusionEntry{r}, []deviceCertificateFact{f}, b, now)
			}
			bundles := []agentpolicy.TrustBundlePayload{bundle, bundle, bundle}
			if err := check([]string{"mac"}, report, fact, bundles); err != nil {
				t.Fatal(err)
			}
			if err := check(nil, report, fact, bundles); err == nil {
				t.Fatal("empty population passed")
			}
			if err := check([]string{"mac", "offline"}, report, fact, bundles); err == nil {
				t.Fatal("missing member passed")
			}
			for _, mutation := range []string{"stale", "future", "zero", "wrong-tenant", "wrong-authority", "old-serial", "old-profile-pin"} {
				if (kind == "device" && mutation == "old-serial") || (kind != "interception" && mutation == "old-profile-pin") {
					continue
				}
				t.Run(mutation, func(t *testing.T) {
					r, f := report, fact
					switch mutation {
					case "stale":
						r.ReportedAt = now.Add(-6 * time.Minute)
						f.LastSeenAt = r.ReportedAt.Format(time.RFC3339)
					case "future":
						r.ReportedAt = now.Add(time.Minute)
						f.LastSeenAt = r.ReportedAt.Format(time.RFC3339)
					case "zero":
						r.AdoptedTrustSerial = 0
						f.LastSeenAt = ""
					case "wrong-tenant":
						r.TenantID = "tenant_b"
						f.TenantID = "tenant_b"
					case "wrong-authority":
						r.PinnedTransportCASHA256 = nil
						r.PinnedInterceptionRootSHA256 = nil
						f.AnchorSHA256 = "other"
					case "old-serial":
						r.AdoptedTrustSerial = 8
					case "old-profile-pin":
						r.InterceptionRootPinSHA256 = roots[0]
					}
					if err := check([]string{"mac"}, r, f, bundles); err == nil {
						t.Fatal("bad evidence passed")
					}
				})
			}
			for _, mutation := range []string{"serial", "tenant", "missing-root"} {
				if kind == "device" && mutation == "missing-root" {
					continue
				}
				b := append([]agentpolicy.TrustBundlePayload(nil), bundles...)
				switch mutation {
				case "serial":
					b[2].Serial = 8
				case "tenant":
					b[2].TenantID = "tenant_b"
				case "missing-root":
					b[2].TransportCAPEM = ""
					b[2].InterceptionRootSHA256 = nil
				}
				if err := check([]string{"mac"}, report, fact, b); err == nil {
					t.Fatalf("region %s divergence passed", mutation)
				}
			}
			// Device certificates, including connector certificates, are measured from verified handshakes.
			if kind == "device" {
				if err := check([]string{"mac"}, observedExclusionEntry{}, fact, bundles); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestPKIPopulationRequiresTenantAndKeepsServiceCertificates(t *testing.T) {
	entries := []enrolledinventory.Entry{{Identity: "mac", TenantID: "tenant_a", Enabled: true}, {Identity: "connector", TenantID: "tenant_a", Kind: enrolledinventory.KindService, Enabled: true}, {Identity: "other", TenantID: "tenant_b", Enabled: true}}
	for _, kind := range []string{"transport", "interception", "device"} {
		c := pkiAuthorityTransition{Tenant: "tenant_a", Kind: kind}
		pop, err := pkiTransitionPopulation(serverConfig{}, c, entries)
		want := 1
		if kind == "device" {
			want = 2
		}
		if err != nil || len(pop) != want {
			t.Fatalf("%s population %v: %v", kind, pop, err)
		}
		unknown := append(append([]enrolledinventory.Entry(nil), entries...), enrolledinventory.Entry{Identity: "unassigned", Enabled: true})
		if _, err := pkiTransitionPopulation(serverConfig{}, c, unknown); err == nil {
			t.Fatal("unattributed member ignored")
		}
	}
}

func TestPKIRegionProbeVerifiesServingCAAndSignedTenantBundle(t *testing.T) {
	tr, _, _ := pkiTestAuthorities(t)
	material, err := tr.IssueAllFor("tenant_a", "edge", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := agentpolicy.LoadOrGenerateSigner(filepath.Join(t.TempDir(), "signer.key"), true)
	if err != nil {
		t.Fatal(err)
	}
	payload := agentpolicy.TrustBundlePayload{TenantID: "tenant_a", Serial: 9, TransportCAPEM: material[1].AnchorPEM, TransportServerName: material[1].ServerName}
	envelope, err := signer.SignTrustBundlePayload(payload, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/bootstrap/trust-bundle" || r.URL.Query().Get("tenant") != "tenant_a" {
			t.Error("unexpected probe path")
		}
		_ = json.NewEncoder(w).Encode(envelope)
	}))
	pair, err := tls.X509KeyPair([]byte(material[1].CertPEM), []byte(material[1].KeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	server.StartTLS()
	defer server.Close()
	region := regionEndpoint{Region: "east", Endpoint: server.URL}
	probe := func(roots, name, key string) error {
		_, err := probePKIRegionTrust(context.Background(), region, "tenant_a", name, roots, key)
		return err
	}
	if err := probe(material[1].AnchorPEM, material[1].ServerName, signer.PublicKeyHex()); err != nil {
		t.Fatal(err)
	}
	if err := probe(material[0].AnchorPEM, material[1].ServerName, signer.PublicKeyHex()); err == nil {
		t.Fatal("old CA accepted new serving certificate")
	}
	if err := probe(material[1].AnchorPEM, "wrong.dsse.invalid", signer.PublicKeyHex()); err == nil {
		t.Fatal("wrong SNI passed")
	}
	if err := probe(material[1].AnchorPEM, material[1].ServerName, strings.Repeat("0", 64)); err == nil {
		t.Fatal("wrong signature key passed")
	}
	payload.TenantID = "tenant_b"
	envelope, err = signer.SignTrustBundlePayload(payload, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := probe(material[1].AnchorPEM, material[1].ServerName, signer.PublicKeyHex()); err == nil {
		t.Fatal("another tenant's signed bundle passed")
	}
}

func TestPKIFleetRequiresEveryConfiguredRegion(t *testing.T) {
	now := time.Now()
	store := newFleetConfigStatusStore(time.Second)
	store.authoritySince = now.Add(-time.Hour)
	regions := []regionEndpoint{{Region: "east"}, {Region: "west"}, {Region: "osaka"}}
	for _, r := range regions {
		store.Record(fleetConfigReport{RegionID: r.Region, NodeID: r.Region + "-1", HaveApplied: true}, now)
	}
	if _, err := pkiSingleNodeMembership(store, regions, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pkiSingleNodeMembership(store, regions, now.Add(time.Minute)); err == nil {
		t.Fatal("stale fleet passed")
	}
	store.Record(fleetConfigReport{RegionID: "east", NodeID: "east-2", HaveApplied: true}, now)
	if _, err := pkiSingleNodeMembership(store, regions, now); err == nil {
		t.Fatal("multi-node region hidden behind one endpoint")
	}
}

func TestPKIAdmissionUsesSharedPopulationAndAdoption(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS cp_state_blobs (store_key text PRIMARY KEY,payload bytea NOT NULL,updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	for _, schema := range [][]string{postgresObservedExclusionSchemaSQL(), postgresObservedTrustTelemetrySchemaSQL(), postgresObservedRecoveryNameSchemaSQL(), postgresObservedRecoveryTargetSchemaSQL(), postgresObservedInterceptionRefusalsSchemaSQL(), postgresObservedAgentPolicyKeysSchemaSQL()} {
		for _, statement := range schema {
			if _, err := db.Exec(statement); err != nil {
				t.Fatal(err)
			}
		}
	}
	key := fmt.Sprintf("test_pki_population_%d", time.Now().UnixNano())
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key)
	store := postgresBlobPersister{db: db, key: key}
	ledger := enrolledinventory.NewLedger()
	if err := ledger.SetPersisterChecked(store); err != nil {
		t.Fatal(err)
	}
	tenant := fmt.Sprintf("tenant_pki_%d", time.Now().UnixNano())
	if _, err := ledger.Enroll("mac", tenant, "", time.Now().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	initial, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	tr := newTenantTransportAuthority(nil, nil, time.Now)
	if _, err := tr.EnsureCA(tenant, "a.dsse.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.RotateCA(tenant); err != nil {
		t.Fatal(err)
	}
	change := pkiAuthorityTransition{Kind: "transport", Action: "retire-previous", Tenant: tenant, TransportBefore: copyAuthority(tr.cas[tenant]), TransportAfter: copyAuthority(tr.cas[tenant].Incoming)}
	signer, err := agentpolicy.LoadOrGenerateSigner(filepath.Join(t.TempDir(), "signer.key"), true)
	if err != nil {
		t.Fatal(err)
	}
	observed := &postgresObservedExclusionStore{db: db}
	defer db.Exec("DELETE FROM observed_steer_exclusions WHERE tenant_id=$1", tenant)
	observed.Record(observedExclusionEntry{TenantID: tenant, DeviceIdentity: "mac", ReportedAt: time.Now(), AdoptedTrustSerial: 9, PinnedTransportCASHA256: []string{fingerprintOfFirstCert(change.TransportAfter.CACertPEM)}})
	catalog, err := parseRegionEndpoints("east=https://east.invalid;west=https://west.invalid;osaka=https://osaka.invalid")
	if err != nil {
		t.Fatal(err)
	}
	previous := regionMap.Catalog()
	regionMap.Set(catalog)
	defer regionMap.Set(previous)
	fleet := newFleetConfigStatusStore(time.Second)
	fleet.authoritySince = time.Now().Add(-time.Hour)
	for _, r := range catalog.allowedRegionEndpoints(nil, "") {
		fleet.Record(fleetConfigReport{RegionID: r.Region, NodeID: r.Region + "-1", HaveApplied: true}, time.Now())
	}
	config := serverConfig{AgentPolicySigner: signer, EnrolledLedger: ledger, ObservedExclusions: observed, FleetConfigStatus: fleet, RegionEndpoints: catalog}
	count := 0
	mode := "ready"
	probe := func(_ context.Context, r regionEndpoint, gotTenant, name, roots, publicKey string) (agentpolicy.TrustBundlePayload, error) {
		count++
		if roots != change.TransportAfter.CACertPEM || publicKey != signer.PublicKeyHex() || name != "a.dsse.invalid" || gotTenant != tenant {
			t.Fatal("probe not bound to retained authority")
		}
		if mode == "old-region" && r.Region == "osaka" {
			return agentpolicy.TrustBundlePayload{}, errors.New("TLS verification failed")
		}
		if mode == "population-changed" && count == 1 {
			if _, err := ledger.Enroll("windows", tenant, "", time.Now().Format(time.RFC3339)); err != nil {
				t.Fatal(err)
			}
		}
		return agentpolicy.TrustBundlePayload{TenantID: tenant, Serial: 9, TransportCAPEM: roots, TransportServerName: name}, nil
	}
	gate := newPKITransitionAdmissionWithProbe(config, probe)
	if err := gate(change); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("probed %d regions", count)
	}
	mode = "old-region"
	count = 0
	if err := gate(change); err == nil {
		t.Fatal("unverified region admitted")
	}
	mode = "population-changed"
	count = 0
	if err := gate(change); err == nil {
		t.Fatal("population changed during judgement")
	}
	if err := store.Save(initial); err != nil {
		t.Fatal(err)
	}
	mode = "ready"
	count = 0
	if err := gate(change); err != nil {
		t.Fatalf("must use restored shared population, not local windows cache: %v", err)
	}
	if _, err := db.Exec("UPDATE observed_steer_exclusions SET adopted_trust_serial=0 WHERE tenant_id=$1", tenant); err != nil {
		t.Fatal(err)
	}
	if err := gate(change); err == nil {
		t.Fatal("zero serial in shared DB passed")
	}
	// A missing population row and a failed adoption connection are both unavailable, never empty success.
	if err := store.Save([]byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := gate(change); err == nil {
		t.Fatal("corrupt shared inventory passed")
	}
	if err := store.Save(initial); err != nil {
		t.Fatal(err)
	}
	other, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	other.Close()
	config.ObservedExclusions = &postgresObservedExclusionStore{db: other}
	if err := newPKITransitionAdmissionWithProbe(config, probe)(change); err == nil {
		t.Fatal("unavailable adoption source passed")
	}
}

// A slow regional probe must not suspend issuance for every tenant. Mutations
// during that probe invalidate its snapshot even when they concern another tenant.
func TestPKIAdmissionDoesNotHoldIssuanceLockDuringEvidence(t *testing.T) {
	for _, kind := range []string{"transport", "device", "interception"} {
		t.Run(kind, func(t *testing.T) {
			tr, de, in := pkiTestAuthorities(t)
			entered, release := make(chan struct{}), make(chan struct{})
			gate := []pkiTransitionAdmission{func(pkiAuthorityTransition) error {
				close(entered)
				<-release
				return nil
			}}
			done := make(chan error, 1)
			go func() {
				var err error
				switch kind {
				case "transport":
					_, err = tr.admitTransition("tenant_a", "retire-previous", gate, (*tenantTransportAuthority).RetirePrevious)
				case "device":
					_, err = de.admitTransition("tenant_a", "retire-previous", gate, (*tenantDeviceAuthority).RetirePrevious)
				case "interception":
					_, err = in.admitTransition("tenant_a", "promote", gate, (*tenantInterceptionAuthority).Promote)
				}
				done <- err
			}()
			<-entered
			issued := make(chan error, 1)
			go func() {
				var err error
				switch kind {
				case "transport":
					_, err = tr.IssueAllFor("tenant_a", "edge", time.Hour)
				case "device":
					_, err = de.IssueFor("tenant_a", time.Hour)
				case "interception":
					_, err = in.IssueFor("tenant_a", "edge", time.Hour)
				}
				issued <- err
			}()
			select {
			case err := <-issued:
				if err != nil {
					t.Error(err)
				}
			case <-time.After(2 * time.Second):
				t.Error("regional probe blocked certificate issuance")
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}
