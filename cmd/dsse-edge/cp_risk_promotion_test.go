package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/revocation"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRiskStoreDefaultUsesSharedBackendWithoutRenamingLocalState(t *testing.T) {
	old := sharedStateDSNConfigured
	defer func() { sharedStateDSNConfigured = old }()
	sharedStateDSNConfigured = true
	dir := t.TempDir()
	got := durableStorePath(dir, "", "high_risk_devices")
	if got != "postgres" {
		t.Fatalf("fresh shared CP: %s", got)
	}
	e := newPromotionModelElector(&promotionLockModel{})
	defer e.db.Close()
	p, err := cpStateBlobPersister(got, e.db, "high_risk_overlay")
	if err != nil {
		t.Fatal(err)
	}
	pg, ok := p.(postgresBlobPersister)
	if !ok || pg.key != "high_risk_overlay" {
		t.Fatal("wrong shared row backend")
	}
	local := filepath.Join(dir, "high_risk_devices.json")
	if err := os.WriteFile(local, []byte("existing snapshot"), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	oldOutput := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(oldOutput)
	if got := durableStorePath(dir, "", "high_risk_devices"); got != local {
		t.Fatal("existing file was migrated implicitly")
	}
	if !strings.Contains(output.String(), "-high-risk-store=postgres+import:") {
		t.Fatal("migration names a nonexistent flag")
	}
	for _, explicit := range []string{"postgres", "postgres+import:" + local, "/explicit/risk.json"} {
		if got := durableStorePath(dir, explicit, "high_risk_devices"); got != explicit {
			t.Fatal("explicit override changed")
		}
	}
	sharedStateDSNConfigured = false
	if got := durableStorePath(dir, "", "high_risk_devices"); got != local {
		t.Fatal("edge no longer uses local state")
	}
	if durableStoreFlag("admission_revocations") != "admission-revocation" {
		t.Fatal("admission migration flag is invalid")
	}
}
func TestRiskPromotionLoadsDeviceAndUserChanges(t *testing.T) {
	oldCP, oldE := edgeIsControlPlane, cpLeaderElectorInstance
	defer func() { edgeIsControlPlane = oldCP; cpLeaderElectorInstance = oldE }()
	edgeIsControlPlane = true
	for _, backend := range []string{"postgres", "postgres+import:legacy.json"} {
		for _, kind := range []string{"device", "user"} {
			for _, initial := range []bool{false, true} {
				t.Run(backend+"/"+kind+map[bool]string{true: "/clear", false: "/raise"}[initial], func(t *testing.T) {
					cpLeaderElectorInstance = nil
					h, _, candidate, _, _, _ := deviceRiskAuditHandler(t)
					p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "risk.json")}
					a := revocation.NewHighRiskOverlay()
					if err := a.SetPersister(p); err != nil {
						t.Fatal(err)
					}
					if _, err := a.SetDeviceRisk("other-device", "high"); err != nil {
						t.Fatal(err)
					}
					set := func(sev string) {
						var err error
						if kind == "device" {
							_, err = a.SetDeviceRisk("owned-device", sev)
						} else {
							_, err = a.SetUserRisk(revocation.UserRisk{TenantID: "tenant_lab_001", ID: "person", Subjects: []string{"subject"}, Severity: sev})
						}
						if err != nil {
							t.Fatal(err)
						}
					}
					if initial {
						set("critical")
					}
					if err := candidate.SetPersister(p); err != nil {
						t.Fatal(err)
					}
					if initial {
						set("none")
					} else {
						set("critical")
					}
					e := newPromotionModelElector(&promotionLockModel{})
					defer func() { e.release(); e.db.Close() }()
					configureAdmissionPromotion(e, "postgres", revocation.NewAdmissionRevocations())
					configureRiskPromotion(e, backend, candidate)
					cpLeaderElectorInstance = e
					e.tick()
					if !e.IsLeader() {
						t.Fatal("not promoted")
					}
					r := promotionRead(h, "/admin/revocations")
					var feed revocationFeed
					if err := json.Unmarshal(r.Body.Bytes(), &feed); err != nil {
						t.Fatal(err)
					}
					got := false
					if kind == "device" {
						got = feed.HighRisk["owned-device"] == "critical"
					} else {
						for _, u := range feed.UserRisk {
							if u.ID == "person" {
								got = u.Severity == "critical"
							}
						}
					}
					if r.Code != 200 || !feed.Authoritative || got == initial || feed.HighRisk["other-device"] != "high" {
						t.Fatalf("stale promotion %+v", feed)
					}
					generation := candidate.ConfigGeneration()
					e.release()
					e.tick()
					if !e.IsLeader() || candidate.ConfigGeneration() != generation {
						t.Fatal("unchanged retry churned state")
					}
				})
			}
		}
	}
}
func TestRiskPromotionRequiresBothPreparedStores(t *testing.T) {
	for _, raw := range []string{"", `{"schema_version":"high_risk_overlay_state.v1","devices":{"ambiguous":"critical"}}`, `{"schema_version":"unknown","devices":{}}`} {
		t.Run(raw, func(t *testing.T) {
			p := blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "risk.json")}
			risk := revocation.NewHighRiskOverlay()
			risk.SetPersister(p)
			risk.SetDeviceRisk("keep", "high")
			os.WriteFile(p.Path, []byte(raw), 0600)
			e := newPromotionModelElector(&promotionLockModel{})
			defer func() { e.release(); e.db.Close() }()
			before := 0
			e.prepareLeadership = func() error { before++; return nil }
			configureRiskPromotion(e, "postgres", risk)
			e.tick()
			if before != 1 || e.IsLeader() || risk.Health() == nil {
				t.Fatal("failed risk refresh was accepted or replaced admission preparation")
			}
			if s, ok := risk.IsHighRisk("keep"); !ok || s != "high" {
				t.Fatal("failed risk refresh lost live data")
			}
			os.WriteFile(p.Path, []byte(`{"schema_version":"high_risk_overlay_state.v2","devices":{"fresh":"critical"}}`), 0600)
			e.tick()
			if before != 2 || !e.IsLeader() || risk.Health() != nil {
				t.Fatal("repair failed")
			}
		})
	}
	e := newPromotionModelElector(&promotionLockModel{})
	defer e.db.Close()
	calls := 0
	e.prepareLeadership = func() error { calls++; return errors.New("prior store unavailable") }
	risk := revocation.NewHighRiskOverlay()
	configureRiskPromotion(e, "postgres", risk)
	e.tick()
	if e.IsLeader() || calls != 1 {
		t.Fatal("previous preparation was skipped")
	}
}
func TestRiskPromotionStartupAndLocalBoundary(t *testing.T) {
	for _, backend := range []string{"", "memory", "local.json"} {
		e := newPromotionModelElector(&promotionLockModel{})
		configureRiskPromotion(e, backend, revocation.NewHighRiskOverlay())
		if e.prepareLeadership != nil {
			t.Fatal("local ownership changed")
		}
		e.db.Close()
	}
	b, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	start := strings.Index(s, "cpLeaderElectorInstance.Start()")
	migration := strings.Index(s, "prepareUserRiskState(context.Background(), highRiskOverlay,")
	attach := strings.Index(s, "configureRiskPromotion(cpLeaderElectorInstance,")
	if strings.Count(s, "cpLeaderElectorInstance.Start()") != 1 || migration < 0 || attach <= migration || start <= attach {
		t.Fatal("leadership can precede risk attribution/preparation")
	}
}

func TestRiskSharedDefaultPreservesExistingStateEntries(t *testing.T) {
	old := sharedStateDSNConfigured
	defer func() { sharedStateDSNConfigured = old }()
	sharedStateDSNConfigured = true
	for _, key := range []string{"high_risk_devices", "admission_revocations", "policy_rules"} {
		for _, kind := range []string{"missing", "empty-file", "directory", "dangling-link"} {
			t.Run(key+"/"+kind, func(t *testing.T) {
				dir := t.TempDir()
				path := filepath.Join(dir, key+".json")
				switch kind {
				case "empty-file":
					if err := os.WriteFile(path, []byte{}, 0600); err != nil {
						t.Fatal(err)
					}
				case "directory":
					if err := os.Mkdir(path, 0700); err != nil {
						t.Fatal(err)
					}
				case "dangling-link":
					if err := os.Symlink(filepath.Join(dir, "absent-target"), path); err != nil {
						t.Skipf("symlink unavailable: %v", err)
					}
				}
				want := path
				if kind == "missing" {
					want = "postgres"
				}
				if got := durableStorePath(dir, "", key); got != want {
					t.Fatalf("%s: selected %q, want %q", kind, got, want)
				}
			})
		}
	}
}
