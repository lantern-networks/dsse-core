package main

import (
	"bytes"
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
	"github.com/lantern-networks/dsse-core/tenantca"
)

func TestDeviceAdmissionMaterialFollowsDurableBYORegistrationAndWithdrawal(t *testing.T) {
	previous := tenantCARegistryShared
	backend := &authorityMemoryCAS{}
	tenantCARegistryShared = backend
	t.Cleanup(func() { tenantCARegistryShared = previous })
	tr := newTenantTransportAuthority(nil, nil, time.Now)
	de := newTenantDeviceAuthority(nil, nil, time.Now)
	if _, err := tr.EnsureCA("tenant_a", "a.dsse.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := de.EnsureCA("tenant_a", "a"); err != nil {
		t.Fatal(err)
	}
	byo, byoPEM, _ := deviceAdmissionTestCA(t, "a BYO")
	reg := tenantca.NewTenantCARegistry()
	if _, err := reg.Register("tenant_a", byoPEM); err != nil {
		t.Fatal(err)
	}
	backend.data, _ = reg.Snapshot()
	// The local CP cache deliberately has no registration; only durable state
	// determines publication, including after a leadership change.
	mux := http.NewServeMux()
	registerTenantTransportMaterialRoute(mux, tr, nil, de, "test-token", time.Hour, tenantca.NewTenantCARegistry(), true)
	type answer struct {
		Generation uint64                 `json:"generation"`
		Unchanged  bool                   `json:"unchanged"`
		Device     []tenantDeviceMaterial `json:"device_identity"`
	}
	ask := func(g uint64, status int) answer {
		t.Helper()
		req := httptest.NewRequest("POST", "/tenant-edge-material", strings.NewReader(fmt.Sprintf(`{"tenants":["tenant_a"],"known_generation":%d}`, g)))
		req.Header.Set("Authorization", "Bearer test-token")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != status {
			t.Fatalf("HTTP %d, wanted %d", w.Code, status)
		}
		var out answer
		if status == 200 {
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
		}
		return out
	}
	first := ask(0, 200)
	if len(first.Device) != 1 || !first.Device[0].AdmissionComplete || !strings.Contains(first.Device[0].AdmissionCAPEM, string(byoPEM)) {
		t.Fatal("registered BYO CA did not reach material")
	}
	if !ask(first.Generation, 200).Unchanged {
		t.Fatal("identical admission set did not reuse generation")
	}
	// A registration-only change must invalidate unchanged without waiting for
	// the managed CA or leaf renewal timer to move.
	if ok, _ := reg.WithdrawAnchor("tenant_a", certFingerprint(byo)); !ok {
		t.Fatal("BYO withdrawal failed")
	}
	backend.data, _ = reg.Snapshot()
	next := ask(first.Generation, 200)
	if next.Unchanged || next.Generation == first.Generation || len(next.Device) != 1 || strings.Contains(next.Device[0].AdmissionCAPEM, string(byoPEM)) {
		t.Fatal("BYO withdrawal was hidden by unchanged or resurrected from local cache")
	}
	backend.readErr = errors.New("database unavailable")
	ask(next.Generation, 503)
	backend.readErr = nil
	for _, broken := range []string{"null", "{}", `{"tenants":null}`, `{"tenants":[{"tenant_id":"tenant_a","ca_pem":"broken"}]}`} {
		backend.data = []byte(broken)
		ask(next.Generation, 503)
	}
}

func TestPKIDeviceGateRetainsBYOButNeverAnExplicitlyRegisteredRetiredManagedCA(t *testing.T) {
	_, de, _ := pkiTestAuthorities(t)
	before := copyAuthority(de.cas["tenant_a"])
	if _, err := de.RetirePrevious("tenant_a"); err != nil {
		t.Fatal(err)
	}
	after := copyAuthority(de.cas["tenant_a"])
	byo, byoPEM, _ := deviceAdmissionTestCA(t, "independent BYO")
	registrations := deviceCARegistrationSnapshot{"tenant_a": before.CACertPEM + string(byoPEM)}
	change := pkiAuthorityTransition{Kind: "device", Action: "retire-previous", Tenant: "tenant_a", DeviceBefore: before, DeviceAfter: after, DeviceAdmissionCAPEM: deviceAdmissionAnchors(after, registrations)}
	now := time.Now().UTC().Truncate(time.Second).Add(time.Second)
	bundle := agentpolicy.TrustBundlePayload{TenantID: "tenant_a", Serial: 1}
	fact := deviceCertificateFact{TenantID: "tenant_a", Identity: "byo-device", AnchorSHA256: certFingerprint(byo), LastSeenAt: now.Format(time.RFC3339), NotAfter: now.Add(time.Hour).Format(time.RFC3339)}
	check := func() error {
		return checkPKITransitionEvidence(change, []string{"byo-device"}, nil, []deviceCertificateFact{fact}, []agentpolicy.TrustBundlePayload{bundle}, now)
	}
	if err := check(); err != nil {
		t.Fatal("unaffected registered BYO device blocked retirement", err)
	}
	fact.AnchorSHA256 = fingerprintOfFirstCert(before.CACertPEM)
	if err := check(); err == nil {
		t.Fatal("old managed CA registration bypassed retirement")
	}
	fact.AnchorSHA256 = certFingerprint(byo)
	change.DeviceAdmissionCAPEM = deviceAdmissionAnchors(after, nil)
	if err := check(); err == nil {
		t.Fatal("unregistered BYO device bypassed readiness")
	}
}

func TestDeviceRetirementHistorySurvivesRestartAndExcludesRegisteredOldManagedCA(t *testing.T) {
	for _, abandon := range []bool{false, true} {
		t.Run(fmt.Sprint("abandoned=", abandon), func(t *testing.T) {
			var saved []byte
			a := newTenantDeviceAuthority(nil, func(b []byte) error { saved = append([]byte(nil), b...); return nil }, time.Now)
			old, err := a.EnsureCA("tenant_a", "a")
			if err != nil {
				t.Fatal(err)
			}
			incoming, err := a.RotateCA("tenant_a")
			if err != nil {
				t.Fatal(err)
			}
			_, byoPEM, _ := deviceAdmissionTestCA(t, "a independent BYO")
			registrations := deviceCARegistrationSnapshot{"tenant_a": old.CACertPEM + incoming.CACertPEM + string(byoPEM)}
			retiring := old.CACertPEM
			if abandon {
				if _, err := a.AbandonRotation("tenant_a"); err != nil {
					t.Fatal(err)
				}
				retiring = incoming.CACertPEM
			}
			if _, err := a.RetirePrevious("tenant_a"); err != nil {
				t.Fatal(err)
			}
			a = newTenantDeviceAuthority(saved, nil, time.Now)
			admitted := deviceAdmissionAnchors(a.cas["tenant_a"], registrations)
			if strings.Contains(admitted, strings.TrimSpace(retiring)) || !strings.Contains(admitted, string(byoPEM)) {
				t.Fatal("restart resurrected retired managed CA or erased independent BYO")
			}
			// A second rotation must carry the first retirement's tombstone forward.
			if _, err := a.RotateCA("tenant_a"); err != nil {
				t.Fatal(err)
			}
			if _, err := a.RetirePrevious("tenant_a"); err != nil {
				t.Fatal(err)
			}
			if len(a.cas["tenant_a"].RetiredAnchorSHA256) != 2 {
				t.Fatal("later promotion forgot previous retirement")
			}
		})
	}
}

func TestDeviceMaterialMissingAdmissionSnapshotKeepsLiveTrust(t *testing.T) {
	isolatedDeviceAuthorityPools(t)
	reg := tenantca.NewTenantCARegistry()
	ca, pem, key := deviceAdmissionTestCA(t, "a")
	mat := deviceMaterialForCA(t, "tenant_a", ca, key, string(pem))
	if err := tenantDeviceIdentity.Install(mat, reg, nil); err != nil {
		t.Fatal(err)
	}
	before, _ := reg.Snapshot()
	for _, bad := range []tenantDeviceMaterial{
		{TenantID: mat.TenantID, CACertPEM: mat.CACertPEM, CAKeyPEM: mat.CAKeyPEM, AnchorPEM: mat.AnchorPEM},
		{TenantID: mat.TenantID, CACertPEM: mat.CACertPEM, CAKeyPEM: mat.CAKeyPEM, AnchorPEM: mat.AnchorPEM, AdmissionComplete: true},
	} {
		if err := tenantDeviceIdentity.Install(bad, reg, nil); err == nil {
			t.Fatal("incomplete admission material was accepted")
		}
		after, _ := reg.Snapshot()
		if string(after) != string(before) {
			t.Fatal("refused material changed live trust")
		}
	}
}

func TestBYOWithdrawalCountsManagedAdmissionAndRefusesUnknownManagedState(t *testing.T) {
	a := newTenantDeviceAuthority(nil, nil, time.Now)
	row, err := a.EnsureCA("tenant_a", "a")
	if err != nil {
		t.Fatal(err)
	}
	config := serverConfig{TenantDeviceAuthority: a}
	byo, _, _ := deviceAdmissionTestCA(t, "BYO")
	if v := deviceCAWithdrawalGate(config, "tenant_a", certFingerprint(byo), 0); !v.Allowed {
		t.Fatal("last imported CA confused with last admitted CA", v.Text)
	}
	if v := deviceCAWithdrawalGate(config, "tenant_a", fingerprintOfFirstCert(row.CACertPEM), 1); v.Allowed {
		t.Fatal("registration removal falsely claimed to withdraw an active managed CA")
	}
	a.reload = func() ([]byte, error) { return nil, errors.New("unavailable") }
	if v := deviceCAWithdrawalGate(config, "tenant_a", certFingerprint(byo), 1); v.Allowed {
		t.Fatal("unknown managed state allowed withdrawal")
	}
}

func TestManagedDeviceScopeIsDeclaredBeforeMaterialAndAdvancesAfterAnotherCPWrite(t *testing.T) {
	b := &authorityMemoryCAS{}
	writer := authorityClient(t, "device", b)
	p := protectPKIAuthorityPersister(b, "tenant_device_authorities")
	seed, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	reader := newTenantDeviceAuthorityWithReload(seed, p.Save, p.Load, time.Now)
	first := reader.Generation()
	if err := writer.create("tenant_a"); err != nil {
		t.Fatal(err)
	}
	// Issuance can discover the shared write before the config generation read.
	if _, err := reader.materialSnapshot(); err != nil {
		t.Fatal(err)
	}
	section := deviceCABundleSection(tenantca.NewTenantCARegistry(), reader)
	if !section.Complete || !section.ManagedComplete || len(section.ManagedTenants) != 1 || section.ManagedTenants[0] != "tenant_a" {
		t.Fatal("CP did not declare managed scope")
	}
	if reader.Generation() <= first {
		t.Fatal("managed scope change did not advance config generation")
	}
	b.readErr = errors.New("unavailable")
	section = deviceCABundleSection(tenantca.NewTenantCARegistry(), reader)
	if section.Complete || section.ManagedComplete {
		t.Fatal("unreadable managed scope was published as an empty complete set")
	}
}

func TestSharedDeviceCARegistryBootstrapNeverResurrectsWithdrawnAnchors(t *testing.T) {
	_, pem, _ := deviceAdmissionTestCA(t, "bootstrap")
	reg := tenantca.NewTenantCARegistry()
	if _, err := reg.Register("tenant_a", pem); err != nil {
		t.Fatal(err)
	}
	seed, err := reg.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(path, seed, 0600); err != nil {
		t.Fatal(err)
	}
	backend := &authorityMemoryCAS{}
	if err := initializeSharedDeviceCARegistry(backend, path); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backend.data, seed) {
		t.Fatal("initial snapshot lost")
	}
	withdrawn := []byte(`{"tenants":[]}`)
	backend.data = withdrawn
	// An old seed remains on disk after withdrawal and after a CP restart.
	if err := initializeSharedDeviceCARegistry(backend, path); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backend.data, withdrawn) {
		t.Fatal("withdrawn CA resurrected")
	}
	// Another CP wins initial publication while this CP is reading the seed.
	backend.data = nil
	backend.beforeSave = func() { backend.data = withdrawn }
	if err := initializeSharedDeviceCARegistry(backend, path); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backend.data, withdrawn) {
		t.Fatal("racing winner overwritten")
	}
	// An initialized store no longer depends on the bootstrap file being present.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := initializeSharedDeviceCARegistry(backend, path); err != nil {
		t.Fatal(err)
	}
}

func TestSharedDeviceCARegistryBootstrapFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.json")
	for _, broken := range []string{"", "null", "{}", `{"tenants":[{"tenant_id":"tenant_a","ca_pem":"broken"}]}`} {
		if err := os.WriteFile(path, []byte(broken), 0600); err != nil {
			t.Fatal(err)
		}
		backend := &authorityMemoryCAS{}
		if err := initializeSharedDeviceCARegistry(backend, path); err == nil {
			t.Fatalf("accepted broken seed %q", broken)
		}
		if backend.data != nil {
			t.Fatal("invalid seed reached durable state")
		}
	}
	if err := os.WriteFile(path, []byte(`{"tenants":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, backend := range []*authorityMemoryCAS{
		{readErr: errors.New("database unavailable")},
		{writeErr: errors.New("database unavailable")},
	} {
		if err := initializeSharedDeviceCARegistry(backend, path); err == nil {
			t.Fatal("database error hidden")
		}
		if backend.data != nil {
			t.Fatal("failed bootstrap changed store")
		}
	}
}
