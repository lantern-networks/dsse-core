package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/tenantca"
)

// A real CA certificate, because the registry parses what it is given and a stub would test the stub.
func makeBundleTestCA(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func registryWith(t *testing.T, entries map[string][][]byte) *tenantca.TenantCARegistry {
	t.Helper()
	reg := tenantca.NewTenantCARegistry()
	for tenant, cas := range entries {
		for _, ca := range cas {
			if _, err := reg.Register(tenant, ca); err != nil {
				t.Fatalf("register %s: %v", tenant, err)
			}
		}
	}
	return reg
}

func TestAnEdgeAdoptsTheControlPlanesDeviceCAs(t *testing.T) {
	caA1, caA2 := makeBundleTestCA(t, "org-a-1"), makeBundleTestCA(t, "org-a-2")
	cp := registryWith(t, map[string][][]byte{"tenant_a": {caA1, caA2}})
	edge := registryWith(t, map[string][][]byte{"tenant_a": {caA1}})

	section := deviceCABundleSection(cp, nil)
	if section == nil || !section.Complete {
		t.Fatal("a control plane holding a registry published no complete section")
	}
	added, removed := applyDeviceCABundleSection(edge, section, nil, nil)
	if added != 1 {
		t.Fatalf("added=%d, want 1: a device CA registered on the control plane never reached the Edge", added)
	}
	if removed != 0 {
		t.Fatalf("removed=%d, want 0", removed)
	}
	if got := edge.Registrations()["tenant_a"]; got != 2 {
		t.Fatalf("the Edge holds %d CA(s) for tenant_a, want 2", got)
	}
}

// A CA the control plane no longer holds stops admitting that organization's devices on the Edge too — but
// only for an organization the section actually named.
func TestARetiredDeviceCAIsRemovedWhereTheSectionNamesTheOrganization(t *testing.T) {
	caA1, caA2 := makeBundleTestCA(t, "org-a-1"), makeBundleTestCA(t, "org-a-2")
	cp := registryWith(t, map[string][][]byte{"tenant_a": {caA1}})
	edge := registryWith(t, map[string][][]byte{"tenant_a": {caA1, caA2}})

	_, removed := applyDeviceCABundleSection(edge, deviceCABundleSection(cp, nil), nil, nil)
	if removed != 1 {
		t.Fatalf("removed=%d, want 1: a CA retired on the control plane still admits that organization here", removed)
	}
	if got := edge.Registrations()["tenant_a"]; got != 1 {
		t.Fatalf("the Edge holds %d CA(s), want 1", got)
	}
}

// ★★★ THE ONE THAT PREVENTS AN OUTAGE. An organization's LAST anchor is not removed by a config poll: with
// none registered, every one of its devices is refused at the handshake. Retiring the last authority is a
// decision and travels as a withdrawal.
func TestTheLastDeviceCAOfAnOrganizationIsNotRemovedByABundle(t *testing.T) {
	caA := makeBundleTestCA(t, "org-a-1")
	caB := makeBundleTestCA(t, "org-b-1")
	// The control plane knows tenant_a exists but holds no CA for it — the shape a half-migrated deployment has.
	cp := registryWith(t, map[string][][]byte{"tenant_b": {caB}})
	edge := registryWith(t, map[string][][]byte{"tenant_a": {caA}, "tenant_b": {caB}})

	section := deviceCABundleSection(cp, nil)
	section.Tenants = append(section.Tenants, "tenant_a") // the control plane speaks for it, and holds none
	_, removed := applyDeviceCABundleSection(edge, section, nil, nil)

	if removed != 0 {
		t.Fatalf("removed=%d: the organization's last CA was withdrawn by a config poll — every one of its "+
			"devices is now refused at the handshake", removed)
	}
	if got := edge.Registrations()["tenant_a"]; got != 1 {
		t.Fatalf("tenant_a holds %d CA(s), want 1 — its devices are locked out", got)
	}
}

// ★★★ AND AN EMPTY SECTION REMOVES NOTHING AT ALL. This reverses the Site catalogue's rule, because what
// "empty" costs is the opposite: an empty Site catalogue refuses new connectors, an empty device-CA registry
// refuses every device of every organization. A control plane that was never given a registry publishes empty
// — and this deployment had exactly that shape.
func TestAnEmptyOrIncompleteDeviceCASectionRemovesNothing(t *testing.T) {
	// ★ TWO CAs, deliberately. With one, the last-anchor guard would refuse the removal and this test would
	// pass whatever the empty rule did — which is exactly what it did when first written: planting the fault
	// changed nothing, because a different guard was doing the work. A test masked by another rule measures
	// that rule.
	caA1, caA2 := makeBundleTestCA(t, "org-a-1"), makeBundleTestCA(t, "org-a-2")
	for _, tc := range []struct {
		name    string
		section *deviceCARegistryBundle
	}{
		{"empty", &deviceCARegistryBundle{Snapshot: []byte(`{"tenants":[]}`), Tenants: []string{}, Complete: true}},
		// ★ THE DANGEROUS ONE: the section NAMES the organization and carries nothing for it — the shape a
		// half-migrated control plane has. Read as "it has none", every anchor goes and every device is refused.
		{"names the organization, carries nothing", &deviceCARegistryBundle{
			Snapshot: []byte(`{"tenants":[]}`), Tenants: []string{"tenant_a"}, Complete: true}},
		{"incomplete", &deviceCARegistryBundle{Snapshot: []byte(`{"tenants":[]}`), Tenants: []string{"tenant_a"}, Complete: false}},
		{"absent", nil},
	} {
		edge := registryWith(t, map[string][][]byte{"tenant_a": {caA1, caA2}})
		if _, removed := applyDeviceCABundleSection(edge, tc.section, nil, nil); removed != 0 {
			t.Fatalf("%s: removed %d — the fleet would stop admitting devices", tc.name, removed)
		}
		if got := edge.Registrations()["tenant_a"]; got != 2 {
			t.Fatalf("%s: tenant_a holds %d CA(s), want 2", tc.name, got)
		}
	}
}

// An organization the section never named is left exactly as it is.
func TestAnOrganizationTheDeviceCASectionDidNotNameIsUntouched(t *testing.T) {
	// Two CAs for the unmentioned organization, so the last-anchor guard is not what keeps them — see the note
	// in the empty-section test above.
	caA := makeBundleTestCA(t, "org-a-1")
	caB1, caB2 := makeBundleTestCA(t, "org-b-1"), makeBundleTestCA(t, "org-b-2")
	cp := registryWith(t, map[string][][]byte{"tenant_a": {caA}})
	edge := registryWith(t, map[string][][]byte{"tenant_a": {caA}, "tenant_b": {caB1, caB2}})

	applyDeviceCABundleSection(edge, deviceCABundleSection(cp, nil), nil, nil)
	if got := edge.Registrations()["tenant_b"]; got != 2 {
		t.Fatalf("tenant_b holds %d CA(s), want 2: an organization the section never named lost its identity basis", got)
	}
}

// A node holding no registry is not the authority and must not publish a section claiming it is.
func TestANodeWithNoRegistryPublishesNoDeviceCASection(t *testing.T) {
	if deviceCABundleSection(nil, nil) != nil {
		t.Fatal("a node holding no device-CA registry published a section")
	}
}

// ★★★ THE GENERATION, and the sum, and the apply. Three separate things, and a section can be perfect at all
// but one and still never travel.
func TestRegisteringADeviceCAChangesTheRegistrysGeneration(t *testing.T) {
	reg := tenantca.NewTenantCARegistry()
	start := reg.ConfigGeneration()
	if _, err := reg.Register("tenant_a", makeBundleTestCA(t, "org-a-1")); err != nil {
		t.Fatalf("register: %v", err)
	}
	if after := reg.ConfigGeneration(); after <= start {
		t.Fatalf("generation stayed at %d: registering a device CA changes the bundle's contents and not its "+
			"version, so no Edge re-pulls", after)
	}
}

func TestTheBundlePublishesAppliesAndCountsTheDeviceCAs(t *testing.T) {
	pub := readSourceFile(t, "admin_policy_routes.go")
	if !strings.Contains(pub, "deviceCABundleSection(") {
		t.Fatal("the config bundle never builds a device-CA section: the registry stays authored on the Edges")
	}
	if !strings.Contains(pub, "+ deviceCAGen") {
		t.Fatal("the registry's generation is not added to the bundle's aggregate: the section would be " +
			"published in every bundle and applied by nobody")
	}
	if !strings.Contains(readSourceFile(t, "config_bundle_sync.go"), "applyDeviceCABundleSection(") {
		t.Fatal("the Edge never applies the device-CA section")
	}
}

// ★★★ ATTRIBUTION AND TRUST ARE TWO HALVES, AND THE BUNDLE HAS TO DO BOTH (2026-08-23, found by the withdrawal
// gate refusing on exactly this ground). The registry answers "whose device is this"; what a handshake verifies
// against is a SEPARATE pool. Removing only the attribution reports a rotation that did not happen — the CA
// goes on admitting devices while every screen says it was retired.
func TestTheBundleTakesARemovedCAOutOfTheTrustSetToo(t *testing.T) {
	src := readSourceFile(t, "config_bundle_device_cas.go")
	if !strings.Contains(src, "trustAnchorStoreOrNil(deviceClientCAs)") {
		t.Fatal("the bundle apply removes a CA from the registry and leaves it in the device trust set: it " +
			"would keep admitting devices while the fleet reports it retired")
	}
	if !strings.Contains(src, "trust.Reapply()") {
		t.Fatal("the trust set is changed and the pool a handshake reads is never rebuilt, so the removal is " +
			"not served — the same order the withdrawal route follows for the same reason")
	}
}

// And a control plane, which terminates no device handshakes, may still withdraw: both halves happen on the
// Edges when they apply the bundle.
func TestAControlPlaneMayWithdrawADeviceCAWithoutATrustPool(t *testing.T) {
	src := readSourceFile(t, "admin_tenant_ca_routes.go")
	i := strings.Index(src, "no runtime device-trust store, so this CA cannot be stopped")
	if i < 0 {
		t.Fatal("the withdrawal route no longer refuses a node that cannot stop the CA — that rule must stay")
	}
	window := src[max(0, i-900):i]
	if !strings.Contains(window, "edgeIsControlPlane") {
		t.Fatal("a control plane is still refused: the node that authors the registry cannot retract what it " +
			"registered, and the authority for device CAs stays conditional on also being an enforcement node")
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
