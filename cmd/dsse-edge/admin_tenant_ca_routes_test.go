package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/tenantca"
)

// ★ THE SECOND OF THE TWO REMAINING BLOCKERS (2026-08-15). There was no API for the CA that identifies a
// tenant's devices: a startup flag pointing at a JSON file, read once. An organization created through the
// Console therefore had devices that could never be admitted, and /admin/tenant-cas answered 404. Measured
// while standing up a second tenant on the lab.
func TestRegisteringATenantCAMakesItTrustedAndAttributed(t *testing.T) {
	handler, registry, trust, path := tenantCARoutesForTest(t)
	caCert, caPEM := tenantCATestCA(t, "Northwind Device CA")

	body := map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(caPEM)}
	res := doTenantCARequest(t, handler, http.MethodPost, "/admin/tenant-cas", body)
	if res.Code != http.StatusCreated {
		t.Fatalf("register: HTTP %d — %s", res.Code, res.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(res.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["durable"] != true {
		t.Fatalf("a registration written to %q reported durable=%v", path, got["durable"])
	}

	// ATTRIBUTION: a chain anchored at that CA now resolves to the tenant.
	tenant, ok := registry.TenantForVerifiedChains([][]*x509.Certificate{{caCert}})
	if !ok || tenant != "tenant_northwind" {
		t.Fatalf("the CA resolves to %q/%v — the organization's devices would belong to nobody", tenant, ok)
	}
	// TRUST: the handshake would accept a certificate issued by it.
	if !trustStoreHolds(t, trust, caCert) {
		t.Fatal("the CA was attributed but not trusted, so that organization's devices cannot connect at all")
	}
}

// Half a registration is worse than none, so the failure has to say WHICH half happened. A CA already
// belonging to another organization is refused — it identifies every device already holding a certificate
// under it — but by then the trust half has been applied, and the response says so rather than reading as a
// clean rejection of a node whose state has changed.
func TestRegisteringACAOwnedByAnotherTenantSaysTheTrustHalfLanded(t *testing.T) {
	handler, _, _, _ := tenantCARoutesForTest(t)
	_, caPEM := tenantCATestCA(t, "Acme Device CA")

	first := doTenantCARequest(t, handler, http.MethodPost, "/admin/tenant-cas",
		map[string]string{"tenant_id": "tenant_acme", "ca_pem": string(caPEM)})
	if first.Code != http.StatusCreated {
		t.Fatalf("first register: HTTP %d — %s", first.Code, first.Body.String())
	}

	second := doTenantCARequest(t, handler, http.MethodPost, "/admin/tenant-cas",
		map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(caPEM)})
	if second.Code != http.StatusConflict {
		t.Fatalf("moving a CA between organizations returned HTTP %d, want 409", second.Code)
	}
	if !strings.Contains(second.Body.String(), "TRUSTED") {
		t.Fatalf("the refusal must say the trust half landed: %s", second.Body.String())
	}
}

// A CA for an organization nobody created would admit devices into a tenant no screen can show.
func TestRegisteringACAForAnUnknownTenantIsRefused(t *testing.T) {
	handler, _, _, _ := tenantCARoutesForTest(t)
	_, caPEM := tenantCATestCA(t, "Ghost Device CA")

	res := doTenantCARequest(t, handler, http.MethodPost, "/admin/tenant-cas",
		map[string]string{"tenant_id": "tenant_never_created", "ca_pem": string(caPEM)})
	if res.Code != http.StatusNotFound {
		t.Fatalf("HTTP %d, want 404 — %s", res.Code, res.Body.String())
	}
}

// tenantCAHarnessTenantStore is the tenant registry the most recent harness built, for the tests that must
// author an organization's own settings (the operator delegation) rather than reach them through a route.
// Set by the harness instead of widening its signature at twelve call sites.
var tenantCAHarnessTenantStore adminTenantModelAdminStore

// tenantCARoutesForTest builds a server whose tenant CA registry and device trust store are both real, with
// two organizations already in the tenant registry.
func tenantCARoutesForTest(t *testing.T, outboxes ...adminAuditOutboxDeadReader) (http.Handler, *tenantca.TenantCARegistry, *transportTrustStore, string) {
	t.Helper()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	now := time.Now().UTC()
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{
		ID: "adm_operator", TenantID: "tenant_lab_001", Subject: "sub_operator",
		Email: "operator@example.invalid", Roles: []string{"admin", "super_admin"}, IDPID: "keycloak_lab",
		Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	auth.UpsertAPIToken(adminAPIToken{
		ID: "tok_operator", TenantID: "tenant_lab_001", Name: "operator",
		TokenHash: adminTokenHash(testTenantCABearer), Roles: []string{"admin", "super_admin"}, Scopes: []string{"*"},
		CreatedByAdminPrincipalID: "adm_operator",
		CreatedAt:                 now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 now.Add(time.Hour).Format(time.RFC3339), Status: "active",
	})
	auth.UpsertPrincipal(adminPrincipal{
		ID: "adm_northwind", TenantID: "tenant_northwind", Subject: "sub_northwind",
		Email: "admin@northwind.invalid", Roles: []string{"admin"}, IDPID: "keycloak_lab",
		Status: "active", CreatedAt: now.Add(-time.Hour).Format(time.RFC3339),
	})
	auth.UpsertAPIToken(adminAPIToken{
		ID: "tok_northwind", TenantID: "tenant_northwind", Name: "northwind admin",
		TokenHash: adminTokenHash(testTenantCANorthwindBearer), Roles: []string{"admin"}, Scopes: []string{"*"},
		CreatedByAdminPrincipalID: "adm_northwind",
		CreatedAt:                 now.Add(-time.Hour).Format(time.RFC3339),
		ExpiresAt:                 now.Add(time.Hour).Format(time.RFC3339), Status: "active",
	})
	path := t.TempDir() + "/tenant_ca_registry.json"
	registry := &tenantca.TenantCARegistry{Pool: x509.NewCertPool()}
	// The REAL runtime trust store, seeded with an unrelated CA, and installed on the same package-level seam
	// production uses. ★ A stand-in here would have hidden the defect this test now covers: the routes used to
	// capture the store at registration, which happens ~80 lines before main creates it, so a node that had a
	// store answered "this node has no runtime device-trust store".
	_, seedPEM := tenantCATestCA(t, "Seed Device CA")
	trust, terr := openTransportTrustStore(t.TempDir()+"/device_client_cas.json", string(seedPEM), 1,
		func(string, int64) (func(), error) { return func() {}, nil })
	if terr != nil {
		t.Fatalf("trust store: %v", terr)
	}
	previousTrust := deviceClientCAs
	deviceClientCAs = trust
	t.Cleanup(func() { deviceClientCAs = previousTrust })

	tenants := newAdminTenantModelStore(model.PolicyBundle{}, time.Now())
	for _, id := range []string{"tenant_acme", "tenant_northwind"} {
		if _, err := tenants.Put(context.Background(), adminTenantModel{TenantID: id, DisplayName: id, Status: "active"}, time.Now()); err != nil {
			t.Fatalf("seed tenant: %v", err)
		}
	}

	var outbox adminAuditOutboxDeadReader
	if len(outboxes) > 0 {
		outbox = outboxes[0]
	}
	handler := newServerWithConfig(serverConfig{
		AdminAuditOutbox:     outbox,
		Evaluator:            testEvaluator(),
		Writer:               writer,
		Registry:             connector.NewRegistry(),
		AdminAuth:            auth,
		TenantModelStore:     tenants,
		TenantCARegistry:     registry,
		TenantCARegistryPath: path,
		// ★ THE OPERATOR IS AN ORGANIZATION, NOT A ROLE (2026-08-21). adm_operator/tok_operator above sit in
		// tenant_lab_001 and hold super_admin; until this line the harness never said that organization was
		// the operator's, and the gate could not tell it apart from a customer that grants itself super_admin
		// — which is exactly how a super_admin of tenant_reference_lab came to read tenant_northwind's audit
		// trail on the live lab.
		OperatorTenantID: "tenant_lab_001",
	})
	tenantCAHarnessTenantStore = tenants
	return handler, registry, trust, path
}

func doTenantCARequest(t *testing.T, handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		reader = strings.NewReader(string(raw))
	} else {
		reader = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, reader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("authorization", "Bearer "+testTenantCABearer)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

// trustStoreHolds asks the REAL store whether a certificate is in the device trust set.
func trustStoreHolds(t *testing.T, store *transportTrustStore, cert *x509.Certificate) bool {
	t.Helper()
	pems, _ := store.Current()
	certs, err := tenantca.ParseCACertsPEM([]byte(pems))
	if err != nil {
		t.Fatalf("parse trust set: %v", err)
	}
	for _, c := range certs {
		if c.Equal(cert) {
			return true
		}
	}
	return false
}

func tenantCATestCA(t *testing.T, cn string) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// testTenantCABearer is this test file's operator API token.
const testTenantCABearer = "raw-tenant-ca-operator"

// testTenantCANorthwindBearer is an ORDINARY admin of tenant_northwind — no super_admin, no cross-tenant
// rights of any kind. It exists because "the customer can manage its own device CA" is not testable with an
// operator token: an operator is allowed to do all of it, so every check passes without proving anything.
const testTenantCANorthwindBearer = "raw-tenant-ca-northwind-admin"

// ★ A WITHDRAWAL THAT WROTE ONE HALF OF WHAT THE REGISTRATION WROTE (2026-08-16, measured live before it was
// understood). Registering a device CA writes BOTH halves: into the runtime trust store the handshake
// verifies against, and into the registry that says whose devices those are. Withdrawing wrote only the
// registry, so the answer claimed "devices issued under this CA can no longer be admitted" while carrying, in
// the same object, "the certificate stays in the device trust set". On the reference lab a certificate issued
// by the just-withdrawn CA completed a (T) handshake and was recorded against the device.
//
// The gate in front of this act refuses while any device is still on the outgoing CA, so by the time the
// withdrawal proceeds there is nobody to strand — which is exactly why leaving admission running bought
// nothing and cost the truth of the answer.
func TestWithdrawingADeviceCATakesItOutOfTheTrustSetToo(t *testing.T) {
	handler, registry, trust, _ := tenantCARoutesForTest(t)

	// Two CAs for one organization: the outgoing one and its replacement. Withdrawing the last CA is a
	// different act and is refused, so the rotation shape is what this test needs.
	_, outgoingPEM := tenantCATestCA(t, "Northwind Device CA 2026")
	_, replacementPEM := tenantCATestCA(t, "Northwind Device CA 2028")
	for _, pemBytes := range [][]byte{outgoingPEM, replacementPEM} {
		body, _ := json.Marshal(map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(pemBytes)})
		req := httptest.NewRequest(http.MethodPost, "/admin/tenant-cas", bytes.NewReader(body))
		req.Header.Set("authorization", "Bearer "+testTenantCANorthwindBearer)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("register: HTTP %d %s", rec.Code, rec.Body.String())
		}
	}
	outgoing := tenantCAFingerprint(t, outgoingPEM)

	// The control, in the same test: registration DID reach the trust set. Without it, "not in the trust set
	// after the withdrawal" proves nothing — it is also what a registration that never wrote there looks like.
	if !trustStoreHoldsAnchor(trust, outgoing) {
		t.Fatal("the control failed: registering a device CA did not put it in the trust set the handshake reads")
	}

	req := httptest.NewRequest(http.MethodDelete, "/admin/tenant-cas/tenant_northwind/"+outgoing, nil)
	req.Header.Set("authorization", "Bearer "+testTenantCANorthwindBearer)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("withdraw: HTTP %d %s", rec.Code, rec.Body.String())
	}

	if trustStoreHoldsAnchor(trust, outgoing) {
		t.Fatal("the withdrawn CA is still in the device trust set — it keeps admitting the devices this act " +
			"exists to stop admitting, and the answer says the rotation is finished")
	}
	// And the attribution half went too, so nothing is trusted-but-attributed-to-nobody.
	for _, fact := range registry.Facts(time.Now()) {
		if strings.EqualFold(fact.SHA256, outgoing) {
			t.Fatal("the CA was taken out of the trust set but is still attributed to the organization")
		}
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["still_trusted"] != false {
		t.Fatalf("the answer still says the certificate stays trusted: %v", body["still_trusted"])
	}
}

// trustStoreHoldsAnchor reports whether the runtime trust set a handshake reads contains this certificate.
func trustStoreHoldsAnchor(store *transportTrustStore, sha256Hex string) bool {
	for _, anchor := range store.Anchors() {
		sum := sha256.Sum256(anchor.Raw)
		if strings.EqualFold(hex.EncodeToString(sum[:]), sha256Hex) {
			return true
		}
	}
	return false
}

// tenantCAFingerprint is the sha256 of the certificate in a PEM, which is how every CA route names one.
func tenantCAFingerprint(t *testing.T, pemBytes []byte) string {
	t.Helper()
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("no PEM block")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

// ★ AND THE ORDER OF THE TWO HALVES DECIDES WHETHER IT WORKS (2026-08-16, measured live, twice). The pool a
// (T) handshake verifies against is not the trust store: it is deviceTrustPoolFrom(registry, store) — the
// registry's pool CLONED, plus the store's certificates — and only a change to the STORE rebuilds it. So
// removing from the store first rebuilt the live pool from a registry that still held the CA, and the
// withdrawal defeated itself. On the lab, a certificate issued by a CA that had just been withdrawn by a
// build containing the both-halves fix still completed a handshake and was answered HTTP 200.
//
// This test drives the same seam production drives, so it fails on the ordering rather than on a restatement
// of it: the rebuild callback is the real one, and what it produces is what the assertion verifies a
// certificate against.
func TestTheWithdrawnCAIsGoneFromThePoolAHandshakeActuallyReads(t *testing.T) {
	handler, registry, _, _ := tenantCARoutesForTest(t)

	// Re-seat the store with production's rebuild: the pool is recomputed from the registry AND the store.
	_, seedPEM := tenantCATestCA(t, "Seed Device CA For Pool")
	var served atomic.Pointer[x509.CertPool]
	store, err := openTransportTrustStore(t.TempDir()+"/device_client_cas.json", string(seedPEM), 1,
		func(pems string, _ int64) (func(), error) {
			pool, perr := deviceTrustPoolFrom(registry.Pool, pems)
			if perr != nil {
				return nil, perr
			}
			return func() { served.Store(pool) }, nil
		})
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	previous := deviceClientCAs
	deviceClientCAs = store
	t.Cleanup(func() { deviceClientCAs = previous })
	pool, _ := deviceTrustPoolFrom(registry.Pool, func() string { p, _ := store.Current(); return p }())
	served.Store(pool)

	outgoingKey, outgoingPEM := tenantCATestCAWithKey(t, "Outgoing Device CA")
	_, replacementPEM := tenantCATestCA(t, "Replacement Device CA")
	for _, pemBytes := range [][]byte{outgoingPEM, replacementPEM} {
		body, _ := json.Marshal(map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(pemBytes)})
		req := httptest.NewRequest(http.MethodPost, "/admin/tenant-cas", bytes.NewReader(body))
		req.Header.Set("authorization", "Bearer "+testTenantCANorthwindBearer)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("register: HTTP %d %s", rec.Code, rec.Body.String())
		}
	}
	leaf := deviceLeafSignedBy(t, outgoingKey, outgoingPEM, "nw-laptop-001")

	// The control: while the CA is registered, a certificate it issued verifies against the served pool. This
	// is the half that makes the assertion below mean something.
	if _, verr := leaf.Verify(x509.VerifyOptions{Roots: served.Load(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); verr != nil {
		t.Fatalf("the control failed: a registered CA's certificate did not verify against the served pool: %v", verr)
	}

	req := httptest.NewRequest(http.MethodDelete, "/admin/tenant-cas/tenant_northwind/"+tenantCAFingerprint(t, outgoingPEM), nil)
	req.Header.Set("authorization", "Bearer "+testTenantCANorthwindBearer)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("withdraw: HTTP %d %s", rec.Code, rec.Body.String())
	}

	if _, verr := leaf.Verify(x509.VerifyOptions{Roots: served.Load(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); verr == nil {
		t.Fatal("a certificate from the withdrawn CA still verifies against the pool the handshake reads — the " +
			"withdrawal changed the bookkeeping and not the admission")
	}
}

// tenantCATestCAWithKey is tenantCATestCA plus the signing key, for tests that must ISSUE under the CA
// rather than only register it.
func tenantCATestCAWithKey(t *testing.T, cn string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// deviceLeafSignedBy issues a client certificate under a CA, the way a device's certificate is issued.
func deviceLeafSignedBy(t *testing.T, caKey *ecdsa.PrivateKey, caPEM []byte, identity string) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse CA: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: identity, Organization: []string{"Northwind Traders"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("issue leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return leaf
}
