package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/agentupdate"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/logs"
)

// admin_agent_update_sign_route_test.go — POST /admin/agent-updates driven through the mux, because the value
// of this endpoint is entirely in the wiring: a signer that is never reached, a floor that is never consulted,
// or an envelope that is signed and then not stored all compile perfectly.

type signRouteHarness struct {
	mux     *http.ServeMux
	store   *publishedAgentUpdateStore
	signer  *agentpolicy.Signer
	ratchet *agentUpdateSignRatchet
	dir     string
}

func newSignRouteHarness(t *testing.T, signer *agentpolicy.Signer) *signRouteHarness {
	t.Helper()
	dir := t.TempDir()
	writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
	if err != nil {
		t.Fatal(err)
	}
	h := &signRouteHarness{
		mux:     http.NewServeMux(),
		store:   newPublishedAgentUpdateStore(),
		signer:  signer,
		ratchet: newAgentUpdateSignRatchet(dir),
		dir:     dir,
	}
	var keys []string
	if signer != nil {
		keys = []string{signer.PublicKeyHex()}
	} else {
		keys = []string{strings.Repeat("aa", 32)}
	}
	registerAgentUpdatePublishRoutes(h.mux, func(_ string, fn http.HandlerFunc) http.HandlerFunc { return fn },
		h.store, keys, false, writer, decision.Evaluator{}, filepath.Join(dir, "artifacts"), &publishedUpdates{byTarget: map[string]publishedUpdate{}},
		signer, h.ratchet)
	return h
}

func (h *signRouteHarness) post(t *testing.T, tenant string, m agentupdate.Manifest) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(m)
	req := httptest.NewRequest(http.MethodPost, "/admin/agent-updates", bytes.NewReader(body))
	req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{},
		adminIdentity{PrincipalID: "adm_test", TenantID: tenant, AuthMethod: "admin_session"}))
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// releasableManifest describes bytes that actually exist, so the release can become ACTIVE rather than pending.
func (h *signRouteHarness) releasableManifest(t *testing.T, tenant, version string, now time.Time) agentupdate.Manifest {
	t.Helper()
	m := publishableManifest(now)
	m.Version = version
	payload := artifactBytesFor(version)
	sum := sha256.Sum256(payload)
	m.ArtifactSHA256 = hex.EncodeToString(sum[:])
	m.ArtifactSize = int64(len(payload))
	p := artifactStorePath(filepath.Join(h.dir, "artifacts"), tenant, m.Platform, m.Arch, version)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return m
}

// ★ THE WHOLE POINT, END TO END: an operator states the fields, the control plane signs, and what is stored is
// an envelope the fleet's pinned key opens. If the signature were skipped, or a different key used, or the
// envelope not stored, everything here still compiles.
func TestTheControlPlaneSignsWhatAnOperatorAsksForAndStoresIt(t *testing.T) {
	now := time.Now().UTC()
	sg := updateSigner(t)
	h := newSignRouteHarness(t, sg)

	code, body := h.post(t, "tenant_a", h.releasableManifest(t, "tenant_a", "0.3.0", now))
	if code != http.StatusOK {
		t.Fatalf("HTTP %d: %v", code, body)
	}
	if body["state"] != "active" {
		t.Fatalf("the artifact is on disk, so this should be active: %v", body)
	}

	key := updateTargetKey(agentupdate.PlatformWindows, agentupdate.ArchAMD64)
	env, ok := h.store.ForTenant("tenant_a")[key]
	if !ok {
		t.Fatal("the signed release was not stored, so nothing reaches a device")
	}
	m, err := agentupdate.Open(env, []string{sg.PublicKeyHex()}, now)
	if err != nil {
		t.Fatalf("what was stored does not open under the pinned key: %v", err)
	}
	if m.Version != "0.3.0" {
		t.Fatalf("stored %s", m.Version)
	}

	// ★ AND THE SIGNATURE MUST NOT VERIFY UNDER SOMEONE ELSE'S KEY — that is the only property that makes the
	// stored bytes mean anything.
	other := updateSigner(t)
	if _, err := agentupdate.Open(env, []string{other.PublicKeyHex()}, now); err == nil {
		t.Fatal("the envelope opened under an unrelated key")
	}
}

// ★ THE DOWNGRADE IS REFUSED BEFORE IT IS SIGNED. A signed downgrade that is then refused has still been
// signed, and an envelope that exists can be replayed at any edge pinning the key — so this asserts the status
// AND that nothing new was stored.
func TestASignedDowngradeIsRefusedAndNothingIsStored(t *testing.T) {
	now := time.Now().UTC()
	sg := updateSigner(t)
	h := newSignRouteHarness(t, sg)

	if code, body := h.post(t, "tenant_a", h.releasableManifest(t, "tenant_a", "0.3.0", now)); code != http.StatusOK {
		t.Fatalf("HTTP %d: %v", code, body)
	}
	code, body := h.post(t, "tenant_a", h.releasableManifest(t, "tenant_a", "0.2.4", now))
	if code != http.StatusConflict {
		t.Fatalf("a downgrade was signed: HTTP %d %v", code, body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "Roll back instead") {
		t.Fatalf("the refusal should name the path that still works: %v", body)
	}

	key := updateTargetKey(agentupdate.PlatformWindows, agentupdate.ArchAMD64)
	m, err := agentupdate.Open(h.store.ForTenant("tenant_a")[key], []string{sg.PublicKeyHex()}, now)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "0.3.0" {
		t.Fatalf("the refused downgrade replaced what the fleet is offered: %s", m.Version)
	}

	// Re-signing the SAME version is allowed — manifests expire, and this is how one is renewed.
	if code, body := h.post(t, "tenant_a", h.releasableManifest(t, "tenant_a", "0.3.0", now)); code != http.StatusOK {
		t.Fatalf("renewing the current version was refused: HTTP %d %v", code, body)
	}
}

// One tenant's release history must not restrict another's: the floor is per target AND per tenant, and this
// endpoint is reachable by any tenant-scoped admin.
func TestOneTenantsFloorDoesNotBindAnother(t *testing.T) {
	now := time.Now().UTC()
	h := newSignRouteHarness(t, updateSigner(t))
	if code, _ := h.post(t, "tenant_a", h.releasableManifest(t, "tenant_a", "0.9.0", now)); code != http.StatusOK {
		t.Fatal("setup publish failed")
	}
	if code, body := h.post(t, "tenant_b", h.releasableManifest(t, "tenant_b", "0.2.0", now)); code != http.StatusOK {
		t.Fatalf("tenant_b was blocked by tenant_a's floor: HTTP %d %v", code, body)
	}
}

// ★ A FIELD THIS BUILD DOES NOT UNDERSTAND IS REFUSED, NOT DROPPED. An operator who writes min_upgrade_from
// where the manifest says min_from would otherwise get a signed manifest WITHOUT the constraint they asked
// for, and nothing anywhere would say so.
func TestAnUnknownFieldIsRefusedRatherThanSignedAway(t *testing.T) {
	h := newSignRouteHarness(t, updateSigner(t))
	req := httptest.NewRequest(http.MethodPost, "/admin/agent-updates",
		strings.NewReader(`{"schema_version":"dsse_agent_update_manifest.v1","version":"9.9.9","min_upgrade_from":"1.0.0"}`))
	req = req.WithContext(context.WithValue(req.Context(), adminIdentityContextKey{},
		adminIdentity{PrincipalID: "adm_test", TenantID: "tenant_a", AuthMethod: "admin_session"}))
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("an unknown field was accepted: HTTP %d %s", rec.Code, rec.Body.String())
	}
}

// A control plane with no update-signing key must say so, rather than 500 or silently publish something
// unsigned. Publishing an envelope signed elsewhere (PUT) is still the way out.
func TestWithNoSigningKeyTheEndpointSaysWhatIsMissing(t *testing.T) {
	now := time.Now().UTC()
	h := newSignRouteHarness(t, nil)
	code, body := h.post(t, "tenant_a", h.releasableManifest(t, "tenant_a", "0.3.0", now))
	if code != http.StatusPreconditionFailed {
		t.Fatalf("HTTP %d: %v", code, body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "hsm-agent-socket") {
		t.Fatalf("the refusal must name what to configure: %v", body)
	}
}
