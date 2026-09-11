package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/installprofile"
	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/logs"
)

// The screen exists so that making the one file every endpoint needs no longer requires a checkout, a Go
// toolchain, and the deployment's raw signing seed in a person's hands. These pin the parts of that which are
// decisions rather than plumbing.

func agentProfileMux(t *testing.T, signed bool, regions []regionEndpoint) *http.ServeMux {
	return agentProfileMuxWithTransportAuthority(t, signed, regions, nil)
}

func agentProfileMuxWithTransportAuthority(t *testing.T, signed bool, regions []regionEndpoint,
	transport *tenantTransportAuthority) *http.ServeMux {
	t.Helper()
	config := serverConfig{TenantTransportAuthority: transport}
	if signed {
		signer, err := agentpolicy.LoadOrGenerateSigner("", true)
		if err != nil {
			t.Fatalf("signer: %v", err)
		}
		config.AgentPolicySigner = signer
	}
	// A real writer, because issuing a profile is a configuration change and this route REFUSES to issue one
	// it cannot record — a fleet's posture set by nobody is the family this deployment keeps finding.
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatalf("writer: %v", err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	mux := http.NewServeMux()
	registerAgentProfileRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
		config, decision.Evaluator{}, writer, nil, "https://agents.example.test",
		func(string) []regionEndpoint { return regions })
	return mux
}

func issueProfile(t *testing.T, mux *http.ServeMux, tenant, body string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/admin/agent-profile", strings.NewReader(body))
	r = requestWithAdminIdentity(r, adminIdentity{PrincipalID: "adm_alice", TenantID: tenant})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// ★★★ A profile names the organization its devices enrol into. Reading that from the body would let one
// customer's administrator mint configuration that enrols machines into another's.
func TestTheProfileNamesTheCallersOrganizationAndNotTheBodys(t *testing.T) {
	mux := agentProfileMux(t, true, nil)
	code, body := issueProfile(t, mux, "tenant_acme", `{"tenant_id":"tenant_northwind","tenant":"tenant_northwind"}`)
	if code != http.StatusOK {
		t.Fatalf("issue: %d %+v", code, body)
	}
	payload := decodeProfilePayload(t, body)
	if payload.TenantID != "tenant_acme" {
		t.Fatalf("profile names %q; the caller is tenant_acme and the body must not move it", payload.TenantID)
	}
}

// The guard for the check above: with no organization on the request there is nothing to name, and issuing
// anyway would hand out a profile whose devices enrol into nothing.
func TestAProfileIsRefusedWhenTheRequestCarriesNoOrganization(t *testing.T) {
	mux := agentProfileMux(t, true, nil)
	r := httptest.NewRequest(http.MethodPost, "/admin/agent-profile", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403 with no organization, got %d: %s", rec.Code, rec.Body.String())
	}
}

// ★★★ Fail-open is a fleet running unmediated whenever no Edge answers. A screen can draw a checkbox; only the
// server can make it mean something.
func TestFailOpenNeedsTheAcknowledgementAndTheServerIsWhereThatHolds(t *testing.T) {
	mux := agentProfileMux(t, true, nil)
	code, body := issueProfile(t, mux, "tenant_acme",
		`{"posture":"`+installprofile.PostureFailOpen+`"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("want the unacknowledged fail-open refused, got %d %+v", code, body)
	}
	// The guard: the SAME request with the acknowledgement is issued, so the refusal above is the
	// acknowledgement being absent and not fail-open being unreachable.
	code, body = issueProfile(t, mux, "tenant_acme",
		`{"posture":"`+installprofile.PostureFailOpen+`","ack_fail_open":true}`)
	if code != http.StatusOK {
		t.Fatalf("acknowledged fail-open: %d %+v", code, body)
	}
	if p := decodeProfilePayload(t, body); !p.FailOpenEnabled() {
		t.Fatalf("acknowledged fail-open did not reach the profile: %+v", p)
	}
}

// ★★ The addresses are the deployment's own, in the shape the agent's bootstrap seed already takes, and every
// region is carried — one address is the case where a device that cannot reach it has nowhere to start.
func TestTheProfileCarriesEveryRegionTheDeploymentPublishes(t *testing.T) {
	mux := agentProfileMux(t, true, []regionEndpoint{
		{Region: "region-a", Endpoint: "https://agents.example.test"},
		{Region: "region-b", Endpoint: "https://agents-b.example.test"},
	})
	code, body := issueProfile(t, mux, "tenant_acme", `{}`)
	if code != http.StatusOK {
		t.Fatalf("issue: %d %+v", code, body)
	}
	payload := decodeProfilePayload(t, body)
	want := []string{"region-a=https://agents.example.test", "region-b=https://agents-b.example.test"}
	if strings.Join(payload.TransportEndpoints, ",") != strings.Join(want, ",") {
		t.Fatalf("endpoints %+v; want %+v", payload.TransportEndpoints, want)
	}
	// ★★ AND THE SINGLE-ADDRESS FIELD IS A URL. An agent built before transport_endpoints existed dials
	// transport_url directly; "region-a=https://…" is not an address, so such a device would fail to reach a
	// deployment that is answering. Measured on the first profile this route ever issued.
	if payload.TransportURL != "https://agents.example.test" {
		t.Fatalf("transport_url %q is not a dialable address; an older agent dials this one verbatim",
			payload.TransportURL)
	}
}

// ★ An unsigned profile is one every endpoint refuses. Answering with one hands an operator a file that
// cannot work and no reason why.
func TestADeploymentWithNoSigningKeySaysSoRatherThanIssuingSomethingUnusable(t *testing.T) {
	mux := agentProfileMux(t, false, nil)
	code, body := issueProfile(t, mux, "tenant_acme", `{}`)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 with no signing key, got %d %+v", code, body)
	}
}

// ★★ THE OPERATOR PICKS A NAME; THE PATTERNS COME FROM THE DEPLOYMENT. Bypass entries are matched by string
// on the device, so a typed pattern produces a profile that is accepted, signed, installed, and silently
// inspecting what somebody asked to leave alone.
func TestChoosingAKnownBypassByNameCarriesItsPatternsAndAnUnknownOneIsNamed(t *testing.T) {
	mux := agentProfileMux(t, true, nil)
	known := knownbypass.Catalog().Entries[0]
	code, body := issueProfile(t, mux, "tenant_acme", `{"bypass_catalog_ids":["`+known.ID+`"]}`)
	if code != http.StatusOK {
		t.Fatalf("issue: %d %+v", code, body)
	}
	got := decodeProfilePayload(t, body).BypassDests
	for _, want := range known.Patterns {
		if !containsString(got, want) {
			t.Fatalf("%q selected but %q is not in the profile: %+v", known.ID, want, got)
		}
	}
	// The guard: an id this deployment does not publish is REFUSED rather than dropped, so the check above is
	// about expansion and not about the route accepting anything at all.
	code, body = issueProfile(t, mux, "tenant_acme", `{"bypass_catalog_ids":["no-such-entry"]}`)
	if code != http.StatusBadRequest {
		t.Fatalf("want an unknown catalogue id refused, got %d %+v", code, body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "no-such-entry") {
		t.Fatalf("the refusal does not name what was dropped: %q", msg)
	}
}

func decodeProfilePayload(t *testing.T, body map[string]any) installprofile.InstallProfile {
	t.Helper()
	// The signed bytes themselves, not a convenience copy beside them: what a device applies is what came out
	// of the signature, so that is what these assertions read.
	b64, _ := body["payload_b64"].(string)
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode payload_b64: %v (%+v)", err, body)
	}
	var p installprofile.InstallProfile
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("decode payload: %v (%s)", err, raw)
	}
	return p
}

// ★★★ THE ORGANIZATION'S OWN DOOR NAME REACHES THE DEVICE (2026-08-28, added after finding that it never had).
//
// The Edge chooses which organization's transport certificate to present from the SNI — it cannot read the
// client certificate first, TLS sends the server's before the client's — and this control plane issues a name
// per organization for exactly that. The agents on both platforms read the block below and act on it. Every
// producer of a profile left it empty, so every device dialled the shared name and was served the deployment's
// own certificate: three layers built, and joined at none.
func TestTheProfileCarriesTheOrganizationsOwnTransportName(t *testing.T) {
	// The CP authors profiles without running an Edge recovery listener.
	previous := renewalRecoveryMainPort.Load()
	renewalRecoveryMainPort.Store(nil)
	t.Cleanup(func() { renewalRecoveryMainPort.Store(previous) })
	authority := newTenantTransportAuthority(nil, func([]byte) error { return nil }, nil)
	if _, err := authority.EnsureCA("tenant_kaede", "kaede.example.test"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	mux := agentProfileMuxWithTransportAuthority(t, true, nil, authority)

	code, body := issueProfile(t, mux, "tenant_kaede", `{}`)
	if code != http.StatusOK {
		t.Fatalf("issue: %d %v", code, body)
	}
	org := decodeProfilePayload(t, body).Organization
	if org.TransportServerName != "kaede.example.test" {
		t.Fatalf("the profile does not tell this organization's devices which name to send: %+v — they will "+
			"dial the shared name and be served the deployment's own certificate, which is the state every "+
			"device of every organization has been in", org)
	}
	if org.EnrolmentServerName != "enrol.kaede.example.test" || org.RenewalRecoveryServerName != "recovery.kaede.example.test" {
		t.Fatalf("CP-issued profile omitted an initial or recovery door: %+v", org)
	}
	if org.TenantID != "tenant_kaede" {
		t.Errorf("the block names no organization: %+v", org)
	}

	// ★ AND AN ORGANIZATION WITHOUT ONE IS LEFT ALONE. Absent is a supported, meaningful state — "the
	// deployment's shared certificate" — and it is what every fleet had before this field existed. Emitting a
	// name the certificate does not carry turns every dial into a verification failure, and this profile's name
	// is used BEFORE the first trust bundle, so nothing proves it on the wire first.
	code, body = issueProfile(t, mux, "tenant_without_one", `{}`)
	if code != http.StatusOK {
		t.Fatalf("issue: %d %v", code, body)
	}
	if name := decodeProfilePayload(t, body).Organization.TransportServerName; strings.TrimSpace(name) != "" {
		t.Fatalf("an organization with no transport authority was told to send %q — nothing serves that name, "+
			"so every dial fails verification", name)
	}
}

// ★★★ LETTING VIRTUAL MACHINES OUT NEEDS THE SAME TWO KEYS, AND FOR A SHARPER REASON (2026-09-01, measured on
// win-dev-1). Fail-open is a state a fleet falls into when a deployment is unreachable; this one is permanent,
// and it needs no administrator on the device to use. A WSL2 distro on a steered Windows box egressed straight
// to the internet with a public CA chain and the site's own address while the agent reported steering.
func TestLettingVirtualMachinesOutNeedsTheAcknowledgement(t *testing.T) {
	mux := agentProfileMux(t, true, nil)

	code, body := issueProfile(t, mux, "tenant_acme",
		`{"virtual_machine_egress":"`+installprofile.VMEgressAllowed+`"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("want the unacknowledged choice refused, got %d %+v", code, body)
	}
	// The guard: the SAME request with the acknowledgement is issued, so the refusal above is the
	// acknowledgement being absent and not the choice being unreachable — an organization that runs virtual
	// machines must be able to say so, or its only remaining option is to stop steering altogether.
	code, body = issueProfile(t, mux, "tenant_acme",
		`{"virtual_machine_egress":"`+installprofile.VMEgressAllowed+`","ack_virtual_machine_egress":true}`)
	if code != http.StatusOK {
		t.Fatalf("acknowledged choice: %d %+v", code, body)
	}
	if p := decodeProfilePayload(t, body); p.VMEgress != installprofile.VMEgressAllowed || !p.AckVMEgress {
		t.Fatalf("the acknowledged choice did not reach the profile: egress=%q ack=%v", p.VMEgress, p.AckVMEgress)
	}

	// ★ AND A PROFILE THAT SAYS NOTHING BLOCKS. Every profile issued before this field existed says nothing,
	// and the promise the agent makes about outbound traffic is what decides the default — not the fact that
	// blocking is the newer behaviour.
	code, body = issueProfile(t, mux, "tenant_acme", `{}`)
	if code != http.StatusOK {
		t.Fatalf("plain issue: %d %+v", code, body)
	}
	if p := decodeProfilePayload(t, body); p.VMEgress != installprofile.VMEgressBlocked {
		t.Fatalf("a profile that chose nothing came out as %q", p.VMEgress)
	}
}
