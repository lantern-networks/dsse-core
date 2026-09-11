package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/installprofile"
)

func opts() installprofile.Options {
	return installprofile.Options{
		Tenant: "acme", TransportURL: "https://edge.acme:18543", EnrollMode: "token",
		Posture: "fail-closed", Backend: "wfp", DNSListen: "127.0.0.1:53", BlockQUIC: true,
		CaptiveTimeout: 180,
	}
}

// ★ THE POSITIVE CONTROL THE ANTI-ROLLBACK GUARD NEVER HAD (2026-08-17).
//
// configstore.Apply refuses a profile older than the applied one. For as long as that refusal keyed on
// `version`, it could not fire: this is the only issuer in the tree and it stamps the literal 3 on every
// profile, so every comparison was 3 < 3. The guard's own unit test passed because it hand-wrote Version 2,
// 3 and 4 — three values the product has never emitted.
//
// So the guard is only worth what the ISSUER's ordering key is worth, and that is what this asserts: two
// issues in sequence must be distinguishable and in order. A future change that drops the stamp, or pins it
// to a constant, fails here rather than silently disarming the refusal downstream.
func TestTheIssuerStampsAnOrderingKeyThatActuallyMoves(t *testing.T) {
	t1 := time.Date(2026, 8, 17, 3, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Minute)

	first := installprofile.Build(opts(), t1)
	second := installprofile.Build(opts(), t2)

	if first.IssuedAt == "" {
		t.Fatal("the issuer emitted no issued_at, so configstore.Apply has nothing to order profiles by and " +
			"its anti-rollback refusal can never fire")
	}
	if first.IssuedAt == second.IssuedAt {
		t.Fatalf("two issues a minute apart carry the same ordering key %q — this is exactly how the version "+
			"comparison became a no-op", first.IssuedAt)
	}
	got, err := time.Parse(time.RFC3339, first.IssuedAt)
	if err != nil {
		t.Fatalf("issued_at %q must be RFC3339 (configstore.Apply parses it, and refuses what it cannot): %v",
			first.IssuedAt, err)
	}
	if !got.Equal(t1) {
		t.Fatalf("issued_at %v is not the time the profile was issued (%v)", got, t1)
	}

	// The negative half: `version` must NOT be doing this job. If someone "fixes" ordering by incrementing the
	// schema version instead, the two profiles above would differ in version — and every OTHER consumer of
	// version (the MDM detection rule, the schema check) would start reading an issue counter.
	if first.Version != second.Version {
		t.Fatalf("version moved between issues (%d -> %d): it is the SCHEMA version, and other code reads it "+
			"as such", first.Version, second.Version)
	}
	if first.Version != 3 {
		t.Fatalf("schema version is %d, want 3 — if the schema really changed, update the readers too",
			first.Version)
	}
}

// The stamp must not cost anything else: everything the flags asked for still reaches the payload.
func TestBuildProfileCarriesTheFlagsThrough(t *testing.T) {
	o := opts()
	o.Group = "developers"
	o.BypassApps = "a.exe, b.exe"
	o.BypassDests = "10.0.0.1:53"
	o.AckFailOpen = true
	o.Posture = "fail-open"
	p := installprofile.Build(o, time.Unix(1_700_000_000, 0))

	if p.Kind != installprofile.ProfileKind {
		t.Fatalf("kind = %q", p.Kind)
	}
	if p.TenantID != "acme" || p.GroupID != "developers" || p.TransportURL != "https://edge.acme:18543" {
		t.Fatalf("identity fields lost: %+v", p)
	}
	if p.Posture != "fail-open" || !p.AckFailOpen {
		t.Fatalf("posture lost: %q ack=%v", p.Posture, p.AckFailOpen)
	}
	if len(p.BypassApps) != 2 || p.BypassApps[1] != "b.exe" {
		t.Fatalf("bypass apps = %v (whitespace around a CSV entry must be trimmed)", p.BypassApps)
	}
	if len(p.BypassDests) != 1 || p.BypassDests[0] != "10.0.0.1:53" {
		t.Fatalf("bypass dests = %v", p.BypassDests)
	}
	if p.BlockQUIC == nil || !*p.BlockQUIC {
		t.Fatalf("block_quic lost: %v", p.BlockQUIC)
	}
	if p.Captive.TimeoutSec != 180 || p.StartMode != installprofile.StartAuto {
		t.Fatalf("captive/start lost: %+v", p)
	}
}
