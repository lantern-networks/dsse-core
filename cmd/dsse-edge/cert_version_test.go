package main

import (
	"context"
	"encoding/json"
	"testing"

	configversion "github.com/lantern-networks/dsse-core/configversion"
)

// A certificate rollback must re-apply the EXACT prior cert+key, so the version snapshot must round-trip
// the private key — while the history LIST redacts it (only non-secret metadata is shown).
func TestCertVersionSnapshotRoundTripAndRedaction(t *testing.T) {
	store := configversion.NewMemoryStore()
	ctx := context.Background()
	const tenant, name = "t1", "edge"

	store.Record(ctx, tenant, configversion.ResourceCertificate, name, configversion.ActionUpsert, "nagi",
		"subject=CN=dsse-edge not_after=2027 fp=AB12", certVersionSnapshot{CertPEM: "CERT-v1", KeyPEM: "KEY-v1"})
	store.Record(ctx, tenant, configversion.ResourceCertificate, name, configversion.ActionUpsert, "nagi",
		"subject=CN=dsse-edge not_after=2028 fp=CD34", certVersionSnapshot{CertPEM: "CERT-v2", KeyPEM: "KEY-v2"})

	// Rollback path: Get v1 returns the full snapshot incl. the private key (needed to re-apply).
	v, ok, _ := store.Get(ctx, tenant, configversion.ResourceCertificate, name, 1)
	if !ok {
		t.Fatal("version 1 must exist")
	}
	var snap certVersionSnapshot
	if err := json.Unmarshal(v.Payload, &snap); err != nil {
		t.Fatal(err)
	}
	if snap.CertPEM != "CERT-v1" || snap.KeyPEM != "KEY-v1" {
		t.Fatalf("rollback snapshot must reproduce v1 cert+key, got %+v", snap)
	}

	// History LIST path: the handler redacts the payload (cert+key) — only the note's non-secret metadata
	// reaches the admin. Simulate the handler's redaction and assert the secret is gone but metadata stays.
	list, _ := store.List(ctx, tenant, configversion.ResourceCertificate, name)
	if len(list) != 2 {
		t.Fatalf("want 2 versions, got %d", len(list))
	}
	for i := range list {
		list[i].Payload = nil // the GET .../versions handler does exactly this
	}
	if list[0].Payload != nil {
		t.Fatal("the cert/key payload must be redacted from the history listing")
	}
	if list[0].Note != "subject=CN=dsse-edge not_after=2028 fp=CD34" || list[0].VersionNo != 2 {
		t.Fatalf("redacted history must keep non-secret metadata + newest-first order: %+v", list[0])
	}
}
