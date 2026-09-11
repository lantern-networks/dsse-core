package configstore

import "testing"

// ★ THE DIAGNOSIS THAT WAS MISSING (2026-08-13). A generic package has no anchor, so a
// profile that is present, intact and correctly signed reported as "INVALID/absent (<nil>)" — an operator then
// looks for a file they can open and read. `<nil>` was the tell: there is no error because there is no key.
func TestTheStoredEnvelopeNamesItsSigner(t *testing.T) {
	const env = `{"type":"dsse.install_profile","signing_key_id":"edge-agent-policy-09b7921bd20c7128","payload_b64":"e30="}`
	if got := SigningKeyIDOf([]byte(env)); got != "edge-agent-policy-09b7921bd20c7128" {
		t.Fatalf("the signer was not readable from the envelope: %q", got)
	}
	// Not evidence, and unreadable input must not become a confident claim.
	if got := SigningKeyIDOf([]byte("not json")); got != "" {
		t.Fatalf("unparseable bytes produced a signer name: %q", got)
	}
	if got := SigningKeyIDOf(nil); got != "" {
		t.Fatalf("no envelope produced a signer name: %q", got)
	}
}

func TestStoredEnvelopeReadsWhatApplyWrote(t *testing.T) {
	b := NewMemoryBackend()
	if _, ok := StoredEnvelope(b); ok {
		t.Fatal("an empty store reported an envelope")
	}
	if err := b.Set(valEnvelope, `{"signing_key_id":"edge-agent-policy-abc"}`); err != nil {
		t.Fatal(err)
	}
	raw, ok := StoredEnvelope(b)
	if !ok || SigningKeyIDOf(raw) != "edge-agent-policy-abc" {
		t.Fatalf("the stored envelope did not come back: ok=%v raw=%s", ok, raw)
	}
}
