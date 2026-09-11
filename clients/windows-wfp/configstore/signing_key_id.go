package configstore

import (
	"encoding/json"
	"strings"
)

// SigningKeyIDOf reports which key an envelope SAYS signed it, for diagnosis only.
//
// ★ IT IS AN ANNOTATION, NOT EVIDENCE, AND THAT IS THE POINT (2026-08-13). Verification
// is a signature check and nothing here changes that. What this is for is the case where verification could
// not even be attempted: a generic package — built without -Pin — has no anchor, so a profile that is present,
// intact and correctly signed reports as "invalid/absent" with a nil error, and the operator goes looking for
// a file they can open and read. The envelope names the signer, the binary knows what it pins, and those two
// strings are what turns that dead end into a sentence.
func SigningKeyIDOf(envelopeJSON []byte) string {
	var env struct {
		SigningKeyID string `json:"signing_key_id"`
	}
	if json.Unmarshal(envelopeJSON, &env) != nil {
		return ""
	}
	return strings.TrimSpace(env.SigningKeyID)
}

// StoredEnvelope returns the raw signed envelope this device holds, if any. Unverified by construction — the
// caller is the one that verifies, and this exists so a FAILED verification can say something specific.
func StoredEnvelope(b Backend) ([]byte, bool) {
	if b == nil {
		return nil, false
	}
	v, ok, err := b.Get(valEnvelope)
	if err != nil || !ok || strings.TrimSpace(v) == "" {
		return nil, false
	}
	return []byte(v), true
}
