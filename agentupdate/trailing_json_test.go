package agentupdate

import (
	"encoding/json"
	"testing"
)

func TestSignedUpdateDocumentsRejectTrailingJSONDelimiters(t *testing.T) {
	manifest, err := json.Marshal(goodManifest())
	if err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{"}", "]"} {
		if _, err := decodeStrict(append(append([]byte(nil), manifest...), extra...)); err == nil {
			t.Fatalf("manifest accepted trailing %q after top-level JSON object", extra)
		}
	}
	plan := []byte(`{"schema_version":"dsse.agent-update-plan.v1"}`)
	for _, extra := range []string{"}", "]"} {
		if _, err := DecodeRolloutPlan(append(append([]byte(nil), plan...), extra...)); err == nil {
			t.Fatalf("rollout plan accepted trailing %q after top-level JSON object", extra)
		}
	}
}
