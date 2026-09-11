package edgeplane

import (
	"encoding/json"
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

func TestSteerMuxWarnNoticePayload(t *testing.T) {
	// A Warn-stage decision carries a warn_notice action → payload with message/destination/service.
	dec := model.AccessDecision{Decision: "allow", Actions: []model.DecisionAction{{
		Type: "warn_notice",
		Metadata: map[string]any{
			"east_west":      true,
			"message":        "This internal connection is monitored. Authentication will soon be required to reach it.",
			"destination":    "10.20.0.10",
			"service_family": "smb",
			"rule_id":        "rule-9",
		},
	}}}
	payload, ok := SteerMuxWarnNoticePayload(dec)
	if !ok {
		t.Fatalf("expected a warn payload")
	}
	var got map[string]string
	if err := json.Unmarshal(payload, &got); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if got["destination"] != "10.20.0.10" || got["service"] != "smb" || got["message"] == "" {
		t.Fatalf("payload wrong: %v", got)
	}

	// An ordinary allow (no warn_notice) yields no payload.
	if _, ok := SteerMuxWarnNoticePayload(model.AccessDecision{Decision: "allow"}); ok {
		t.Fatalf("a plain allow must not produce a warn payload")
	}
}

func TestSteerMuxWarnOnceCoalesces(t *testing.T) {
	m := NewSteerMux(nil)
	if !m.warnOnce("smb|10.20.0.10") {
		t.Fatalf("first warn for a resource must send")
	}
	if m.warnOnce("smb|10.20.0.10") {
		t.Fatalf("second warn for the same resource must be coalesced (not sent)")
	}
	if !m.warnOnce("rdp|10.20.0.10") {
		t.Fatalf("a different resource must send its own first warn")
	}
}
