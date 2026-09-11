package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// A device-restricted east-west rule matches only its named devices (via req.DeviceID), and an unset source
// selector never degrades the source to wildcard.
func TestEastWestSourceDeviceRestriction(t *testing.T) {
	rule := EastWestRule{ID: "r1", Priority: 100, SourceDevices: []string{"dev-alice", "dev-bob"}, Destinations: []string{"db.internal"}, Protocols: []string{"smb"}, Mode: "authenticate"}
	rules := []EastWestRule{rule}

	req := func(deviceID string) model.DecisionRequest {
		return model.DecisionRequest{DeviceID: deviceID, Destination: "db.internal", ServiceFamily: "smb"}
	}

	// A named device matches.
	if _, ok := MatchedEastWestRule(rules, req("dev-alice")); !ok {
		t.Fatalf("dev-alice should match the device-restricted rule")
	}
	// A device NOT in the source set does not match (so default-deny applies to it).
	if _, ok := MatchedEastWestRule(rules, req("dev-eve")); ok {
		t.Fatalf("dev-eve must NOT match a rule restricted to alice/bob")
	}
	// Empty DeviceID does not match a device-restricted rule.
	if _, ok := MatchedEastWestRule(rules, req("")); ok {
		t.Fatalf("empty device id must not match a device-restricted rule")
	}

	// The fail-closed sentinel that the compiler emits for an unresolved source never matches a real device.
	sentinelRule := []EastWestRule{{ID: "r2", SourceDevices: []string{"\x00no-such-source-device"}, Destinations: []string{"db.internal"}, Protocols: []string{"smb"}, Mode: "allow"}}
	if _, ok := MatchedEastWestRule(sentinelRule, req("dev-alice")); ok {
		t.Fatalf("sentinel source must never match")
	}
}
