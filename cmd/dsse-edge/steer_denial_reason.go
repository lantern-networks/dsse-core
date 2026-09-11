package main

import (
	"strings"

	"github.com/lantern-networks/dsse-core/model"
)

// steer_denial_reason.go — saying WHY a flow was refused, in the words the decision already carries.
//
// ★★ THE DECISION HAS ALWAYS CARRIED THIS AND NOTHING PRINTED IT (2026-08-25). A refused flow closes with no
// bytes, which from the device is indistinguishable from a network failure — so the Edge's line is the only
// place the difference exists. It said the port and the verdict; the reason and the codes were right there on
// the same struct.
func steerDenialReason(dec model.AccessDecision) string {
	if dec.Reason != nil {
		if r := strings.TrimSpace(*dec.Reason); r != "" {
			return r
		}
	}
	if len(dec.ReasonCodes) > 0 {
		return strings.Join(dec.ReasonCodes, ",")
	}
	// ★ NOT EMPTY. "no reason given" is itself worth reading: it says the denial came from somewhere that did
	// not record one, which is a different thing to look at than a rule that did.
	return "no reason given"
}
