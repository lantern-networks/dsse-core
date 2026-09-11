package main

import "testing"

// appBypassDecision is the steer-all AppID safety core. The critical property is FAIL-OPEN: an unresolved
// owner must be passed through (never steered), so a resolution race can't strangle a brand-new flow such
// as Automation's api.anthropic.com:443.
func TestAppBypassDecision(t *testing.T) {
	cases := []struct {
		name          string
		ownerResolved bool
		ownerExcluded bool
		wantBypass    bool
		wantReason    string
	}{
		{
			name:          "unresolved owner is fail-open passthrough",
			ownerResolved: false,
			ownerExcluded: false,
			wantBypass:    true,
			wantReason:    appBypassReasonUnresolved,
		},
		{
			name:          "unresolved owner fails open even if a stale excluded flag is set",
			ownerResolved: false,
			ownerExcluded: true, // must be ignored: ownership is the gate, and it is unresolved
			wantBypass:    true,
			wantReason:    appBypassReasonUnresolved,
		},
		{
			name:          "resolved excluded app is bypassed",
			ownerResolved: true,
			ownerExcluded: true,
			wantBypass:    true,
			wantReason:    appBypassReasonExcluded,
		},
		{
			name:          "resolved non-excluded app is steered",
			ownerResolved: true,
			ownerExcluded: false,
			wantBypass:    false,
			wantReason:    "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bypass, reason := appBypassDecision(tc.ownerResolved, tc.ownerExcluded)
			if bypass != tc.wantBypass || reason != tc.wantReason {
				t.Fatalf("appBypassDecision(resolved=%v, excluded=%v) = (%v, %q), want (%v, %q)",
					tc.ownerResolved, tc.ownerExcluded, bypass, reason, tc.wantBypass, tc.wantReason)
			}
		})
	}
}
