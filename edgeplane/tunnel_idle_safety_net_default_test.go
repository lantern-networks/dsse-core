package edgeplane

import (
	"testing"
	"time"
)

// The idle safety net is resource protection. Left unset it must bound
// abandoned flows; it was removed once by being classified as an opt-in
// performance quota, and flows then piled up on every Edge without limit.
func TestTunnelIdleSafetyNetIsOnUnlessExplicitlyDisabled(t *testing.T) {
	for _, tc := range []struct {
		value string
		set   bool
		want  time.Duration
	}{
		{set: false, want: 180 * time.Second},
		{value: "", set: true, want: 180 * time.Second},
		{value: "600", set: true, want: 600 * time.Second},
		{value: "0", set: true, want: 0},
	} {
		if tc.set {
			t.Setenv("DSSE_NE_TUNNEL_IDLE_TIMEOUT_SECONDS", tc.value)
		}
		if got := resolveNetworkExtensionRuntimeCopyTunnelIdleTimeout(); got != tc.want {
			t.Fatalf("value=%q set=%v: got %v, want %v", tc.value, tc.set, got, tc.want)
		}
	}
}
