package runtimequota

import "testing"

func TestStartupRejectsLazyResourceSettingsBeforeAnyTraffic(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"DSSE_TCP_STREAM_MAX_BYTES", "1GB"},
		{"DSSE_TCP_STREAM_MAX_LIFETIME_SECONDS", "-1"},
		{"DSSE_TCP_STREAM_IDLE_TIMEOUT_SECONDS", "9223372037"},
		{"DSSE_HTTP2_MAX_CONCURRENT_STREAMS", "4294967296"},
		{"DSSE_NE_ABANDONED_HALF_CLOSE_LINGER_MILLISECONDS", "9223372036855"},
		{"DSSE_EGRESS_ENGINE_WORKERS", "bad"},
		{"DSSE_ENROL_BURST", "0.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.name, tc.value)
			if ValidateEnvironment() == nil {
				t.Fatal("bad setting accepted at startup")
			}
		})
	}
}
