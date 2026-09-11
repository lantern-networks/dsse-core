package tunnel

import "testing"

func TestValidateProbeRequestFrame(t *testing.T) {
	valid := Frame{Type: FrameProbeRequest, RequestID: "req_1", Host: "jira.internal", Port: 443, ProbeProtocol: ProbeProtocolWeb}
	if err := ValidateProbeRequestFrame(valid); err != nil {
		t.Fatalf("valid probe request rejected: %v", err)
	}

	cases := []struct {
		name  string
		frame Frame
	}{
		{"wrong type", Frame{Type: FrameTCPOpen, RequestID: "r", Host: "h", Port: 1}},
		{"missing request id", Frame{Type: FrameProbeRequest, Host: "h", Port: 1}},
		{"missing host", Frame{Type: FrameProbeRequest, RequestID: "r", Port: 1}},
		{"port low", Frame{Type: FrameProbeRequest, RequestID: "r", Host: "h", Port: 0}},
		{"port high", Frame{Type: FrameProbeRequest, RequestID: "r", Host: "h", Port: 70000}},
		{"bad protocol", Frame{Type: FrameProbeRequest, RequestID: "r", Host: "h", Port: 1, ProbeProtocol: "ftp"}},
		{"timeout over max", Frame{Type: FrameProbeRequest, RequestID: "r", Host: "h", Port: 1, ConnectTimeoutMillis: MaxProbeTimeoutMillis + 1}},
	}
	for _, tc := range cases {
		if err := ValidateProbeRequestFrame(tc.frame); err == nil {
			t.Fatalf("%s: expected validation error", tc.name)
		}
	}
}

func TestProbeTimeoutMillisOrDefault(t *testing.T) {
	if got := ProbeTimeoutMillisOrDefault(0); got != DefaultProbeTimeoutMillis {
		t.Fatalf("zero -> %d, want default %d", got, DefaultProbeTimeoutMillis)
	}
	if got := ProbeTimeoutMillisOrDefault(MaxProbeTimeoutMillis + 5000); got != MaxProbeTimeoutMillis {
		t.Fatalf("over-max -> %d, want clamp %d", got, MaxProbeTimeoutMillis)
	}
	if got := ProbeTimeoutMillisOrDefault(1234); got != 1234 {
		t.Fatalf("in-range -> %d, want 1234", got)
	}
}
