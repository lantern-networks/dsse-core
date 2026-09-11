package main

import "testing"

// splitSteerAuthorityMeta is shared by CONNECT /steer and /steer-mux so the two transports parse the steer OPEN
// authority identically. A past defect: /steer omitted this parse and silently dropped the logged-in OS user
// (docs/mac_ne_os_user_missing_in_logs.md, break point A). These cases lock in the symmetric behaviour.
func TestSplitSteerAuthorityMeta(t *testing.T) {
	cases := []struct {
		name                            string
		authority                       string
		wantHostPort, wantUser, wantApp string
	}{
		{"plain host:port (old agent, no metadata)", "example.com:443", "example.com:443", "", ""},
		{"os user only", "example.com:443\x00u=alice", "example.com:443", "alice", ""},
		{"os user + app", "10.0.0.5:22\x00u=bob a=ssh", "10.0.0.5:22", "bob", "ssh"},
		{"non-interactive system account is blanked", "sink.internal:443\x00u=SYSTEM", "sink.internal:443", "", ""},
		{"ipv6 literal host:port with user", "[2001:db8::1]:443\x00u=carol", "[2001:db8::1]:443", "carol", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hp, user, app := splitSteerAuthorityMeta(tc.authority)
			if hp != tc.wantHostPort {
				t.Errorf("hostPort = %q, want %q", hp, tc.wantHostPort)
			}
			if user != tc.wantUser {
				t.Errorf("osUser = %q, want %q", user, tc.wantUser)
			}
			if app != tc.wantApp {
				t.Errorf("sourceApp = %q, want %q", app, tc.wantApp)
			}
		})
	}
}
