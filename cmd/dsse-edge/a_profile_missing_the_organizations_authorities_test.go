package main

import (
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/installprofile"
)

// ★★★ AN INCOMPLETE PROFILE INSTALLS, WHICH IS WHY IT MUST NOT BE ISSUED (2026-08-31, measured live).
//
// Three organizations were minted their own authorities while one region's control plane led. Leadership
// moved. Every profile issued after that was 200, correctly signed, and carried no device-CA pin, no
// interception root, no transport anchors and no organization door name — a device installed from it enrols
// at the deployment-wide name, pins nothing, and refuses every page the moment its Edge inspects. Nothing on
// any screen distinguished it from a good one.
func TestAProfileThisNodeCannotCompleteIsRefused(t *testing.T) {
	cases := []struct {
		name       string
		known      bool
		spec       installprofile.DeploymentSpec
		wantRefuse bool
	}{
		{
			name:       "the organization has authorities and this node holds them",
			known:      true,
			spec:       installprofile.DeploymentSpec{DeviceCAPinSHA256: "abc", InterceptionRootPEM: "-----BEGIN CERTIFICATE-----"},
			wantRefuse: false,
		},
		{
			name:       "the organization has authorities and this node cannot see them",
			known:      true,
			spec:       installprofile.DeploymentSpec{},
			wantRefuse: true,
		},
		{
			// A real, supported state: the deployment's own authorities cover this organization, and the
			// profile says so by carrying none. Refusing here would make a working deployment un-installable.
			name:       "the organization has none of its own",
			known:      false,
			spec:       installprofile.DeploymentSpec{},
			wantRefuse: false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			now := func() time.Time { return time.Unix(1_760_000_000, 0).UTC() }
			// A device authority that HAS this organization is the only half needed to state the case: the
			// question this asks is "does this node know the organization has one", not "can it produce it".
			device := newTenantDeviceAuthority(nil, func([]byte) error { return nil }, now)
			config := serverConfig{}
			if c.known {
				if _, err := device.EnsureCA("t1", "Test Organization"); err != nil {
					t.Fatalf("mint the organization's device authority: %v", err)
				}
				config.TenantDeviceAuthority = device
			} else {
				config.TenantDeviceAuthority = device
			}
			got := organizationAuthoritiesUnavailable(config, "t1", c.spec)
			if (got != "") != c.wantRefuse {
				t.Fatalf("organizationAuthoritiesUnavailable = %q, want refuse=%v", got, c.wantRefuse)
			}
			if c.wantRefuse {
				msg := refuseTheProfileThisNodeCannotComplete("t1", got).Error()
				for _, want := range []string{"pins nothing", "minted them"} {
					if !strings.Contains(msg, want) {
						t.Errorf("the refusal does not tell an operator what to do: %q missing %q", msg, want)
					}
				}
			}
		})
	}
}
