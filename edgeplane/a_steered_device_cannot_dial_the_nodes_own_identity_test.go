package edgeplane

import (
	"context"
	"strings"
	"testing"

	swg "github.com/lantern-networks/dsse-core/swg"
)

// ★★★ A STEERED DEVICE MUST NOT REACH WHAT ONLY THE NODE CAN REACH (2026-08-31, reproduced on a real Mac).
//
// From an armed laptop, through the tunnel: an IMDSv2 token from 169.254.169.254, then the node's role name,
// then `aws sts get-caller-identity` answering assumed-role/dsse-lab-node. The device had the cloud identity
// of the node carrying its traffic, and every steered device could.
//
// The guard already existed and the SWG's HTTP path already called it — that is the 502 a steered browser
// gets for an internal address. The transparent steer path, which carries everything else a device sends,
// never asked. This test is on the DIALER, because that is the thing every steered flow goes through.
func TestTheSteerDialerRefusesWhatOnlyTheNodeCanReach(t *testing.T) {
	// ★ AND IT PUTS THE FLAG BACK. swg's internal-block switch is process-global, so a test that turns it on
	// and walks away changes what every test after it in this package measures — this one passed alone and
	// failed in the suite until it restored what it found.
	wasOn := swg.CheckEgressDestination(context.Background(), "169.254.169.254") != nil
	swg.SetInternalBlockEnabled(true)
	t.Cleanup(func() { swg.SetInternalBlockEnabled(wasOn) })
	dialer := NetworkExtensionRuntimeCopyNetDialer{}
	for _, dest := range []struct {
		name string
		host string
	}{
		{"the cloud metadata service", "169.254.169.254"},
		{"anything else link-local", "169.254.1.1"},
		{"loopback", "127.0.0.1"},
		{"the node's own private network", "10.20.1.164"},
		{"IPv6 link-local", "fe80::1"},
	} {
		t.Run(dest.name, func(t *testing.T) {
			_, err := dialer.OpenTCPConnection(context.Background(),
				NetworkExtensionRuntimeCopyTCPRoute{Host: dest.host, Port: 80})
			if err == nil {
				t.Fatalf("a steered flow to %s (%s) was dialled. On a cloud node that is the device assuming "+
					"the node's IAM role; on any node it is the customer's internal network reachable from "+
					"every managed laptop", dest.name, dest.host)
			}
			if !strings.Contains(err.Error(), "refused before it was dialled") {
				t.Errorf("the refusal does not say what happened: %v", err)
			}
		})
	}
}
