package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// A risk signal MARKS. It does not cut.
//
// Marking a device or user high-risk used to revoke their standing east-west grants on the spot, and the same
// thing happened again on every node when the mark propagated. That is enforcement decided by an ingested
// signal instead of by policy, and it produced access that vanished for reasons an operator could not find in
// any rule they had written — nothing to point at, nothing to scope, nothing to argue with.
//
// The severity still reaches every node's decision path. A policy gating on risk_state_severity is what refuses
// the device, per request, where it can be read.
func TestRiskSignalMarksButNeverCuts(t *testing.T) {
	for _, sev := range []string{"high", "critical", "medium", "none"} {
		resp, err := applyAdminRiskSignal(nil, "tenant_x", model.RiskSignal{
			EntityType: "user", EntityID: "u-alice", Severity: sev,
		}, time.Now().UTC())
		if err != nil {
			t.Fatalf("severity %q: %v", sev, err)
		}
		if resp.StandingGrantsCut != 0 {
			t.Fatalf("severity %q cut %d standing grant(s) — a risk signal must never revoke access; policy decides",
				sev, resp.StandingGrantsCut)
		}
		wantHigh := sev == "high" || sev == "critical"
		if resp.HighRisk != wantHigh {
			t.Fatalf("severity %q: HighRisk=%v want %v — the MARK must still be reported so a policy can gate on it",
				sev, resp.HighRisk, wantHigh)
		}
	}
}

// Access is taken away by a rule an operator wrote, or by an administrator acting deliberately. Nothing else.
//
// This reads the source rather than the behaviour because the failure it guards against is a re-wiring: someone
// hands the grant revoker to a heartbeat handler, a sync loop or a signal ingest again, and every behavioural
// test still passes because each piece works. Three separate paths had done exactly that.
func TestOnlyTheExplicitAdminRouteRevokesStandingGrants(t *testing.T) {
	// The single legitimate caller: the admin east-west grant-revoke route, via oss/eastwest.RevokeGrants.
	allowed := map[string]bool{
		filepath.Join("..", "..", "eastwest", "grant.go"): true,
		filepath.Join("..", "..", "policy", "store.go"):   true, // the implementation itself
	}
	var offenders []string
	roots := []string{".", filepath.Join("..", "..")}
	for _, root := range roots {
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if allowed[path] {
				return nil
			}
			body, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			for _, line := range strings.Split(string(body), "\n") {
				// A call, not the interface declaration or a comment about it.
				if strings.Contains(line, "RevokeEastWestGrants(") && strings.Contains(line, ".RevokeEastWestGrants(") &&
					!strings.HasPrefix(strings.TrimSpace(line), "//") {
					offenders = append(offenders, path+": "+strings.TrimSpace(line))
				}
			}
			return nil
		})
	}
	if len(offenders) > 0 {
		t.Fatalf("standing east-west grants are revoked outside the explicit admin route:\n  %s\n"+
			"A high-risk or degraded device is denied when a POLICY denies it. Automatic signals mark; they do not cut.",
			strings.Join(offenders, "\n  "))
	}
}
