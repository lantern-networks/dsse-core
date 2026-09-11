package main

import (
	"os"
	"testing"

	"github.com/lantern-networks/dsse-core/edgeplane"
	"golang.org/x/crypto/bcrypt"
)

// TestMain enables the verbose per-request interception logs for the whole package's tests. In production they
// default OFF (quiet hot path), but several tests assert on hot-path log lines (request_observed,
// http_forward_completed, …), so the test binary turns them on. Keep this the only TestMain in the package.
// It also lowers the password hashing cost, and that half is worth its own paragraph.
//
// ★ MEASURED, 2026-08-10. The pre-push gate was taking over two minutes; this package's suite was ~50 s of it
// and NINE tests were ~41 s of that — every one in the admin-account or credential path, every one slow for
// the same reason: bcrypt at cost 12 is ~0.3 s per hash by design, and they create accounts and log in dozens
// of times. That cost was paid on nearly every push, because oss is a dependency of main so any oss change
// invalidates this package's cached results.
//
// It bought nothing. Not one of those tests asserts anything about how EXPENSIVE the hash is; they exercise
// the lifecycle around it. The property that must not be lost — that production hashes at a real cost — is
// asserted directly by TestProductionPasswordHashingStaysExpensive instead of being implied by the suite
// being slow. That is the better arrangement regardless: "the tests take a while" is not a check, and the day
// someone speeds it up the wrong way, nothing fails.
func TestMain(m *testing.M) {
	edgeplane.SetNetworkExtensionHotPathLogs(true)
	bcryptCost = bcrypt.MinCost
	os.Exit(m.Run())
}
