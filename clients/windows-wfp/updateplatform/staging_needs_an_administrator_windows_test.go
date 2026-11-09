//go:build windows

package updateplatform

import (
	"testing"

	"golang.org/x/sys/windows"
)

// stagingNeedsAnAdministrator skips a test that stages, on a token that is not elevated.
//
// Stage creates %ProgramData%\DSSE and hands its ownership to Administrators (datadir's harden), which the
// installer's SYSTEM context and an elevated administrator can assign and a token that is not elevated cannot.
// Without elevation such a test fails at the ownership — or, worse, passes because of it when the failure it
// expects is a different one (a refused download, a poisoned version). Run these tests elevated.
func stagingNeedsAnAdministrator(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip(`staging hands %ProgramData%\DSSE to Administrators, which only an elevated token can assign; run these tests elevated`)
	}
}
