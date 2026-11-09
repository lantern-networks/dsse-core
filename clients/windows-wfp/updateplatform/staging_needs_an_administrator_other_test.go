//go:build !windows

package updateplatform

import "testing"

// stagingNeedsAnAdministrator: off Windows, the data directory is not handed to an owner, so nothing is needed.
func stagingNeedsAnAdministrator(t *testing.T) { t.Helper() }
