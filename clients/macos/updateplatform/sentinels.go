package updateplatform

import (
	"path"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

// sentinels.go — the shared sentinels observe.go raises, bound WITHOUT a build tag.
//
// ★ Why this file exists rather than the aliases living in platform_darwin.go, where they started.
//
// observe.go carries no build tag on purpose: it is the pure half — what counts as a running version, when a
// heartbeat is too old to believe — and the whole point of keeping it tag-free is that those decisions are
// compiled and tested on any host. The aliases it depends on were defined behind //go:build darwin, so the
// package built on macOS and failed everywhere else:
//
//	vet: clients/macos/updateplatform/observe.go:192:65: undefined: errAgentNotRunning
//
// That is the same shape as the defect the Windows session hit in its own session-folding code, and the same
// one the tree keeps closing: a decision that compiles only on the platform that wrote it is a decision no
// other host can check. Here the cost was not subtle — it stopped every push from the Windows box, because
// the pre-push gate builds the whole oss module and only macOS could satisfy it.
//
// The intent behind the original placement is kept: observe.go still does not import agentupdate, so the
// pure file stays free of it and both platforms answer with one vocabulary.
var (
	errAgentNotRunning       = agentupdate.ErrAgentNotRunning
	errRunningVersionUnknown = agentupdate.ErrRunningVersionUnknown
)

// DataRoot is where DSSE keeps endpoint state on macOS: the same directory the agent config already lives in,
// so an operator has one place to look rather than two.
const DataRoot = "/Library/Application Support/Dsse"

// dataRootOverride redirects the paths below, for TESTS ONLY.
//
// ★ A TEST REACHED THE REAL DEVICE (2026-08-12, twelfth review). The whole-pass dry-run test runs a REAL pass,
// which reaches ClearStaged — and every path here was a constant, so running that suite as root on a machine
// with the agent installed would delete the staged package of the release it is actually holding. A test that
// can damage the device it is testing on is not one to leave loaded.
//
// Deliberately unexported with an exported setter that only tests call: production has no way to move these,
// which is the property the constant was protecting.
var dataRootOverride string

// SetDataRootForTest redirects the endpoint state directory. Returns a function restoring the previous value.
func SetDataRootForTest(dir string) func() {
	previous := dataRootOverride
	dataRootOverride = dir
	return func() { dataRootOverride = previous }
}

func dataRoot() string {
	if dataRootOverride != "" {
		return dataRootOverride
	}
	return DataRoot
}

// ★ These build a macOS TARGET path, so they use path.Join and not filepath.Join.
//
// The difference only shows off macOS, and it showed loudly: IntentPath() is compared against a literal inside
// the installer's shell script by a test in the main module, and on a Windows host filepath.Join produced
// backslashes. The test failed on a machine where nothing was wrong, which blocked every push from that box —
// the same cost this file's own header describes. A path that names a location on ANOTHER system is not a host
// path, and asking the host to spell it was the mistake.
func RuntimeMarkerPath() string { return path.Join(dataRoot(), "runtime_version.json") }

// RollbackRoot is where the installer leaves the .pkg a rollback would reinstall.
func RollbackRoot() string { return path.Join(dataRoot(), "rollback") }

// StagedRoot is where a verified artifact waits for the installer.
func StagedRoot() string { return path.Join(dataRoot(), "staged") }
