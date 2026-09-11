package runstate

import (
	"errors"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/agentupdate"
)

func live() Liveness { return Liveness{Running: true, Known: true} }

func recorded(v string) Record { return Record{Version: v, Present: true, PID: 6084} }

func TestARunningAgentReportsItsVersion(t *testing.T) {
	got, err := Resolve(recorded("0.1.0+2e39256d"), live())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "0.1.0+2e39256d" {
		t.Fatalf("got %q", got)
	}
}

// ★ The staleness rule, and the whole reason this is not just a registry read. A crashed agent leaves its last
// version behind; reading that as current would gate an update on a build nobody is running.
func TestAStoredVersionWithNoLiveAgentIsNotARunningVersion(t *testing.T) {
	_, err := Resolve(recorded("0.1.0+2e39256d"), Liveness{Running: false, Known: true})
	if !errors.Is(err, agentupdate.ErrAgentNotRunning) {
		t.Fatalf("got %v, want ErrAgentNotRunning", err)
	}
	// The stale value belongs in the prose — useful to a human, and deliberately not offered as data.
	if !strings.Contains(err.Error(), "0.1.0+2e39256d") {
		t.Fatalf("the message should name the stale value for diagnosis, got %q", err)
	}
	if !strings.Contains(err.Error(), "memory") {
		t.Fatalf("the message must say why the value is not the answer, got %q", err)
	}
}

func TestNoRecordAndNoAgentIsSimplyNotRunning(t *testing.T) {
	_, err := Resolve(Record{}, Liveness{Running: false, Known: true})
	if !errors.Is(err, agentupdate.ErrAgentNotRunning) {
		t.Fatalf("got %v, want ErrAgentNotRunning", err)
	}
}

// ★ An agent older than this mechanism. It must be distinguishable from a dead one, because the fix is
// different — an install, not a recovery — and because these devices have to be countable.
func TestARunningAgentThatRecordsNothingIsItsOwnCase(t *testing.T) {
	_, err := Resolve(Record{}, live())
	if !errors.Is(err, agentupdate.ErrRunningVersionUnknown) {
		t.Fatalf("got %v, want ErrRunningVersionUnknown", err)
	}
	if errors.Is(err, agentupdate.ErrAgentNotRunning) {
		t.Fatal("an agent that IS running must never be reported as not running: the two need opposite responses")
	}
	if !strings.Contains(err.Error(), "re-installed") {
		t.Fatalf("the message must say what actually fixes this device, got %q", err)
	}
}

// An empty value is a different bug from a missing one and must not be silently treated as a version.
func TestAnEmptyRecordedVersionIsNotAVersion(t *testing.T) {
	_, err := Resolve(Record{Version: "   ", Present: true}, live())
	if !errors.Is(err, agentupdate.ErrRunningVersionUnknown) {
		t.Fatalf("got %v, want ErrRunningVersionUnknown", err)
	}
}

// ★ A failed SCM query is a fault and must not resolve into an answer. Turning it into "not running" would let
// one broken API call quietly drop a device out of a rollout while blaming the device.
func TestAnUnqueryableServiceManagerIsAFaultNotAnAnswer(t *testing.T) {
	_, err := Resolve(recorded("0.1.0"), Liveness{Known: false})
	if err == nil {
		t.Fatal("want an error")
	}
	if errors.Is(err, agentupdate.ErrAgentNotRunning) || errors.Is(err, agentupdate.ErrRunningVersionUnknown) {
		t.Fatalf("an unknown must not be reported as either verdict, got %v", err)
	}
}

// The key lives under the service so it inherits the Services ACL and is removed with the service. If this
// ever moves, an uninstalled agent could leave a version behind for something else to read as current.
func TestTheRecordLivesUnderTheServiceKey(t *testing.T) {
	if !strings.HasPrefix(KeyPath, `SYSTEM\CurrentControlSet\Services\DsseSteer\`) {
		t.Fatalf("KeyPath = %q; it must stay under the DsseSteer service key", KeyPath)
	}
}

// TestResolveStartPendingIsSkippedNotJudged is the case that motivated splitting Starting out of Running.
//
// A service in START_PENDING has been launched and may not have reached runstate.Write yet. Folding it into
// Running makes the "running, nothing recorded" branch fire, and that branch means "this agent predates the
// marker, re-install it" — a diagnosis an operator would act on, about a box that was simply starting up.
// The required outcome is the harmless one: ErrAgentNotRunning, which refuses WITHOUT recording a failure, so
// the device is reassessed on the next tick instead of being poisoned or misreported.
func TestResolveStartPendingIsSkippedNotJudged(t *testing.T) {
	starting := Liveness{Known: true, Starting: true}

	// No record yet — the realistic shape of the race.
	if _, err := Resolve(Record{}, starting); !errors.Is(err, agentupdate.ErrAgentNotRunning) {
		t.Fatalf("START_PENDING with no record: err = %v, want ErrAgentNotRunning", err)
	}
	if _, err := Resolve(Record{}, starting); errors.Is(err, agentupdate.ErrRunningVersionUnknown) {
		t.Fatal("START_PENDING reported ErrRunningVersionUnknown, which tells an operator to re-install a box that is merely starting")
	}
	// A stale record from the previous run must not be offered as the running version either.
	got, err := Resolve(Record{Version: "0.1.0+old", Present: true}, starting)
	if err == nil {
		t.Fatalf("START_PENDING with a stale record returned %q as a running version", got)
	}
	if !errors.Is(err, agentupdate.ErrAgentNotRunning) {
		t.Fatalf("START_PENDING with a stale record: err = %v, want ErrAgentNotRunning", err)
	}
}

// TestResolveRunningStillAnswers guards the opposite failure: the new branch must not swallow the normal case.
func TestResolveRunningStillAnswers(t *testing.T) {
	got, err := Resolve(Record{Version: "0.9.9+abcd1234", Present: true}, Liveness{Known: true, Running: true})
	if err != nil {
		t.Fatalf("running agent with a recorded version: %v", err)
	}
	if got != "0.9.9+abcd1234" {
		t.Fatalf("Resolve = %q, want %q", got, "0.9.9+abcd1234")
	}
}
