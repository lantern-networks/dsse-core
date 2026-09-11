//go:build windows

package main

import (
	"testing"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

// ★ The property that matters here is IDEMPOTENCE against a service that is already up.
//
// doReconcileStartType runs on EVERY install and upgrade, and on most of them DsseSteer is already running.
// StartService on a running service returns ERROR_SERVICE_ALREADY_RUNNING rather than doing nothing, so a naive
// call would report "THIS BOX IS NOT STEERING" on a box that is steering perfectly — the false alarm attached
// to the normal outcome, which is the failure this repository keeps rediscovering. It would also be the loudest
// possible way to be wrong, since the warning tells an operator their machine is unprotected.
//
// Run against a real running service rather than a fake: the thing under test is what the SCM answers, and a
// fake would be my own opinion of that. EventLog is used rather than DsseSteer because this must not be able to
// start the steering agent on a machine where it is deliberately stopped — the assertion is about the
// already-running branch, and EventLog is always running.
func TestStartingAnAlreadyRunningServiceIsNotAFailure(t *testing.T) {
	const name = "EventLog"

	m, err := mgr.Connect()
	if err != nil {
		t.Skipf("cannot reach the service control manager: %v", err)
	}
	s, err := m.OpenService(name)
	if err != nil {
		m.Disconnect()
		t.Skipf("cannot open %s: %v", name, err)
	}
	st, err := s.Query()
	s.Close()
	m.Disconnect()
	if err != nil {
		t.Skipf("cannot query %s: %v", name, err)
	}
	if st.State != svc.Running {
		t.Skipf("%s is not running (state %v), so the already-running branch cannot be exercised", name, st.State)
	}

	if err := startServiceIfStopped(name); err != nil {
		t.Fatalf("startServiceIfStopped(%q) reported a failure for a service that is already RUNNING: %v — an "+
			"upgrade of a healthy box would print that it is not steering", name, err)
	}

	// And it must not have disturbed the service it found healthy.
	m2, err := mgr.Connect()
	if err != nil {
		t.Fatalf("reconnect: %v", err)
	}
	defer m2.Disconnect()
	s2, err := m2.OpenService(name)
	if err != nil {
		t.Fatalf("reopen %s: %v", name, err)
	}
	defer s2.Close()
	after, err := s2.Query()
	if err != nil {
		t.Fatalf("re-query %s: %v", name, err)
	}
	if after.State != svc.Running {
		t.Fatalf("%s is in state %v after the call; a service that was already running must be left alone",
			name, after.State)
	}
}

// A name the SCM does not know must be reported, not swallowed. The caller turns this into the warning that
// says the box is not steering, and that sentence has to be reachable — a version of this that returned nil on
// every error would be indistinguishable from one that worked.
func TestAnUnknownServiceIsReported(t *testing.T) {
	if err := startServiceIfStopped("DsseNoSuchServiceForTest"); err == nil {
		t.Fatal("opening a service that does not exist returned no error; a genuine failure to start the agent " +
			"would be silent")
	}
}
