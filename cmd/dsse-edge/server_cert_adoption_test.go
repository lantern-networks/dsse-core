package main

import (
	"path/filepath"
	"testing"
	"time"
)

// The measurement that would have caught the 2026-07-31 outage: a replacement is not adopted until every
// device has RE-HANDSHAKED onto it. A fleet still riding old connections must not read as complete.
func TestServerCertAdoptionSeparatesAppliedFromAdopted(t *testing.T) {
	old := parseAllCerts(testCertPEM(t, "old-identity"))[0]
	current := parseAllCerts(testCertPEM(t, "new-identity"))[0]
	now := time.Now()

	sight := map[string]serverCertSighting{}
	// mac re-handshaked onto the new certificate; win is still on the old one; conn has never been seen.
	sight["mac-dev-1"] = serverCertSighting{Fingerprint: certFingerprint(current), At: now}
	sight["win-dev-1"] = serverCertSighting{Fingerprint: certFingerprint(old), At: now.Add(-time.Hour)}

	rep := buildServerCertAdoption(current, sight, []string{"mac-dev-1", "win-dev-1", "conn-lab-1"})
	if rep.Complete {
		t.Fatal("a replacement is not complete while a device is still on the previous certificate")
	}
	if len(rep.OnCurrent) != 1 || rep.OnCurrent[0] != "mac-dev-1" {
		t.Fatalf("on-current wrong: %v", rep.OnCurrent)
	}
	if len(rep.OnPrevious) != 1 || rep.OnPrevious[0] != "win-dev-1" {
		t.Fatalf("a device on the old certificate must be named: %v", rep.OnPrevious)
	}
	if len(rep.NotSeen) != 1 || rep.NotSeen[0] != "conn-lab-1" {
		t.Fatalf("an identity that has not handshaked is not adopted: %v", rep.NotSeen)
	}

	// Once every device has re-handshaked, and only then, the replacement is complete.
	sight["win-dev-1"] = serverCertSighting{Fingerprint: certFingerprint(current), At: now}
	sight["conn-lab-1"] = serverCertSighting{Fingerprint: certFingerprint(current), At: now}
	if !buildServerCertAdoption(current, sight, []string{"mac-dev-1", "win-dev-1", "conn-lab-1"}).Complete {
		t.Fatal("with every device re-handshaked onto it, the replacement is complete")
	}
}

// C6: the measurement must outlive the process. A rotation every device took yesterday must not read as one
// still waiting for them just because the Edge restarted.
func TestAdoptionMeasurementSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "adoption.json")
	leaf := parseAllCerts(testCertPEM(t, "served"))[0]

	first := &serverCertAdoption{by: map[string]serverCertSighting{}}
	first.load(path) // no file yet: a first run, not a failure
	first.observe("mac-1", leaf, time.Now())
	first.observe("win-1", leaf, time.Now())

	restarted := &serverCertAdoption{by: map[string]serverCertSighting{}}
	restarted.load(path)
	r := buildServerCertAdoption(leaf, restarted.snapshot(), []string{"mac-1", "win-1"})
	if !r.Complete || len(r.NotSeen) != 0 {
		t.Fatalf("a completed rotation must still read as complete after a restart: %+v", r)
	}
	if r.MeasuringSince == "" {
		t.Fatal("the report must say how far back the measurement reaches")
	}

	// And a device moved onto a DIFFERENT certificate is recorded as such, not left on the stale one.
	other := parseAllCerts(testCertPEM(t, "other"))[0]
	restarted.observe("win-1", other, time.Now())
	again := &serverCertAdoption{by: map[string]serverCertSighting{}}
	again.load(path)
	r2 := buildServerCertAdoption(leaf, again.snapshot(), []string{"mac-1", "win-1"})
	if r2.Complete || len(r2.OnPrevious) != 1 || r2.OnPrevious[0] != "win-1" {
		t.Fatalf("a change of certificate must be persisted too: %+v", r2)
	}
}
