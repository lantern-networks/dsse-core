package main

import (
	"strings"
	"testing"
)

// ★★★ A JOINING REGION'S CONTROL PLANES WAITED FOR NOTHING AND DIED ON THEIR OWN DATABASE (2026-08-29,
// measured while building a two-region deployment):
//
//	open CP-state blob store: ping cp-state blob db: dial tcp: lookup postgres on 127.0.0.11:53: no such host
//
// The founding shape waits for dsse-postgres-init, which by definition means the database is answering. The
// joining shape correctly does not run that init — a database that already exists must not be initialised
// again — and in dropping it, dropped its only ordering dependency. Both control planes started before the
// database's front door existed and exited. Compose reported success. `docker ps` showed a control-plane
// machine with no control planes on it, which is exactly what the fleet view shows for a region nobody
// switched on.
//
// ★ IT IS A RACE, so it survived the build the day before — that time the door won. A test is the only place
// a race like this can be held still.
func TestAJoiningRegionsControlPlanesWaitForTheirDatabase(t *testing.T) {
	joining := joiningStateBearingServices()

	// ★ AND THE DOOR IS BACK (2026-09-02, the same day it was removed). Waiting for the local member was
	// wrong for a second reason beyond ordering: this deployment has one Postgres cluster across its regions,
	// so a joining region's own member is a REPLICA, and a control plane that reaches it directly cannot
	// write. The door health-checks Patroni's GET /primary across every member and forwards to the one that
	// can. See composeDatabaseDoor.
	if !strings.Contains(joining, "postgres: { condition: service_started }") {
		t.Errorf("a joining region's control planes name nothing to wait for:\n%s",
			lineContaining(joining, "depends_on"))
	}
	// The control that says this test is about ORDER and not about the string: the joining region must still
	// not DEPEND on the database init, which it does not define, or compose refuses the whole file. The name
	// appears in the comments either way, so the assertion is about the dependency and not the mention.
	if strings.Contains(joining, "dsse-postgres-init: { condition:") {
		t.Error("a joining region depends on dsse-postgres-init — it does not define it, and compose refuses " +
			"a file that depends on an undefined service")
	}
	// ★ AND ORDER IS NOT ENOUGH ON ITS OWN. The process fatals when the database cannot be opened, so a
	// database that is late by more than the door's start-up leaves the region without a control plane until
	// somebody looks.
	//
	// ★★ BOTH HALVES, COUNTED (2026-08-29, an hour after the first version of this fix). The pair is ONE
	// string with dsse-control-plane-a and -b in it, and writing the policy into the -a block by hand gave it
	// to one and not the other: on the live build the region's control plane recovered and its standby stayed
	// dead. A half-fixed pair is worse than an unfixed one, because it looks like it works.
	for _, shape := range []struct {
		name, body string
	}{{"joining", joining}, {"founding", stateBearingServices()}} {
		// ★ ONE CONTROL PLANE PER MACHINE SINCE 2026-09-02, so what has to hold is that IT retries: a region
		// whose control plane does not come back after its database does is a region that stays silent while
		// looking installed.
		// ★ AND "RETRIES" IS NOT ENOUGH — IT MUST ALSO COME BACK (2026-09-06). This counted
		// `restart: on-failure`, which retries a control plane whose database was slow and declines one that
		// exited cleanly. A machine that is stopped and started again stops every container cleanly, so a
		// region brought back served its door with its Edge and nothing behind it, while the fleet view read
		// that Edge and called the region current. The property this test is about is the same one; the
		// spelling that satisfies it is the stronger policy.
		if got := strings.Count(shape.body, "restart: unless-stopped"); got < 1 {
			t.Errorf("the %s region does not bring its control plane back (%d) — it would stay dead after a "+
				"database that was merely slow to start, and after any restart of its machine", shape.name, got)
		}
	}
	// And the YAML is still the shape compose reads: the retry must not land between depends_on and its
	// entries, which is where the first attempt at making it structural put it.
	if strings.Contains(joining, "depends_on:\n    restart:") {
		t.Error("the restart policy was written between depends_on and its entries — the file will not parse")
	}

	// ★ THE FOUNDING SHAPE KEEPS ITS OWN ANSWER. It waits for the initialisation to COMPLETE, which is a
	// stronger statement than the door being up, and it must not be weakened to match.
	founding := stateBearingServices()
	if !strings.Contains(founding, "dsse-postgres-init: { condition: service_completed_successfully }") {
		t.Error("the founding region no longer waits for its database to be initialised")
	}
}
