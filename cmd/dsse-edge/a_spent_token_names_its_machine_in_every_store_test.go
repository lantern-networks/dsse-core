package main

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolltoken"
)

// ★★★ EVERY STORE SAYS IT, BECAUSE A GENERATED DEPLOYMENT RUNS THE OTHER ONE (2026-09-01).
//
// "enrolment token has already been used" was made to name the machine that spent it and when. The change
// landed in the in-memory store, a test of the wire builder passed, the build was shipped to a live
// three-region deployment — and the answer came back
//
//	error="used"  used_by=null  used_at=null
//
// because a generated deployment keeps its tokens in Postgres, and that store had its own copy of the same
// four refusals. A message improved in the store nobody runs improves nothing anybody reads.
//
// So this walks BOTH: whichever backend a deployment is configured with, the operator gets the same sentence.
// It is the shape this repository keeps finding — a concrete store swapped in, and a path quietly off.
func TestASpentTokenNamesItsMachineInEveryStore(t *testing.T) {
	const tenant, first, second = "tenant_kaede", "skusanagi-win10", "shinnomac-mini"
	now := time.Date(2026, 8, 31, 21, 21, 17, 0, time.UTC)

	t.Run("the in-memory store", func(t *testing.T) {
		store := enrolltoken.NewStore()
		tok, secret, err := store.Issue(enrolltoken.Policy{}, tenant, "default", "one machine", "adm", "admin@kaede.lab",
			now.Add(24*time.Hour), now)
		if err != nil {
			t.Fatalf("issue: %v", err)
		}
		if _, err := store.Spend(tok.ID, tenant, first, now); err != nil {
			t.Fatalf("first spend: %v", err)
		}
		_, err = store.Verify(secret, tenant, now.Add(time.Hour))
		assertNamesTheMachine(t, err, first, now)
		_, err = store.Spend(tok.ID, tenant, second, now.Add(time.Hour))
		assertNamesTheMachine(t, err, first, now)
	})

	t.Run("the store a generated deployment runs", func(t *testing.T) {
		// enrolmentTokenUsability is where the Postgres store decides; calling it directly keeps this a unit
		// test while still covering the code path that answered the live deployment.
		spent := enrolltoken.Token{
			ID: "ent_x", TenantID: tenant,
			UsedBy: first, UsedAt: now.Format(time.RFC3339),
			ExpiresAt: now.Add(24 * time.Hour).Format(time.RFC3339),
		}
		assertNamesTheMachine(t, enrolmentTokenUsability(spent, tenant, now.Add(time.Hour)), first, now)
	})
}

// assertNamesTheMachine holds both stores to one sentence: still the sentinel every caller branches on, and
// carrying the two facts that make it actionable.
func assertNamesTheMachine(t *testing.T, err error, machine string, when time.Time) {
	t.Helper()
	if err == nil {
		t.Fatal("a spent token was accepted")
	}
	if !errors.Is(err, enrolltoken.ErrTokenUsed) {
		t.Fatalf("%v is not the spent-token sentinel — /enroll branches on it", err)
	}
	for _, want := range []string{machine, when.Format(time.RFC3339), "one machine, once"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the line an operator reads does not contain %q: %s", want, err.Error())
		}
	}
}
