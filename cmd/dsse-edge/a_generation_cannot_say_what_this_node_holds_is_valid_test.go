package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ★★★ TWELVE HOURS AFTER IT WAS BUILT, EVERY ORGANIZATION OF A THREE-REGION DEPLOYMENT WAS DOWN (2026-09-08).
//
//	05:15:28  tenant_edge_material installed … soonest expiry 2026-09-07T17:15:28Z    ← installs=1, and only 1
//	17:15:28  every device of every organization begins failing the handshake
//	20:31     still failing; every Edge still serving the expired certificate
//
// The Edge asks the control plane every minute whether anything has changed, and pays for material only when
// it has. In between it was told "unchanged" about seven hundred times. That answer was TRUE — the authority
// had not changed — and it was not the question that mattered, which is whether what this node HOLDS is still
// valid. The two were conflated when the two-thirds refresh was replaced by the generation poll on
// 2026-08-20, and the refresh it replaced was not put back.
//
// Devices and connectors pin their own organization's authority, so they refused the expired certificate
// correctly and had no way back until a person restarted something.

func fetcherAgainst(t *testing.T, seen *[]uint64, expiryFromNow time.Duration) *tenantTransportMaterialFetcher {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			KnownGeneration uint64 `json:"known_generation"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		*seen = append(*seen, body.KnownGeneration)
		// The control plane's own rule: a generation that matches means nothing is minted. Anything else —
		// including zero — falls through and material is issued.
		if body.KnownGeneration == 7 {
			_ = json.NewEncoder(w).Encode(map[string]any{"unchanged": true, "generation": 7})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"generation": 7, "materials": []any{}})
	}))
	t.Cleanup(srv.Close)
	f := &tenantTransportMaterialFetcher{
		endpoint: srv.URL, client: srv.Client(), tenants: func() []string { return nil },
		log: func(string, ...any) {}, generation: 7,
	}
	f.expiry = time.Now().Add(expiryFromNow)
	f.installedAt = f.expiry.Add(-12 * time.Hour) // a twelve-hour life, the deployment's own
	return f
}

func TestTheCheapQuestionIsAskedWhileTheMaterialIsFresh(t *testing.T) {
	var seen []uint64
	f := fetcherAgainst(t, &seen, 11*time.Hour) // one hour into a twelve-hour life
	if _, err := f.FetchOnce(); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(seen) != 1 || seen[0] != 7 {
		t.Fatalf("while the material is fresh this node must ask the cheap question, sent %v", seen)
	}
}

func TestPastTwoThirdsOfItsLifeThisNodeAsksForMaterialOutright(t *testing.T) {
	var seen []uint64
	f := fetcherAgainst(t, &seen, 3*time.Hour) // nine hours into a twelve-hour life
	if _, err := f.FetchOnce(); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(seen) != 1 || seen[0] != 0 {
		t.Fatalf("past two thirds of its life this node must drop the generation and get material minted, "+
			"sent %v — with the generation attached the control plane answers \"unchanged\", which is true "+
			"and is not the question: this is how every organization of a deployment went down twelve hours "+
			"after it was built", seen)
	}
}

// Expired already, and still asking: the node must not go quiet because the moment to renew has passed.
func TestMaterialThatHasAlreadyExpiredIsStillAskedFor(t *testing.T) {
	var seen []uint64
	f := fetcherAgainst(t, &seen, -2*time.Hour)
	if _, err := f.FetchOnce(); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(seen) != 1 || seen[0] != 0 {
		t.Fatalf("expired material must be asked for outright, sent %v", seen)
	}
}

// A node holding nothing keeps the ordinary path: it has no lifetime to take a fraction of, and asking
// outright on every poll would mint a certificate a minute per organization.
func TestANodeHoldingNothingDoesNotMintOnEveryPoll(t *testing.T) {
	var seen []uint64
	f := fetcherAgainst(t, &seen, 11*time.Hour)
	f.expiry, f.installedAt = time.Time{}, time.Time{}
	if _, err := f.FetchOnce(); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(seen) != 1 || seen[0] != 7 {
		t.Fatalf("a node with nothing held must still ask the cheap question, sent %v", seen)
	}
}
