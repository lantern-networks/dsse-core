package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ★★★ THE NODE MUST NOT SCHEDULE ITS OWN OUTAGE (2026-09-08, written from a measured one).
//
// A single transient fetch failure four seconds after start-up put one region's Edge to sleep for ten
// minutes while it held six minutes of material. It woke four minutes after the end, having served an
// expired certificate to every connector that reached it in between. Nothing was wrong with the failure —
// the fleet was mid-roll — and nothing was wrong with the warning it printed. What was wrong was that the
// interval was a constant and the material's life was not.
//
// These cases are the boundary: the same constant is right against long material and fatal against short.
func TestTheBackoffAfterAFailedFetchNeverOutlivesTheMaterial(t *testing.T) {
	now := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	ordinary := 10 * time.Minute

	for _, c := range []struct {
		name      string
		remaining time.Duration
		want      time.Duration
	}{
		// Twelve-hour material, which is the deployment default: the ordinary back-off is unchanged, and
		// this case is why it can be ten minutes at all.
		{"twelve hours left", 12 * time.Hour, 10 * time.Minute},
		{"one hour left", time.Hour, 10 * time.Minute},
		// Forty minutes is where a quarter of the life becomes the shorter of the two.
		{"forty minutes left", 40 * time.Minute, 10 * time.Minute},
		{"thirty-six minutes left", 36 * time.Minute, 9 * time.Minute},
		// ★ THE MEASURED ONE. Six minutes of material and a ten-minute back-off cost four minutes of an
		// expired door. Three more attempts must fit before the end.
		{"six minutes left — the outage", 6 * time.Minute, 90 * time.Second},
		{"one minute left", time.Minute, 15 * time.Second},
		// Nearly gone: the floor, so a doomed node does not spin — but never past the end, because the floor
		// is a constant too. The attempt after these finds the material expired and reportFetchFailure
		// leaves the fleet, which is the designed answer.
		{"ten seconds left — the floor", 10 * time.Second, 5 * time.Second},
		{"four seconds left — half of what is left", 4 * time.Second, 2 * time.Second},
	} {
		f := &tenantTransportMaterialFetcher{expiry: now.Add(c.remaining)}
		got := f.backoffAfterFailure(now, ordinary)
		if got != c.want {
			t.Errorf("%s: waited %s, wanted %s", c.name, got, c.want)
		}
		// The rule stated as a rule, not as a table: while the node still holds valid material, the wait
		// must leave room to try again before that material ends.
		if got >= c.remaining {
			t.Errorf("%s: the node would sleep %s past its own material's end (%s left)",
				c.name, got-c.remaining, c.remaining)
		}
	}

	// A node holding nothing has no life to be shorter than, and must not be pushed into a hot loop by this.
	empty := &tenantTransportMaterialFetcher{}
	if got := empty.backoffAfterFailure(now, ordinary); got != 10*time.Second {
		t.Errorf("a node holding no material backed off %s instead of 10s", got)
	}
	// Past the end the interval is moot — reportFetchFailure is leaving — but it must still be finite.
	past := &tenantTransportMaterialFetcher{expiry: now.Add(-time.Minute)}
	if got := past.backoffAfterFailure(now, ordinary); got != ordinary {
		t.Errorf("a node past its material's end backed off %s instead of the ordinary %s", got, ordinary)
	}
}

// ★ AND THE LINE THE OPERATOR READS NAMES THE INTERVAL THAT WAS CHOSEN. The old line said "backing off to
// 10m" whatever it did. A reader who checked the log during the measured outage would have been told the
// node was retrying every ten minutes, which was true — and would have had no way to see that ten minutes
// was longer than the material. Now the number is the decision.
func TestTheFailureLineNamesTheIntervalItActuallyChose(t *testing.T) {
	lines := []string{}
	f := &tenantTransportMaterialFetcher{
		log:    func(format string, a ...any) { lines = append(lines, sprintf(format, a...)) },
		fatal:  func(format string, a ...any) {},
		expiry: time.Now().Add(6 * time.Minute),
	}
	f.reportFetchFailure(errString("EOF"), f.backoffAfterFailure(time.Now(), 10*time.Minute))
	joined := strings.Join(lines, " | ")
	if !strings.Contains(joined, "backing off to 1m30s") {
		t.Fatalf("the failure line did not name the interval it chose: %v", lines)
	}
	if strings.Contains(joined, "backing off to 10m") {
		t.Fatalf("the failure line still states the constant: %v", lines)
	}
}

// Reproduce bootstrap's transient 503, followed by an empty deployment and then its first authority.
// Both empty states must retry promptly; installing material resumes the normal refresh schedule.
func TestBootstrapMaterialRecoversAfterUnavailableAndEmptyAnswers(t *testing.T) {
	useEmptyTenantCertificateIndex(t)
	authority := newTenantTransportAuthority(nil, nil, time.Now)
	if _, err := authority.EnsureCA("tenant_bootstrap", "tenant_bootstrap.example.com"); err != nil {
		t.Fatal(err)
	}
	material, err := authority.IssueFor("tenant_bootstrap", "edge-a", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			w.WriteHeader(http.StatusServiceUnavailable)
		case 2:
			json.NewEncoder(w).Encode(map[string]any{"materials": []tenantTransportMaterial{}, "generation": 1})
		default:
			json.NewEncoder(w).Encode(map[string]any{"materials": []tenantTransportMaterial{material}, "generation": 2})
		}
	}))
	defer srv.Close()
	f := &tenantTransportMaterialFetcher{endpoint: srv.URL, token: "test", client: srv.Client(), tenants: func() []string { return nil }, log: func(string, ...any) {}}
	for attempt := 1; attempt <= 3; attempt++ {
		expiry, err := f.FetchOnce()
		if (attempt == 1) != (err != nil) {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		if !expiry.IsZero() {
			f.expiry = expiry
		}
		wait := f.nextFetchWait(time.Now(), err)
		if attempt < 3 && wait != 10*time.Second {
			t.Fatalf("empty attempt %d waits %s; recovery would be delayed", attempt, wait)
		}
		if attempt == 3 {
			if expiry.IsZero() || f.installedTenants.Load() != 1 {
				t.Fatal("first organization's material was not installed")
			}
			if wait != time.Minute {
				t.Fatalf("installed material refresh waits %s", wait)
			}
		}
	}
}
