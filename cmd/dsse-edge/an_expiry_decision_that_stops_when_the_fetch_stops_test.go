package main

import (
	"crypto/tls"
	"strings"
	"testing"
	"time"
)

// ★★★ THE JUDGEMENT MUST NOT LIVE INSIDE THE THING THAT REFRESHES IT (2026-09-08, found by review).
//
// Every expiry branch was reached only from a FAILED fetch, so the decision stopped whenever the refresh
// stopped in a way that did not look like failure: a request hanging inside its twenty-second timeout, a 200
// carrying no material, a refusal classified as evidence. Material could pass its end with nothing anywhere
// deciding anything.
//
// These exercise the judge directly, with an injected clock and no I/O at all — which is the point: if the
// decision needed a fetch to happen, this test could not be written.
func TestTheExpiryDecisionRunsWithoutAnyFetch(t *testing.T) {
	useEmptyTenantCertificateIndex(t)
	at := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	useTransportInstallClock(t, func() time.Time { return at })
	useTransportSelectorClock(t, func() time.Time { return at })
	lines, fatals := []string{}, []string{}
	newFetcher := func() *tenantTransportMaterialFetcher {
		return &tenantTransportMaterialFetcher{
			log:   func(f string, a ...any) { lines = append(lines, sprintf(f, a...)) },
			fatal: func(f string, a ...any) { fatals = append(fatals, sprintf(f, a...)) },
		}
	}
	// ★ THE DOORS ARE REAL CERTIFICATES, because that is the change this judgement rests on: availability is
	// read from what is being served, not from a book kept beside it. A fixture that writes the book directly
	// would pass while every transition that moves a certificate without an install went on breaking it.
	authority := newTenantTransportAuthority(nil, nil, func() time.Time { return at })
	install := func(tenant string, ttl time.Duration) {
		t.Helper()
		if _, err := authority.EnsureCA(tenant, tenant+".example.com"); err != nil {
			t.Fatal(err)
		}
		mat, err := authority.IssueFor(tenant, "edge-a", ttl)
		if err != nil {
			t.Fatal(err)
		}
		if err := installTenantTransportMaterial(mat); err != nil {
			t.Fatal(err)
		}
	}

	// Holding nothing is not a reason to leave: this node runs on files, or has not been given anything yet,
	// and the fleet guard is what judges that.
	f := newFetcher()
	if _, leaving := f.judgeMaterialExpiry(at); leaving || len(fatals) != 0 {
		t.Fatalf("a node holding no material decided to leave: %v", fatals)
	}

	// Everything current: silence. A line every few seconds for a healthy node is a line nobody reads.
	install("tenant_a", 6*time.Hour)
	install("tenant_b", 6*time.Hour)
	f = newFetcher()
	if expired, leaving := f.judgeMaterialExpiry(at); len(expired) != 0 || leaving || len(lines) != 0 {
		t.Fatalf("a healthy node said something: expired=%v lines=%v", expired, lines)
	}

	// ★ ONE ORGANIZATION PAST ITS END MUST NOT TAKE THE OTHERS DOWN. On three regions of one machine, exiting
	// for one customer's lapse takes the other nineteen with it — strictly worse than refusing that one.
	useEmptyTenantCertificateIndex(t)
	authority = newTenantTransportAuthority(nil, nil, func() time.Time { return at })
	install("tenant_short", time.Minute)
	install("tenant_long", 12*time.Hour)
	lines, fatals = nil, nil
	f = newFetcher()
	expired, leaving := f.judgeMaterialExpiry(at.Add(2 * time.Minute))
	if leaving || len(fatals) != 0 {
		t.Fatalf("one organization's lapse ended the process for all of them: %v", fatals)
	}
	if len(expired) != 1 || !strings.Contains(expired[0], "tenant_short") {
		t.Fatalf("the expired organization was not named: %v", expired)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "REFUSED") {
		t.Fatalf("the node did not say it refuses that organization: %v", lines)
	}
	// And it is refused where it matters: at the selector, not only in the log.
	useTransportSelectorClock(t, func() time.Time { return at.Add(2 * time.Minute) })
	selected := transportCertificateForClientHello(func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		t.Fatal("a name this node serves must not fall back to the shared certificate")
		return nil, nil
	})
	if _, err := selected(&tls.ClientHelloInfo{ServerName: "tenant_long.example.com"}); err != nil {
		t.Fatalf("the healthy organization was refused: %v", err)
	}
	if _, err := selected(&tls.ClientHelloInfo{ServerName: "tenant_short.example.com"}); err == nil {
		t.Fatal("the expired organization was still served")
	}

	// Nothing usable left: leave, because a node answering wrongly is worse than a node that is gone, and a
	// load balancer only routes around the second.
	lines, fatals = nil, nil
	f = newFetcher()
	if _, leaving := f.judgeMaterialExpiry(at.Add(13 * time.Hour)); !leaving {
		t.Fatal("a node whose every door had expired kept serving")
	}
	if len(fatals) != 1 || !strings.Contains(fatals[0], "leaving the fleet") {
		t.Fatalf("the exit does not say what it is doing: %v", fatals)
	}
}

// ★★★ THE WATCHER MUST NOT SLEEP PAST WHAT IT IS WATCHING, AND MUST FOLLOW THE NEXT DEADLINE STILL AHEAD
// (2026-09-08, found by review).
//
// The interval was derived from the SOONEST deadline held. Once one organization was past its end — which is
// the state this loop exists to be in — that deadline stayed in the past, the calculation fell back to a flat
// minute, and the NEXT organization's deadline could pass unwatched inside it. And the five-second floor was
// itself a constant that could outlive what it watched: with one second left it slept four seconds too long.
func TestTheExpiryWatcherFollowsTheNextDeadlineAndNeverSleepsPastIt(t *testing.T) {
	at := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)

	// Nothing held: the ordinary cadence, and no spinning.
	empty := &tenantTransportMaterialFetcher{}
	if got := empty.watchInterval(at); got != time.Minute {
		t.Fatalf("a node holding nothing watched every %s", got)
	}

	// ★ ONE DEADLINE ALREADY PAST AND ANOTHER TWO MINUTES OUT. The past one must not send this back to a
	// flat minute — the two-minute one is what has to be caught.
	f := &tenantTransportMaterialFetcher{}
	f.recordHeld("transport/active", "tenant_gone", at.Add(-time.Hour))
	f.recordHeld("transport/active", "tenant_next", at.Add(2*time.Minute))
	got := f.watchInterval(at)
	if got != 15*time.Second {
		t.Fatalf("with a deadline two minutes ahead the watcher slept %s (wanted an eighth of it)", got)
	}

	// Never past the thing being watched, at any remaining time — the property, not a table.
	for _, remaining := range []time.Duration{time.Hour, time.Minute, 8 * time.Second, time.Second, 200 * time.Millisecond} {
		one := &tenantTransportMaterialFetcher{}
		one.recordHeld("transport/active", "tenant_only", at.Add(remaining))
		if w := one.watchInterval(at); w > remaining {
			t.Errorf("with %s left the watcher would sleep %s — %s past the deadline it is watching",
				remaining, w, w-remaining)
		}
	}
}

// ★★ AND A REFUSAL REACHES THE TLS SELECTOR, not just the log. The judge naming an organization is not the
// node taking it out of service; the client's own rejection is not evidence that this node stopped serving.
func TestAnExpiredOrganizationIsRefusedAtTheSelectorAndComesBackOnItsOwn(t *testing.T) {
	useEmptyTenantCertificateIndex(t)
	at := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	useTransportSelectorClock(t, func() time.Time { return at })

	transportTenantCertificates.Refuse("tenant_a", "its material expired and could not be refreshed")
	if _, refused := transportTenantCertificates.refusalFor("nobody.example.com"); refused {
		t.Fatal("a name this node does not serve was refused instead of falling through to the shared certificate")
	}
	transportTenantCertificates.Allow("tenant_a")
	if _, refused := transportTenantCertificates.refusalFor("nobody.example.com"); refused {
		t.Fatal("Allow did not lift the refusal")
	}
}

// ★★★ THE WITHDRAWAL LEAVES THE ANNOUNCEMENT, NOT ONLY THE EXPIRY BOOK (2026-09-08, found by review).
//
// A rotation the operator abandons used to leave this node announcing an authority nobody will ever sign
// under: devices adopt by the fingerprints in that announcement, so they would go on adopting an anchor that
// is never used, and the announcement's serial would keep moving for it.
func TestAnAbandonedRotationStopsBeingAnnounced(t *testing.T) {
	useEmptyTenantCertificateIndex(t)
	at := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	useTransportInstallClock(t, func() time.Time { return at })
	useTransportSelectorClock(t, func() time.Time { return at })
	authority := newTenantTransportAuthority(nil, nil, func() time.Time { return at })
	if _, err := authority.EnsureCA("tenant_a", "tenant-a.example.com"); err != nil {
		t.Fatal(err)
	}
	current, err := authority.IssueFor("tenant_a", "edge-a", 12*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := installTenantTransportMaterial(current); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.RotateCA("tenant_a"); err != nil {
		t.Fatal(err)
	}
	both, err := authority.IssueAllFor("tenant_a", "edge-a", 12*time.Hour)
	if err != nil || len(both) != 2 {
		t.Fatalf("fixture did not stage an authority: %v", err)
	}
	for _, m := range both {
		if err := installTenantTransportMaterial(m); err != nil {
			t.Fatal(err)
		}
	}
	if transportTenantCertificates.PendingFingerprintFor("tenant_a") == "" {
		t.Fatal("fixture did not announce a pending authority")
	}

	// The operator abandons it, so the control plane sends the current authority alone.
	if _, err := authority.AbandonRotation("tenant_a"); err != nil {
		t.Fatal(err)
	}
	only, err := authority.IssueAllFor("tenant_a", "edge-a", 12*time.Hour)
	if err != nil || len(only) != 1 {
		t.Fatalf("the authority is still rotating: %v", err)
	}
	f := &tenantTransportMaterialFetcher{log: func(string, ...any) {}}
	f.withdrawAuthoritiesTheControlPlaneNoLongerSends(only, 0, "")

	if fp := transportTenantCertificates.PendingFingerprintFor("tenant_a"); fp != "" {
		t.Fatalf("an abandoned rotation is still announced to devices: %s", fp)
	}
	if _, ok := transportTenantCertificates.PendingDeadlineFor("tenant_a"); ok {
		t.Fatal("the withdrawn authority still carries a deadline")
	}
	// ★ THE CONTROL. An incomplete answer must never be read as a withdrawal: that is how a deployment tears
	// down material that is still in force.
	for _, m := range both {
		if err := installTenantTransportMaterial(m); err != nil {
			t.Fatal(err)
		}
	}
	f.withdrawAuthoritiesTheControlPlaneNoLongerSends(only, 1, "")
	if transportTenantCertificates.PendingFingerprintFor("tenant_a") == "" {
		t.Fatal("a round with an unresolved material was read as a withdrawal")
	}
	f.withdrawAuthoritiesTheControlPlaneNoLongerSends(only, 0, "the control plane could not say")
	if transportTenantCertificates.PendingFingerprintFor("tenant_a") == "" {
		t.Fatal("a refusal this node could not interpret was read as a withdrawal")
	}
}
