package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ★★★ SHORT-LIVED MATERIAL IS ONLY ACCEPTABLE IF THE NODE STOPS WHEN IT RUNS OUT (2026-08-20).
//
// Handing a disposable machine key material is defensible because the material expires. The other half of
// that bargain is what happens at the end of it: a node that keeps serving an expired certificate is refused
// by every device that reaches it AND keeps being routed traffic, which is worse than not being there.
//
// The warning half matters as much as the exit: an operator needs the hours before it, not the moment of it.
func TestANodeLeavesTheFleetRatherThanServeExpiredMaterial(t *testing.T) {
	useEmptyTenantCertificateIndex(t)
	lines := []string{}
	fatals := []string{}
	f := &tenantTransportMaterialFetcher{
		log:   func(format string, a ...any) { lines = append(lines, strings.TrimSpace(sprintf(format, a...))) },
		fatal: func(format string, a ...any) { fatals = append(fatals, sprintf(format, a...)) },
	}

	// Still valid, control plane unreachable: keep going, say nothing alarming.
	f.expiry = time.Now().Add(6 * time.Hour)
	f.reportFetchFailure(errString("connection refused"), 10*time.Minute)
	if len(fatals) != 0 {
		t.Fatalf("a node with six hours of valid material left the fleet: %v", fatals)
	}
	if len(lines) != 1 || !strings.Contains(lines[0], "keeping what this node already has") {
		t.Fatalf("the failure was not reported as survivable: %v", lines)
	}

	// Inside the last hour: warn, and say what will happen.
	lines = nil
	f.expiry = time.Now().Add(20 * time.Minute)
	f.reportFetchFailure(errString("connection refused"), 10*time.Minute)
	if len(fatals) != 0 {
		t.Fatalf("a node still holding valid material left the fleet: %v", fatals)
	}
	joined := strings.Join(lines, " | ")
	if !strings.Contains(joined, "will STOP") {
		t.Fatalf("the hour before the end did not say what is about to happen: %v", lines)
	}

	// Expired: leave, and name when the control plane was last reachable.
	//
	// ★ THE FIXTURE RECORDS HELD MATERIAL, NOT ONLY A DEADLINE (2026-09-08). The exit is decided by
	// judgeMaterialExpiry over what this node is SERVING, so that one organization's lapse cannot end the
	// process for the other nineteen — see the expiry-judgement test beside it. In production f.expiry is only
	// ever non-zero because held is non-empty (it is computed from it); a fixture that sets one without the
	// other is describing a node that cannot exist.
	lines = nil
	f.expiry = time.Now().Add(-time.Minute)
	// ★ THE DOOR IS A REAL CERTIFICATE (2026-09-08). The exit is decided by judgeMaterialExpiry over the
	// certificates this node is SERVING, so that one organization's lapse cannot end the process for the
	// other nineteen and so that a promotion or a withdrawal cannot desynchronise the judgement from what is
	// on the wire. A fixture that wrote a deadline into the book without a certificate behind it would be
	// describing a node that cannot exist.
	installAnExpiredDoorForTest(t, "tenant_only")
	f.reportFetchFailure(errString("connection refused"), 10*time.Minute)
	if len(fatals) != 1 {
		t.Fatal("a node whose material had expired kept serving — every device that reaches it is refused, " +
			"and it goes on being sent traffic")
	}
	if !strings.Contains(fatals[0], "leaving the fleet") {
		t.Fatalf("the exit does not say what it is doing: %v", fatals)
	}

	// ★ AND A NODE THAT NEVER HAD MATERIAL AT ALL MUST NOT BE KILLED BY THIS. It is running on files, or on
	// nothing, and the fleet guard is what judges it.
	fatals = nil
	f.expiry = time.Time{}
	useEmptyTenantCertificateIndex(t)
	f.reportFetchFailure(errString("connection refused"), 10*time.Minute)
	if len(fatals) != 0 {
		t.Fatalf("a node that never fetched material was killed by the expiry rule: %v", fatals)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// ★★★ A 200 CARRYING A REFUSAL WAS TREATED AS A SUCCESSFUL FETCH (2026-08-28, measured — two Edges exited and
// stayed down for a leadership move that lasted seconds).
//
// The start-up fetch is retried for a bounded window precisely so a node that comes up before its control
// plane can still join. That retry is driven by the error FetchOnce returns, and the refusal arrived INSIDE a
// perfectly good 200 — so the loop never engaged, the node went straight to the fleet guard, and the guard
// correctly refused to serve a name it had no certificate for.
//
// Only a refusal that is not evidence becomes an error. A real absence must stay a fact: retrying it would
// just be asking the same question until a different answer appears.
func TestARefusalThatIsNotEvidenceIsRetryableAndARealAbsenceIsNot(t *testing.T) {
	notEvidence := "tenant_kaede: this control plane " + authorityNotAskedPhrase +
		", so it cannot say whether this organization has one"
	if !transportAuthorityRefusalIsNotEvidence(notEvidence) {
		t.Fatal("the Edge cannot tell 'I could not find out' apart from 'there is none', which is the whole " +
			"defect: it acts on the second and waits on the first")
	}
	realAbsence := `tenant_kaede: no transport authority for "tenant_kaede" — an Edge cannot be given material ` +
		"for an organization the control plane does not hold an authority for"
	if transportAuthorityRefusalIsNotEvidence(realAbsence) {
		t.Fatal("a real absence was treated as unanswered — an Edge would retry a fact until the window ran " +
			"out, and then act on it anyway")
	}
	// Both sides agree through one constant rather than two copies of a sentence.
	if !strings.Contains(errAuthorityNotAsked.Error(), authorityNotAskedPhrase) {
		t.Fatal("the phrase the Edge matches on is not the one the control plane sends")
	}

	// ★★★ AND THE FETCH ITSELF MUST SAY SO, which is the half the matcher cannot testify to. The caller's
	// retry window is driven by the error FetchOnce returns; a 200 that comes back nil is a node walking
	// straight into the fleet guard.
	answer := func(refused string) (time.Time, error) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("content-type", "application/json")
			_, _ = w.Write([]byte(`{"materials":[],"interception":[],"device_identity":[],"generation":7,` +
				`"refused":["` + refused + `"]}`))
		}))
		defer srv.Close()
		f := &tenantTransportMaterialFetcher{
			endpoint: srv.URL, token: "t", client: srv.Client(),
			tenants: func() []string { return []string{"tenant_kaede"} },
			log:     func(string, ...any) {}, fatal: func(string, ...any) {},
		}
		return f.FetchOnce()
	}
	if _, err := answer(strings.ReplaceAll(notEvidence, `"`, `\"`)); err == nil {
		t.Fatal("a 200 carrying 'I could not find out' was reported as a successful fetch — the caller's retry " +
			"window never engages and the node goes straight to the fleet guard, which is how two Edges exited")
	}
	if _, err := answer(strings.ReplaceAll(realAbsence, `"`, `\"`)); err != nil {
		t.Fatalf("a real absence was turned into a retryable error, so the node would ask the same question "+
			"until the window ran out and then act on it anyway: %v", err)
	}
}

// installAnExpiredDoorForTest puts a real, already-expired certificate in the index for one organization, so
// a test can exercise the judgement the way the running node reaches it.
func installAnExpiredDoorForTest(t *testing.T, tenant string) {
	t.Helper()
	useEmptyTenantCertificateIndex(t)
	minted := time.Now().UTC().Add(-2 * time.Hour)
	useTransportInstallClock(t, func() time.Time { return minted })
	authority := newTenantTransportAuthority(nil, nil, func() time.Time { return minted })
	if _, err := authority.EnsureCA(tenant, tenant+".example.com"); err != nil {
		t.Fatal(err)
	}
	mat, err := authority.IssueFor(tenant, "edge-a", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := installTenantTransportMaterial(mat); err != nil {
		t.Fatal(err)
	}
}
