package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolltoken"
)

// ★★★ THE SENTINELS ARE THE POINT. POST /enroll logs "already spent" differently from "never existed", and —
// crucially — treats an UNKNOWN secret as possibly-the-shared-token and falls THROUGH to the other eligibility
// modes. A reason flattened into prose across the wire would have broken the shared-token path silently: every
// deployment still using it would have stopped enrolling, with the log saying only "invalid or missing".
func TestEveryRefusalReasonSurvivesTheTripBackAsItsOwnError(t *testing.T) {
	for _, want := range []error{
		enrolltoken.ErrUnknownToken,
		enrolltoken.ErrTokenUsed,
		enrolltoken.ErrTokenRevoked,
		enrolltoken.ErrTokenExpired,
		enrolltoken.ErrWrongTenant,
	} {
		reason := enrolmentTokenReason(want)
		if reason == "" || reason == "refused" {
			t.Fatalf("%v has no reason of its own: %q", want, reason)
		}
		if got := enrolmentTokenSentinel(reason, "", ""); !errors.Is(got, want) {
			t.Fatalf("%q came back as %v, want %v — the enrol endpoint would log the wrong cause, and an "+
				"unknown secret would stop falling through to the shared token", reason, got, want)
		}
	}
}

func remoteAuthorityAgainst(t *testing.T, h http.HandlerFunc) (*remoteEnrolmentTokenAuthority, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	return newRemoteEnrolmentTokenAuthority(srv.URL, "the-bearer", srv.Client()), srv
}

func TestAnEdgeSpendsThroughTheAuthorityAndGetsTheToken(t *testing.T) {
	var sawPath, sawAuth, sawDevice string
	a, srv := remoteAuthorityAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		sawPath, sawAuth = r.URL.Path, r.Header.Get("Authorization")
		var req enrolmentTokenRemoteRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		sawDevice = req.DeviceID
		_ = json.NewEncoder(w).Encode(enrolmentTokenRemoteResponse{
			Token: enrolltoken.Token{ID: "tok_1", TenantID: "tenant_a", Group: "laptops"}})
	})
	defer srv.Close()

	tok, err := a.Spend("tok_1", "tenant_a", "mac-dev-9", time.Now())
	if err != nil {
		t.Fatalf("spend: %v", err)
	}
	if tok.ID != "tok_1" || tok.Group != "laptops" {
		t.Fatalf("the authority's answer did not come back intact: %+v", tok)
	}
	if !strings.HasSuffix(sawPath, "/admin/fleet/enrolment-token/spend") {
		t.Fatalf("asked %q", sawPath)
	}
	if sawAuth != "Bearer the-bearer" {
		t.Fatalf("authenticated as %q", sawAuth)
	}
	// The device the token is being spent FOR has to travel, or the authority records a spend against nobody
	// and an operator cannot tell which machine used a credential.
	if sawDevice != "mac-dev-9" {
		t.Fatalf("the device id did not travel: %q", sawDevice)
	}
}

// ★★★ AN UNREACHABLE AUTHORITY IS NOT AN UNKNOWN TOKEN. If those collapsed into one, a control-plane outage
// would read as "every installer config is invalid" — and, worse, an unknown-token error is the one /enroll
// falls THROUGH on, so a partition would silently start letting the shared token enrol devices.
func TestAnUnreachableAuthorityIsItsOwnFailureAndNotAnUnknownToken(t *testing.T) {
	a, srv := remoteAuthorityAgainst(t, func(w http.ResponseWriter, r *http.Request) {})
	srv.Close() // gone before the call
	_, err := a.Spend("tok_1", "tenant_a", "mac-dev-9", time.Now())
	if err == nil {
		t.Fatal("a spend against an unreachable authority succeeded")
	}
	if errors.Is(err, enrolltoken.ErrUnknownToken) {
		t.Fatal("an unreachable authority came back as ErrUnknownToken: a control-plane outage would read as " +
			"an invalid credential, and /enroll would fall through to the shared token")
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("the failure does not say what happened: %v", err)
	}
}

// The administrative half stays on the authority. Answering it from nothing here would make an empty list look
// like an answer.
func TestAnEdgeDoesNotIssueOrListEnrolmentTokens(t *testing.T) {
	a := &remoteEnrolmentTokenAuthority{url: "https://cp", token: "t", client: http.DefaultClient}
	if _, _, err := a.Issue(enrolltoken.Policy{}, "tenant_a", "", "", "", "", time.Now(), time.Now()); err == nil {
		t.Fatal("an Edge issued an enrolment token")
	}
	if got := a.List("tenant_a"); got != nil {
		t.Fatalf("an Edge answered a token list: %v", got)
	}
}

// And the two halves are wired: the Edge asks when it pulls its config, and the authority answers.
func TestTheRemoteAuthorityIsChosenAndTheRoutesExist(t *testing.T) {
	src := readSourceFile(t, "main.go")
	if !strings.Contains(src, "newRemoteEnrolmentTokenAuthority(") {
		t.Fatal("nothing selects the remote enrolment-token authority: a config-pulling Edge keeps a database")
	}
	if !strings.Contains(src, "registerEnrolmentTokenFleetRoutes(") {
		t.Fatal("the authority never registers the routes an Edge asks on: every enrolment would be refused")
	}
}

// ★★★ "ALREADY BEEN USED" MUST SAY WHOSE (2026-09-01, an hour lost on a real Mac quietly sending another
// machine's spent token, while the token issued for it showed used_at=null at the control plane).
//
// The two facts live only at the authority — an Edge holds no token store — so they have to cross the wire,
// and the Edge has to put them in the operator's log. Walked through the authority's response builder and the
// Edge's reader, because the sentence is assembled from both ends.
func TestASpentTokenNamesTheMachineThatSpentIt(t *testing.T) {
	refusal := enrolmentTokenRefusal(&enrolltoken.AlreadyUsedError{
		UsedBy: "skusanagi-win10", UsedAt: "2026-08-31T21:21:17Z",
	})
	if refusal.Error != "used" {
		t.Fatalf("reason = %q, want \"used\" — every Edge branches on this word", refusal.Error)
	}
	if refusal.UsedBy != "skusanagi-win10" || refusal.UsedAt != "2026-08-31T21:21:17Z" {
		t.Fatalf("the authority did not put the facts on the wire: used_by=%q used_at=%q",
			refusal.UsedBy, refusal.UsedAt)
	}

	got := enrolmentTokenSentinel(refusal.Error, refusal.UsedBy, refusal.UsedAt)
	if !errors.Is(got, enrolltoken.ErrTokenUsed) {
		t.Fatalf("%v is no longer the spent-token sentinel — /enroll branches on it", got)
	}
	for _, want := range []string{"skusanagi-win10", "2026-08-31T21:21:17Z", "one machine, once"} {
		if !strings.Contains(got.Error(), want) {
			t.Errorf("the line an operator reads does not contain %q: %s", want, got.Error())
		}
	}
}
