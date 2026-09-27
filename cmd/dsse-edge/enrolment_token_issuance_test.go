package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/deviceca"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/enrolltoken"
	"github.com/lantern-networks/dsse-core/logs"
)

func TestPostgresEnrolmentConcurrentIssueCap(t *testing.T) {
	db := openEnrolmentTokenDB(t)
	// Widen the count/insert window to reproduce the former multi-writer race.
	if _, err := db.Exec(`CREATE FUNCTION review_enrolment_issue_delay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_sleep(0.05); RETURN NEW; END $$;
 CREATE TRIGGER review_enrolment_issue_delay BEFORE INSERT ON enrolment_tokens FOR EACH ROW EXECUTE FUNCTION review_enrolment_issue_delay()`); err != nil {
		t.Fatal(err)
	}
	defer db.Exec(`DROP TRIGGER review_enrolment_issue_delay ON enrolment_tokens; DROP FUNCTION review_enrolment_issue_delay()`)
	now := time.Now().UTC()
	policy := enrolltoken.Policy{MaxOutstanding: 1, MaxLifetime: time.Hour}
	start := make(chan struct{})
	results := make(chan error, 16)
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			s := newPostgresEnrolmentTokenStore(db)
			_, _, err := s.Issue(policy, "tenant_test_issue_race", "", "", "issuer", "", now.Add(time.Hour), now)
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		} else if !errors.Is(err, enrolltoken.ErrOutstandingCap) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("cap=1 allowed %d concurrent issues", successes)
	}
	if got := newPostgresEnrolmentTokenStore(db).Outstanding("tenant_test_issue_race", now); got != 1 {
		t.Fatalf("persisted %d outstanding", got)
	}
}

// Changes leadership when body decoding starts, after the middleware captured
// the old term. Exercises the actual production request adapter, not just SQL.
type enrolmentTermBody struct {
	*strings.Reader
	before func()
}

func (b *enrolmentTermBody) Read(p []byte) (int, error) {
	if b.before != nil {
		f := b.before
		b.before = nil
		f()
	}
	return b.Reader.Read(p)
}
func (b *enrolmentTermBody) Close() error { return nil }

func TestPostgresEnrolmentIssueSpendRequestTermAndAudit(t *testing.T) {
	leader, peer := postgresFailureElectors(t)
	db := openEnrolmentTokenDB(t)
	s := newPostgresEnrolmentTokenStore(db)
	oldE, oldCP := cpLeaderElectorInstance, edgeIsControlPlane
	defer func() { cpLeaderElectorInstance = oldE; edgeIsControlPlane = oldCP }()
	cpLeaderElectorInstance = nil
	edgeIsControlPlane = true
	tenant := "tenant_lab_001"
	if _, err := db.Exec(`DELETE FROM enrolment_tokens WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(adminPrincipal{ID: "issuer", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
	auth.UpsertSession(adminSession{ID: "issue-session", TenantID: tenant, AdminPrincipalID: "issuer", Roles: []string{"admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "issue-csrf"}})
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, AdminAuth: auth, EnrolmentTokens: s, EnrolledLedger: enrolledinventory.NewLedger(), EnrolmentTokenPolicy: enrolltoken.Policy{MaxOutstanding: 2, MaxLifetime: 48 * time.Hour}})
	cpLeaderElectorInstance = leader
	leader.tick()
	if !leader.IsLeader() {
		t.Fatal("leader")
	}
	rotate := func() {
		leader.release()
		peer.tick()
		if !peer.IsLeader() {
			t.Fatal("peer")
		}
		peer.release()
		leader.tick()
		if !leader.IsLeader() {
			t.Fatal("leader reacquisition")
		}
	}
	call := func(path, body string, old bool, want int) *httptest.ResponseRecorder {
		t.Helper()
		reader := &enrolmentTermBody{Reader: strings.NewReader(body)}
		if old {
			reader.before = rotate
		}
		r := httptest.NewRequest("POST", path, reader)
		r.AddCookie(&http.Cookie{Name: "admin_session", Value: "issue-session"})
		r.Header.Set("X-CSRF-Token", "issue-csrf")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s: %d want %d: %s", path, w.Code, want, w.Body)
		}
		return w
	}
	failed := call("/admin/enrolment-tokens", `{"expires_in_hours":24}`, true, 409)
	if !strings.Contains(failed.Body.String(), enrolltoken.ErrStateUnavailable.Error()) || s.Outstanding(tenant, now) != 0 {
		t.Fatal("old issue accepted")
	}
	success := call("/admin/enrolment-tokens", `{"expires_in_hours":24}`, false, 200)
	var issued struct {
		Token  enrolltoken.Token `json:"token"`
		Secret string            `json:"secret"`
	}
	if err := json.Unmarshal(success.Body.Bytes(), &issued); err != nil || issued.Secret == "" {
		t.Fatal("no issued secret")
	}
	spendBody := fmt.Sprintf(`{"id":%q,"tenant_id":%q,"device_id":"accepted-device"}`, issued.Token.ID, tenant)
	failed = call("/admin/fleet/enrolment-token/spend", spendBody, true, 200)
	if !strings.Contains(failed.Body.String(), `"error":"refused"`) || s.Outstanding(tenant, now) != 1 {
		t.Fatal("old spend accepted")
	}
	success = call("/admin/fleet/enrolment-token/spend", spendBody, false, 200)
	if !strings.Contains(success.Body.String(), "accepted-device") || s.Outstanding(tenant, now) != 0 {
		t.Fatal("spend not committed")
	}
	repeat := call("/admin/fleet/enrolment-token/spend", spendBody, false, 200)
	if !strings.Contains(repeat.Body.String(), `"error":"used"`) {
		t.Fatal("repeat accepted")
	}
	// Known partial success still returns the first credential when the second
	// insert fails; the response and audit must not promise a complete batch.
	if _, err := db.Exec(`ALTER TABLE enrolment_tokens ADD CONSTRAINT review_issue_failure CHECK(label NOT LIKE '%(2/2)') NOT VALID`); err != nil {
		t.Fatal(err)
	}
	partial := call("/admin/enrolment-tokens", `{"label":"review batch","count":2,"expires_in_hours":24}`, false, 409)
	db.Exec(`ALTER TABLE enrolment_tokens DROP CONSTRAINT review_issue_failure`)
	var batch struct {
		Partial bool `json:"partial"`
		Tokens  []struct {
			Secret string `json:"secret"`
		} `json:"tokens"`
	}
	if err := json.Unmarshal(partial.Body.Bytes(), &batch); err != nil || !batch.Partial || len(batch.Tokens) != 1 || batch.Tokens[0].Secret == "" || strings.Contains(partial.Body.String(), "review_issue_failure") {
		t.Fatalf("partial response: %s", partial.Body)
	}
	audits, err := writer.ReadJSONL("audit.log.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	good, bad := 0, 0
	for _, a := range audits {
		if a["event_type"] != "admin_config_change" {
			continue
		}
		if a["result"] == "success" {
			good++
		} else {
			bad++
		}
		raw, _ := json.Marshal(a)
		if bytes.Contains(raw, []byte(issued.Secret)) || bytes.Contains(raw, []byte(batch.Tokens[0].Secret)) {
			t.Fatal("audit leaked credential")
		}
	}
	if good != 2 || bad != 4 {
		t.Fatalf("audit success=%d failure=%d", good, bad)
	}
	// The public device endpoint must carry the same request term through the
	// issuer callback. Invalid CSR text is never reached because spending is denied.
	mux := http.NewServeMux()
	registerEnrollEndpointWithIdP(mux, &deviceca.Signer{}, enrolledinventory.NewLedger(), s, nil, "", tenant, "default", time.Hour, nil, nil, nil, nil, nil)
	body := fmt.Sprintf(`{"device_id":"old-term-device","csr_pem":"not reached","eligibility":{"mode":"token","token":%q}}`, batch.Tokens[0].Secret)
	request := httptest.NewRequest("POST", "/enroll", &enrolmentTermBody{Reader: strings.NewReader(body), before: rotate})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, request)
	if w.Code != 403 || s.Outstanding(tenant, now) != 1 {
		t.Fatalf("public enrolment escaped term: %d %s", w.Code, w.Body)
	}

	// A current-term request reaches CSR validation and spends the approval;
	// this positive control rules out refusal by an unrelated eligibility gate.
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/enroll", strings.NewReader(body)))
	if w.Code != 400 || s.Outstanding(tenant, now) != 0 {
		t.Fatalf("current enrolment did not reach CSR: %d %s", w.Code, w.Body)
	}

}
