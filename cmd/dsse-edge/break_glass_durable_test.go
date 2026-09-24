package main

import (
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type breakGlassFaultPersister struct {
	raw       []byte
	attempted []byte
	err       error
}

func (p *breakGlassFaultPersister) Load() ([]byte, error) { return append([]byte(nil), p.raw...), nil }
func (p *breakGlassFaultPersister) Save(raw []byte) error {
	p.attempted = append([]byte(nil), raw...)
	if p.err != nil {
		return p.err
	}
	p.raw = append([]byte(nil), raw...)
	return nil
}

func TestBreakGlassFailedSaveDoesNotAuthorize(t *testing.T) {
	for _, stage := range []string{"create", "approve", "issue"} {
		t.Run(stage, func(t *testing.T) {
			s := newBreakGlassRequestStore()
			p := &breakGlassFaultPersister{}
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			request := breakGlassSessionRequest{TenantID: "tenant", UserID: "user", Reason: "incident"}
			var id string
			if stage != "create" {
				item, err := s.Create(request, "tenant", now)
				if err != nil {
					t.Fatal(err)
				}
				id = item.ID
			}
			if stage == "issue" {
				if _, err := s.Approve(id, breakGlassApprovalRequest{ApproverUserID: "approver"}, now); err != nil {
					t.Fatal(err)
				}
			}
			before := string(p.raw)
			p.err = errors.New("disk unavailable")
			var err error
			switch stage {
			case "create":
				_, err = s.Create(request, "tenant", now)
			case "approve":
				_, err = s.Approve(id, breakGlassApprovalRequest{ApproverUserID: "approver"}, now)
			case "issue":
				_, err = s.MarkSessionIssued(id, "session", now)
			}
			if err == nil {
				t.Fatal("failed save returned success")
			}
			if string(p.raw) != before {
				t.Fatal("durable state changed")
			}
			if stage == "create" {
				if len(s.requests) != 0 {
					t.Fatal("failed request published")
				}
			} else {
				item, _ := s.Get(id)
				want := "requested"
				if stage == "issue" {
					want = "approved"
				}
				if item.Status != want {
					t.Fatalf("unconfirmed authorization published: %s", item.Status)
				}
			}
		})
	}
}

func TestBreakGlassHTTPRejectsUnconfirmedIssuance(t *testing.T) {
	for _, fault := range []error{errors.New("private backend failure"), blobstore.ErrDurabilityUnconfirmed} {
		t.Run(fault.Error(), func(t *testing.T) {
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			s := newBreakGlassRequestStore()
			sessions := sessionStoreForTest()
			h := newServerWithConfig(serverConfig{Writer: writer, Evaluator: testEvaluator(), BreakGlassRequests: s, SessionStore: sessions})
			p := &breakGlassFaultPersister{}
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			call := func(path, body string, want int) *httptest.ResponseRecorder {
				t.Helper()
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(body)))
				if w.Code != want {
					t.Fatalf("%s: %d %s", path, w.Code, w.Body)
				}
				return w
			}
			body := `{"user_id":"user","reason":"incident"}`
			p.err = fault
			call("/break-glass/requests", body, 503)
			p.err = nil
			w := call("/break-glass/requests", body, 201)
			var item breakGlassAccessRequest
			json.Unmarshal(w.Body.Bytes(), &item)
			path := "/break-glass/requests/" + item.ID
			p.err = fault
			call(path+"/approve", `{"approver_user_id":"approver"}`, 503)
			p.err = nil
			call(path+"/approve", `{"approver_user_id":"approver"}`, 200)
			p.err = fault
			w = call(path+"/issue-session", "", 503)
			if len(w.Result().Cookies()) != 0 || strings.Contains(w.Body.String(), fault.Error()) {
				t.Fatal("failed issuance leaked cookie/backend")
			}
			var attempted map[string]breakGlassAccessRequest
			json.Unmarshal(p.attempted, &attempted)
			if id := attempted[item.ID].SessionID; id == "" {
				t.Fatal("no attempted issuance")
			} else if _, ok := sessions.Get(id); ok {
				t.Fatal("failed save activated a session")
			}
			rows, _ := writer.ReadJSONL("audit.log.jsonl")
			for _, row := range rows {
				if row["event_type"] == "break_glass_session_issued" {
					t.Fatal("failed issuance logged success")
				}
			}
			p.err = nil
			w = call(path+"/issue-session", "", 201)
			if len(w.Result().Cookies()) != 1 {
				t.Fatal("confirmed issuance missing cookie")
			}
			call(path+"/issue-session", "", http.StatusBadRequest)
			reloaded := newBreakGlassRequestStore()
			if err := reloaded.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			got, _ := reloaded.Get(item.ID)
			if got.Status != "session_issued" {
				t.Fatal("restart lost consumption")
			}
		})
	}
}
