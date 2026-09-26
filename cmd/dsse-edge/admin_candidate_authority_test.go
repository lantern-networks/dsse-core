package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/policy"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func TestCandidateWritesUseControlPlaneAuthority(t *testing.T) {
	for _, operation := range []string{"create", "review", "materialize", "refresh", "publish", "manual"} {
		for _, sourced := range []bool{true, false} {
			name := operation + "/authority"
			if sourced {
				name = operation + "/pulling-edge"
			}
			t.Run(name, func(t *testing.T) {
				ctx, now := context.Background(), time.Now()
				tenant := testEvaluator().PolicyBundle.TenantID
				candidates, apps := policycandidate.NewStore(), appcatalog.NewStore()
				discovered, err := candidates.ObserveConnectorDiscovered(ctx, tenant, "wiki.example.test", 443, "web", "connector", "site", "", nil, now)
				if err != nil {
					t.Fatal(err)
				}
				learned, err := candidates.ObserveUnmatchedFlow(ctx, tenant, "learned.example.test", "", 443, "", now)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err = candidates.Review(ctx, tenant, learned.CandidateID, policycandidate.ReviewRequest{Decision: "approved"}, now); err != nil {
					t.Fatal(err)
				}
				writer, err := logs.NewWriter(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				defer writer.Close()
				outbox := &recordingAdminAuditOutboxDeadReader{}
				source := ""
				if sourced {
					source = "https://control.example.test"
				}
				h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), AdminAuth: newAdminAuthStore(), Registry: connector.NewRegistry(), Writer: writer, AdminAuditOutbox: outbox, ApplicationCatalogStore: apps, PolicyCandidateStore: candidates, AssetStore: assetcatalog.NewStore(), RuleStore: policyrule.NewStore(), PolicyStore: policy.NewStore(nil), ConfigSourceURL: source})
				path, body := "/admin/policy-candidates/"+discovered.CandidateID+"/review", `{"decision":"approved"}`
				switch operation {
				case "manual":
					path, body = "/admin/cert-pin-bypass", `{"host":"manual.example.test","port":443}`
				case "create":
					path = "/admin/policy-candidates"
					row := discovered
					row.CandidateID = "new-candidate"
					raw, err := json.Marshal(row)
					if err != nil {
						t.Fatal(err)
					}
					body = string(raw)
				case "materialize":
					path = "/admin/policy-candidates/" + learned.CandidateID + "/materialize"
					body = `{}`
				case "refresh":
					path = "/admin/connector-discovery/refresh"
					body = `{}`
				case "publish":
					path = "/admin/policy-candidates/" + discovered.CandidateID + "/approve-private-app"
					body = `{}`
				}
				before, err := candidates.List(ctx, tenant, policycandidate.ListOptions{})
				if err != nil {
					t.Fatal(err)
				}
				beforeApps := apps.Snapshot()
				w := httptest.NewRecorder()
				h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
				want := http.StatusOK
				if sourced {
					want = http.StatusConflict
				}
				if w.Code != want {
					t.Fatalf("status=%d want=%d body=%s", w.Code, want, w.Body)
				}
				if sourced {
					after, err := candidates.List(ctx, tenant, policycandidate.ListOptions{})
					if err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(before, after) || !reflect.DeepEqual(beforeApps, apps.Snapshot()) {
						t.Fatal("pulling Edge changed authoritative data")
					}
					if len(outbox.insertedAudits) != 0 {
						t.Fatal("rejected change emitted domain success")
					}
					if len(outbox.wrapperAudits) != 1 || stringPtrValue(outbox.wrapperAudits[0].Result) == "success" {
						t.Fatal("missing failed operation audit")
					}
					for _, url := range []string{"/admin/policy-candidates", "/admin/policy-candidates/" + discovered.CandidateID} {
						read := httptest.NewRecorder()
						h.ServeHTTP(read, httptest.NewRequest(http.MethodGet, url, nil))
						if read.Code != http.StatusOK {
							t.Fatalf("read blocked: %d", read.Code)
						}
					}
				}
			})
		}
	}
}
