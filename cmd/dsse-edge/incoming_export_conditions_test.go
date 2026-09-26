package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"github.com/lantern-networks/dsse-core/logs"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
)

func TestIncomingUnsupportedConditionsCannotBeActivated(t *testing.T) {
	for name, change := range map[string]func(*model.LegacyException){
		"udp":           func(x *model.LegacyException) { x.Protocol = "udp"; x.ServiceFamily = ""; x.Port = 53 },
		"approval":      func(x *model.LegacyException) { x.ApprovalRequired = true },
		"session limit": func(x *model.LegacyException) { x.MaxSessionSeconds = 60 },
		"unscoped port": func(x *model.LegacyException) { x.ServiceFamily = ""; x.Protocol = "" },
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "runtime.json")
			s := policy.NewStore(nil)
			if err := s.SetRuntimeStatePath(path); err != nil {
				t.Fatal(err)
			}
			tenant := testEvaluator().PolicyBundle.TenantID
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(adminPrincipal{ID: "owner", TenantID: tenant, Roles: []string{"admin"}, Status: "active"})
			const token = "synthetic-incoming-conditions-token"
			auth.UpsertAPIToken(adminAPIToken{ID: "owner", TenantID: tenant, TokenHash: adminTokenHash(token), Roles: []string{"admin"}, Scopes: []string{"admin.serverinitiated.read", "admin.serverinitiated.write"}, CreatedByAdminPrincipalID: "owner", Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
			writer, err := logs.NewWriter(filepath.Join(dir, "logs"))
			if err != nil {
				t.Fatal(err)
			}
			outbox := &recordingAdminAuditOutboxDeadReader{}
			h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: s, AdminAuth: auth, Writer: writer, AdminAuditOutbox: outbox})
			call := func(x model.LegacyException, want int) {
				t.Helper()
				raw, err := json.Marshal(x)
				if err != nil {
					t.Fatal(err)
				}
				req := httptest.NewRequest("POST", "/admin/legacy-exceptions", bytes.NewReader(raw))
				req.Header.Set("Authorization", "Bearer "+token)
				r := httptest.NewRecorder()
				h.ServeHTTP(r, req)
				if r.Code != want {
					t.Fatalf("save returned %d want %d: %s", r.Code, want, r.Body)
				}
			}
			ex := model.LegacyException{ID: "old", BusinessOwner: "secops", SourceServer: "192.0.2.1", Protocol: "tcp", ServiceFamily: "smb", Port: 445, Mode: "allow", Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
			change(&ex)
			generation := s.ConfigGeneration()
			call(ex, 400)
			if len(s.LegacyExceptionsFor(tenant)) != 0 || s.ConfigGeneration() != generation {
				t.Fatal("refused creation changed state")
			}
			// Existing deployments may already contain this record. Disabling it must
			// remain possible without dropping the original conditions.
			s.UpsertLegacyException(tenant, ex)
			ex.Status = "disabled"
			call(ex, 200)
			saved := s.LegacyExceptionsFor(tenant)
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			generation = s.ConfigGeneration()
			ex.Status = "active"
			call(ex, 400)
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) || !reflect.DeepEqual(saved, s.LegacyExceptionsFor(tenant)) || s.ConfigGeneration() != generation {
				t.Fatal("refused reactivation changed saved/live state")
			}
			fresh := policy.NewStore(nil)
			if err := fresh.SetRuntimeStatePath(path); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(saved, fresh.LegacyExceptionsFor(tenant)) {
				t.Fatal("restart changed disabled record")
			}
			ex.Protocol = "tcp"
			ex.ServiceFamily = "smb"
			ex.Port = 445
			ex.ApprovalRequired = false
			ex.MaxSessionSeconds = 0
			call(ex, 200)
			fresh = policy.NewStore(nil)
			if err := fresh.SetRuntimeStatePath(path); err != nil {
				t.Fatal(err)
			}
			if x := fresh.LegacyExceptionsFor(tenant); len(x) != 1 || x[0].Status != "active" || x[0].Protocol != "tcp" {
				t.Fatal("corrected activation not saved")
			}
			outbox.mu.Lock()
			defer outbox.mu.Unlock()
			if len(outbox.wrapperAudits) != 4 {
				t.Fatalf("audits=%d", len(outbox.wrapperAudits))
			}
			for i, a := range outbox.wrapperAudits {
				want := 200
				result := "success"
				if i == 0 || i == 2 {
					want = 400
					result = "error"
				}
				if a.TenantID != tenant || a.ActorUserID == nil || *a.ActorUserID != "owner" || a.Result == nil || *a.Result != result || a.Metadata["status_code"] != want {
					t.Fatalf("audit %d: %+v", i, a)
				}
			}
		})
	}
}

func TestIncomingExportRejectsLegacyConditionsAndAllowsWithdrawal(t *testing.T) {
	tenant := testEvaluator().PolicyBundle.TenantID
	s := policy.NewStore(nil)
	ex := model.LegacyException{ID: "old", TenantID: tenant, BusinessOwner: "secops", Protocol: "udp", Port: 53, Mode: "allow", Status: "active", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	s.UpsertLegacyException(tenant, ex)
	ledger := enrolledinventory.NewLedger()
	if _, err := ledger.Enroll("device", tenant, "", time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	h := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), PolicyStore: s, EnrolledLedger: ledger, AdminAuth: newAdminAuthStore()})
	for _, enabled := range []bool{true, false} {
		s.SetServerInitiatedEnabled(tenant, enabled)
		a := httptest.NewRecorder()
		h.ServeHTTP(a, httptest.NewRequest("GET", "/admin/legacy-exceptions/export", nil))
		d := asVerifiedDevice(t, h, "device", "/steer/server-initiated-export")
		for _, r := range []*httptest.ResponseRecorder{a, d} {
			if enabled {
				if r.Code != 503 || strings.Contains(r.Body.String(), `"rules"`) {
					t.Fatalf("unsupported export: %d %s", r.Code, r.Body)
				}
			} else {
				var exp serverInitiatedExport
				if err := json.Unmarshal(r.Body.Bytes(), &exp); err != nil || r.Code != 200 || exp.DefaultAction != "allow" || len(exp.Rules) != 0 {
					t.Fatalf("withdrawal: %d %s", r.Code, r.Body)
				}
			}
		}
	}
}
