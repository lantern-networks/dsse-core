package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
)

type logoutFailureStore struct {
	*adminAuthStore
	fail bool
}

func (s *logoutFailureStore) RevokeSessionForTenant(ctx context.Context, id, tenant string, now time.Time) (adminSession, bool, error) {
	if s.fail {
		return adminSession{}, false, errors.New("private revocation storage sentinel")
	}
	return s.adminAuthStore.RevokeSessionForTenant(ctx, id, tenant, now)
}

func TestLogoutDoesNotReportSuccessWhenRevocationFails(t *testing.T) {
	now := time.Now().UTC()
	s := &logoutFailureStore{adminAuthStore: newAdminAuthStore(), fail: true}
	s.UpsertPrincipal(adminPrincipal{ID: "admin", TenantID: "tenant_lab_001", Status: "active", Roles: []string{"admin"}})
	s.UpsertSession(adminSession{ID: "session", TenantID: "tenant_lab_001", AdminPrincipalID: "admin", Status: "active", Roles: []string{"admin"}, ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "test-csrf"}})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	outbox := &recordingAdminAuditOutboxDeadReader{}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), AdminAuth: s, AdminAuditOutbox: outbox})
	logout := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/admin/logout", nil)
		r.AddCookie(&http.Cookie{Name: "admin_session", Value: "session"})
		r.Header.Set("x-csrf-token", "test-csrf")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	w := logout()
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("unconfirmed logout reported status %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "sentinel") {
		t.Error("storage details exposed")
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == "admin_session" && c.MaxAge < 0 {
			t.Error("failed logout discarded the credential needed to retry")
		}
	}
	events := auditLogEventTypes(outbox.insertedAudits)
	if events["admin_logout"] || !events["admin_logout_failed"] {
		t.Errorf("logout failure audit incorrect: %v", events)
	}
	if _, ok := s.IdentityForSession("session", "tenant_lab_001", now); !ok {
		t.Fatal("fixture did not retain session on failed save")
	}
	s.fail = false
	if w := logout(); w.Code != http.StatusOK {
		t.Fatalf("retry failed: %d", w.Code)
	}
	if _, ok := s.IdentityForSession("session", "tenant_lab_001", now); ok {
		t.Fatal("confirmed logout did not revoke session")
	}
}
