package main

import (
	"context"
	"errors"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestManagedAccountChangesApplyToExistingCredentials(t *testing.T) {
	for _, kind := range []string{"session", "api_token"} {
		t.Run(kind, func(t *testing.T) {
			now := time.Now().UTC()
			creds := newLocalAdminCredentialStore("DSSE")
			seedActiveAdminAccount(t, creds, "live@example.com", "tenant_lab_001", "adm_live", []string{"admin"}, now)
			auth := newAdminAuthStore()
			auth.UpsertPrincipal(principalFromCredential(creds.byEmail["live@example.com"], now))
			auth.UpsertSession(adminSession{ID: "live-session", TenantID: "tenant_lab_001", AdminPrincipalID: "adm_live", Roles: []string{"admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339), Metadata: map[string]any{adminCSRFTokenKey: "live-csrf"}})
			auth.UpsertAPIToken(adminAPIToken{ID: "live-token", TenantID: "tenant_lab_001", TokenHash: adminTokenHash("live-secret"), Roles: []string{"admin"}, Scopes: []string{"*"}, CreatedByAdminPrincipalID: "adm_live", Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
			writer, err := logs.NewWriter(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), AdminAuth: auth, LocalCredentials: creds})
			request := func(method, path string) int {
				r := httptest.NewRequest(method, path, strings.NewReader(`{"active":true}`))
				if kind == "session" {
					r.AddCookie(&http.Cookie{Name: "admin_session", Value: "live-session"})
					r.Header.Set("X-CSRF-Token", "live-csrf")
				} else {
					r.Header.Set("Authorization", "Bearer live-secret")
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				return w.Code
			}
			if status := request("GET", "/admin/session"); status != 200 {
				t.Fatalf("fixture: %d", status)
			}
			if _, err := creds.SetStatus("tenant_lab_001", "adm_live", credentialStatusSuspended, now); err != nil {
				t.Fatal(err)
			}
			if status := request("GET", "/admin/session"); status != 401 {
				t.Fatalf("suspended account credential still accepted: %d", status)
			}
			if _, err := creds.SetStatus("tenant_lab_001", "adm_live", credentialStatusActive, now); err != nil {
				t.Fatal(err)
			}
			if kind == "session" {
				if _, err := creds.SetRoles("tenant_lab_001", "adm_live", []string{"analyst"}, now); err != nil {
					t.Fatal(err)
				}
				if status := request("POST", "/admin/legal-hold"); status != 403 {
					t.Fatalf("session kept old write role: %d", status)
				}
			}
			if _, err := creds.Delete("tenant_lab_001", "adm_live", now); err != nil {
				t.Fatal(err)
			}
			if status := request("GET", "/admin/session"); status != 401 {
				t.Fatalf("deleted account credential still accepted: %d", status)
			}
			rows, err := writer.ReadJSONL("audit.log.jsonl")
			if err != nil {
				t.Fatal(err)
			}
			denied := 0
			for _, row := range rows {
				if row["event_type"] == "admin_auth_failed" {
					denied++
				}
			}
			if denied != 2 {
				t.Fatalf("expected suspension and deletion refusal audit, got %d", denied)
			}

		})
	}
}

// A blocked durable update must not hold existing session checks hostage.
type blockedCredentialPersistence struct {
	*fakeCredentialPersistence
	block   atomic.Bool
	entered chan context.Context
	release chan struct{}
}

func (p *blockedCredentialPersistence) Upsert(ctx context.Context, c *localAdminCredential) error {
	if p.block.Load() {
		p.entered <- ctx
		select {
		case <-p.release:
			return errors.New("injected save failure")
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return p.fakeCredentialPersistence.Upsert(ctx, c)
}
func TestManagedSessionRemainsResponsiveDuringCredentialSave(t *testing.T) {
	p := &blockedCredentialPersistence{fakeCredentialPersistence: newFakeCredentialPersistence(), entered: make(chan context.Context, 1), release: make(chan struct{})}
	defer close(p.release)
	creds, err := newLocalAdminCredentialStoreWithPersistence("DSSE", p)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	seedActiveAdminAccount(t, creds, "live@example.com", "tenant_lab_001", "adm_live", []string{"admin"}, now)
	auth := newAdminAuthStore()
	auth.UpsertPrincipal(principalFromCredential(creds.byEmail["live@example.com"], now))
	auth.UpsertSession(adminSession{ID: "live-session", TenantID: "tenant_lab_001", AdminPrincipalID: "adm_live", Roles: []string{"admin"}, Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), AdminAuth: auth, LocalCredentials: creds})
	p.block.Store(true)
	done := make(chan error, 1)
	go func() {
		_, e := creds.SetStatus("tenant_lab_001", "adm_live", credentialStatusSuspended, now)
		done <- e
	}()
	select {
	case ctx := <-p.entered:
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > credentialPersistenceTimeout {
			t.Fatal("save has no bounded deadline")
		}
	case <-time.After(time.Second):
		t.Fatal("write never started")
	}
	response := make(chan int, 1)
	go func() {
		r := httptest.NewRequest("GET", "/admin/session", nil)
		r.AddCookie(&http.Cookie{Name: "admin_session", Value: "live-session"})
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		response <- w.Code
	}()
	select {
	case status := <-response:
		if status != 200 {
			t.Fatalf("committed session status=%d", status)
		}
	case <-time.After(time.Second):
		t.Fatal("session check waited for credential write")
	}
	record, ok := creds.authorityFor("tenant_lab_001", "adm_live")
	if !ok || record.Status != credentialStatusActive {
		t.Fatal("uncommitted suspension published")
	}
	record.Roles[0] = "corrupted"
	again, _ := creds.authorityFor("tenant_lab_001", "adm_live")
	if again.Roles[0] != "admin" {
		t.Fatal("authority roles escaped by reference")
	}
	// Cancel through the production deadline, exercising the real timeout path.
	select {
	case err := <-done:
		if !errors.Is(err, errCredentialPersistence) {
			t.Fatalf("save error=%v", err)
		}
	case <-time.After(credentialPersistenceTimeout + time.Second):
		t.Fatal("save did not time out")
	}
	p.block.Store(false)
	if _, err := creds.SetStatus("tenant_lab_001", "adm_live", credentialStatusSuspended, now); err != nil {
		t.Fatal(err)
	}
	final, _ := creds.authorityFor("tenant_lab_001", "adm_live")
	if final.Status != credentialStatusSuspended {
		t.Fatal("committed suspension not published")
	}
}
