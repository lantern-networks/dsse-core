package main

import (
	"encoding/json"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/logs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestActivationAttemptsAreAuditedWithoutSecrets(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	store := newLocalAdminCredentialStore("DSSE")
	token, err := store.Invite("audit@example.com", "tenant_activation", "adm_activation", []string{"admin"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	expired, err := store.Invite("expired@example.com", "tenant_expired", "adm_expired", []string{"admin"}, time.Now().Add(-30*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, Registry: connector.NewRegistry(), LocalCredentials: store})
	secrets := []string{token, expired, "strong-synthetic-password-123", "invalid-token-sentinel"}
	cases := []struct {
		route, token, password string
		status                 int
		identified             bool
		malformed              bool
	}{
		{"password", "", "", 400, false, true},
		{"password", "invalid-token-sentinel", "strong-synthetic-password-123", 400, false, false},
		{"password", expired, "strong-synthetic-password-123", 400, false, false},
		{"password", token, "weak", 400, true, false},
		{"totp/begin", token, "", 400, true, false},
		{"password", token, "strong-synthetic-password-123", 200, true, false},
		{"totp/begin", token, "", 200, true, false},
		{"totp/begin", token, "", 200, true, false},
		{"totp/begin", "", "", 400, false, true},
		{"totp/begin", "invalid-token-sentinel", "", 400, false, false},
	}
	for i, tc := range cases {
		body, _ := json.Marshal(map[string]string{"token": tc.token, "new_password": tc.password})
		if tc.malformed {
			body = []byte("{")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/admin/activate/"+tc.route, strings.NewReader(string(body))))
		if rec.Code != tc.status {
			t.Fatalf("case %d: status %d", i, rec.Code)
		}
		if tc.route == "totp/begin" && rec.Code == 200 {
			var response map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"secret", "otpauth_uri"} {
				if response[key] == "" {
					t.Fatal("missing enrollment material")
				}
				secrets = append(secrets, response[key])
			}
		}
		rows, err := writer.ReadJSONL("audit.log.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != i+1 {
			t.Fatalf("case %d: audit count %d", i, len(rows))
		}
		row := rows[i]
		event := "admin_activation_password_set"
		if tc.route == "totp/begin" {
			event = "admin_activation_totp_started"
		}
		result := "success"
		if tc.status >= 400 {
			event += "_failed"
			result = "failure"
		}
		tenant := testEvaluator().PolicyBundle.TenantID
		if tc.identified {
			tenant = "tenant_activation"
			if row["target_id"] != "adm_activation" {
				t.Fatal("missing target account")
			}
		} else if row["target_id"] != nil {
			t.Fatal("unverified target attributed")
		}
		if row["tenant_id"] != tenant || row["event_type"] != event || row["result"] != result || row["action"] != "admin_activation" || row["target_type"] != "admin_account" || row["actor_user_id"] != nil || row["timestamp"] == nil {
			t.Fatalf("wrong attribution/outcome: %#v", row)
		}
		metadata := row["metadata"].(map[string]any)
		if metadata["status_code"] != float64(tc.status) || metadata["path"] != "/admin/activate/"+tc.route {
			t.Fatal("wrong HTTP outcome")
		}
	}
	rows, _ := writer.ReadJSONL("audit.log.jsonl")
	encoded, _ := json.Marshal(rows)
	for _, secret := range secrets {
		if strings.Contains(string(encoded), secret) {
			t.Fatal("activation material leaked into audit")
		}
	}
}
