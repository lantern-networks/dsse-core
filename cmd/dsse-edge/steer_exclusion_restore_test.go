package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"github.com/lantern-networks/dsse-core/steerexclusion"
	"io"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type steerRestoreSQLConnector struct{ c *steerRestoreSQLConn }

func (c steerRestoreSQLConnector) Connect(context.Context) (driver.Conn, error) { return c.c, nil }
func (steerRestoreSQLConnector) Driver() driver.Driver                          { return steerSQLDriver{} }

type steerRestoreSQLConn struct {
	steerSQLConn
	rows *steerRestoreSQLRows
}

func (c *steerRestoreSQLConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return c.rows, nil
}

type steerRestoreSQLRows struct {
	data [][]driver.Value
	err  error
}

func (*steerRestoreSQLRows) Columns() []string {
	return []string{"id", "tenant_id", "scope_type", "scope_id", "excluded_app_signing_ids", "note", "status", "created_at", "updated_at"}
}
func (*steerRestoreSQLRows) Close() error { return nil }
func (r *steerRestoreSQLRows) Next(dst []driver.Value) error {
	if len(r.data) == 0 {
		if r.err != nil {
			return r.err
		}
		return io.EOF
	}
	copy(dst, r.data[0])
	r.data = r.data[1:]
	return nil
}
func TestPostgresSteerExclusionRestoreRejectsBadAppJSON(t *testing.T) {
	for _, tc := range []struct {
		name, apps string
		bad        bool
	}{
		{"valid", `["com.example.tool"]`, false}, {"malformed", `[`, true}, {"object", `{}`, true}, {"null", `null`, true}, {"empty", `[]`, true}, {"wrong-element", `[1]`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := func(id, apps string) []driver.Value {
				return []driver.Value{id, "tenant_a", "tenant", "", []byte(apps), "", "active", time.Now(), time.Now()}
			}
			c := &steerRestoreSQLConn{rows: &steerRestoreSQLRows{data: [][]driver.Value{row("first", `["com.example.first"]`), row("second", tc.apps)}}}
			db := sql.OpenDB(steerRestoreSQLConnector{c})
			defer db.Close()
			s, err := steerexclusion.NewStoreWithPersistence(postgresSteerExclusionPersistence{db: db})
			if (err != nil) != tc.bad {
				t.Fatal("restore result", err)
			}
			if tc.bad && s != nil {
				t.Fatal("partially loaded store escaped")
			}
			if !tc.bad && len(s.List("tenant_a")) != 2 {
				t.Fatal("valid rows lost")
			}
		})
	}
	c := &steerRestoreSQLConn{rows: &steerRestoreSQLRows{err: errors.New("rows failed")}}
	db := sql.OpenDB(steerRestoreSQLConnector{c})
	defer db.Close()
	if _, err := steerexclusion.NewStoreWithPersistence(postgresSteerExclusionPersistence{db: db}); err == nil {
		t.Fatal("rows error swallowed")
	}
}

func TestAdminSteerExclusionRestoreHealthAndSync(t *testing.T) {
	h, s, _, path, mirror, _ := steerMutationFullFixture(t)
	server := httptest.NewServer(h)
	defer server.Close()
	edge := steerexclusion.NewStore()
	source := steerExclusionSource{url: server.URL, token: "steering-review-token", tenantID: "tenant_lab_001", client: server.Client()}
	if n, err := source.fetchAndReplace(context.Background(), edge); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	before := edge.List("tenant_lab_001")
	file, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	waitStatus := func(want int) {
		t.Helper()
		deadline := time.Now().Add(7 * time.Second)
		for time.Now().Before(deadline) {
			r := steerMutationRequest(h, "GET", "/admin/steer-exclusions", nil)
			if r.Code == want {
				if strings.Contains(r.Body.String(), path) {
					t.Fatal("storage path leaked")
				}
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("authority did not reach %d", want)
	}
	waitStatus(503)
	if n, err := source.fetchAndReplace(context.Background(), edge); n != 0 || err == nil {
		t.Fatal("failed authority accepted", n, err)
	}
	if !reflect.DeepEqual(edge.List("tenant_lab_001"), before) || !reflect.DeepEqual(s.List("tenant_lab_001"), before) {
		t.Fatal("held sets changed")
	}
	r := steerMutationRequest(h, "POST", "/admin/steer-exclusions", map[string]any{"id": "owned", "scope_type": "tenant", "excluded_app_signing_ids": []string{"changed"}})
	if r.Code != 500 {
		t.Fatal("write with unverified base", r.Code)
	}
	stored, _ := os.ReadFile(path)
	if string(stored) != `{}` {
		t.Fatal("failed write overwrote damage")
	}
	if err = os.WriteFile(path, file, 0600); err != nil {
		t.Fatal(err)
	}
	waitStatus(200)
	if _, err = source.fetchAndReplace(context.Background(), edge); err != nil {
		t.Fatal("recovered pull", err)
	}
	entries := inventoryMutationAudits(t, filepath.Dir(filepath.Dir(path)))
	if len(entries) != 2 {
		t.Fatal("expected failed mutation audit only", len(entries))
	}
	mirror.mu.Lock()
	raw, _ := json.Marshal(mirror.insertedAudits)
	mirror.mu.Unlock()
	if !strings.Contains(string(raw), `"result":"failed"`) {
		t.Fatal("domain mirror", string(raw))
	}
}
