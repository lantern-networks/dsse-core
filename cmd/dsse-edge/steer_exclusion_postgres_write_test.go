package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"github.com/lantern-networks/dsse-core/steerexclusion"
	"strings"
	"testing"
)

type steerSQLConnector struct{ c *steerSQLConn }

func (c steerSQLConnector) Connect(context.Context) (driver.Conn, error) { return c.c, nil }
func (steerSQLConnector) Driver() driver.Driver                          { return steerSQLDriver{} }

type steerSQLDriver struct{}

func (steerSQLDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

type steerSQLConn struct {
	query  string
	args   []driver.NamedValue
	result driver.Result
	err    error
}

func (*steerSQLConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*steerSQLConn) Close() error                        { return nil }
func (*steerSQLConn) Begin() (driver.Tx, error)           { return nil, errors.New("unused") }
func (c *steerSQLConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	c.query = q
	c.args = args
	return c.result, c.err
}

type steerSQLResultError struct{}

func (steerSQLResultError) LastInsertId() (int64, error) { return 0, errors.New("unused") }
func (steerSQLResultError) RowsAffected() (int64, error) {
	return 0, errors.New("row count unavailable")
}

// Exercises the SQL adapter and result handling through database/sql. This is a
// driver contract test; live PostgreSQL concurrency remains an integration gate.
func TestPostgresSteerExclusionTenantWriteContract(t *testing.T) {
	for _, tt := range []struct {
		name                string
		result              driver.Result
		err                 error
		wantError, conflict bool
	}{
		{"written", driver.RowsAffected(1), nil, false, false},
		{"foreign-owner", driver.RowsAffected(0), nil, true, true},
		{"exec-error", nil, errors.New("database unavailable"), true, false},
		{"result-error", steerSQLResultError{}, nil, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := &steerSQLConn{result: tt.result, err: tt.err}
			db := sql.OpenDB(steerSQLConnector{c})
			defer db.Close()
			p := postgresSteerExclusionPersistence{db: db}
			err := p.Upsert(context.Background(), &steerexclusion.Policy{ID: "shared-id", TenantID: "tenant-a", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"com.example.app"}})
			if (err != nil) != tt.wantError || errors.Is(err, steerexclusion.ErrTenantConflict) != tt.conflict {
				t.Fatal("result", err)
			}
			q := strings.Join(strings.Fields(c.query), " ")
			if !strings.Contains(q, "WHERE steer_exclusion_policies.tenant_id = EXCLUDED.tenant_id") || strings.Contains(q, "tenant_id=EXCLUDED.tenant_id") {
				t.Fatal("unguarded ownership update", q)
			}
			if len(c.args) != 9 || c.args[0].Value != "shared-id" || c.args[1].Value != "tenant-a" {
				t.Fatal("unbound identity", c.args)
			}
		})
	}
}
