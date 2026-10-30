package hotstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type scopeCaptureConnector struct {
	query  string
	args   []driver.NamedValue
	oldest time.Time
}

func (c *scopeCaptureConnector) Connect(context.Context) (driver.Conn, error) {
	return &scopeCaptureConn{c}, nil
}
func (c *scopeCaptureConnector) Driver() driver.Driver { return scopeCaptureDriver{} }

type scopeCaptureDriver struct{}

func (scopeCaptureDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }

type scopeCaptureConn struct{ c *scopeCaptureConnector }

func (c *scopeCaptureConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not used") }
func (c *scopeCaptureConn) Close() error                        { return nil }
func (c *scopeCaptureConn) Begin() (driver.Tx, error)           { return nil, errors.New("not used") }
func (c *scopeCaptureConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.c.query = q
	c.c.args = args
	return &scopeCaptureRows{oldest: c.c.oldest}, nil
}

type scopeCaptureRows struct {
	oldest time.Time
	done   bool
}

func (r *scopeCaptureRows) Columns() []string { return []string{"oldest"} }
func (r *scopeCaptureRows) Close() error      { return nil }
func (r *scopeCaptureRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.oldest
	return nil
}

func TestPostgresOldestMatchedRetainsFiltersWithoutTimeWindow(t *testing.T) {
	c := &scopeCaptureConnector{oldest: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	db := sql.OpenDB(c)
	defer db.Close()
	from := c.oldest.Add(time.Hour)
	to := from.Add(time.Hour)
	got, err := NewPostgresStore(db).oldestEventAt(context.Background(), SearchQuery{TenantID: "own", Stream: "access", Filters: map[string]string{"tenant_id": "foreign", "decision": "deny", "edge_region_id": "region-a"}, Text: "needle", From: &from, To: &to})
	if err != nil || !got.Equal(c.oldest) {
		t.Fatalf("oldest=%v err=%v", got, err)
	}
	for _, required := range []string{"own", "access", "decision", "deny", "region-a", "%needle%"} {
		found := false
		for _, arg := range c.args {
			if arg.Value == required {
				found = true
			}
		}
		if !found {
			t.Errorf("oldest query lost scope %q: %s %#v", required, c.query, c.args)
		}
	}
	for _, arg := range c.args {
		if arg.Value == "foreign" || arg.Value == from || arg.Value == to {
			t.Errorf("untrusted tenant or time window retained: %#v", arg)
		}
	}
	if strings.Contains(c.query, "LIMIT") || strings.Contains(c.query, "OFFSET") {
		t.Errorf("oldest scope was paginated: %s", c.query)
	}
}

func TestPostgresFreeTextUsesLiteralSubstring(t *testing.T) {
	statement, err := buildPostgresSearchStatement(SearchQuery{TenantID: "own", Stream: "access", Limit: 10, Text: `100%_path\name`})
	if err != nil {
		t.Fatal(err)
	}
	want := `%100\%\_path\\name%`
	if len(statement.Args) < 3 || statement.Args[2] != want {
		t.Fatalf("free text changed into SQL pattern: %#v, want %q", statement.Args, want)
	}
}
