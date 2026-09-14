package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"testing"
	"time"
)

type archiveFaultConnector struct{ conn *archiveFaultConn }

func (c archiveFaultConnector) Connect(context.Context) (driver.Conn, error) { return c.conn, nil }
func (c archiveFaultConnector) Driver() driver.Driver                        { return archiveFaultDriver{} }

type archiveFaultDriver struct{}

func (archiveFaultDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

type archiveFaultConn struct {
	scanFailure        bool
	deletes, rollbacks int
}

func (*archiveFaultConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*archiveFaultConn) Close() error                        { return nil }
func (c *archiveFaultConn) Begin() (driver.Tx, error)         { return archiveFaultTx{c}, nil }
func (c *archiveFaultConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return &archiveFaultRows{scanFailure: c.scanFailure}, nil
}
func (c *archiveFaultConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	c.deletes++
	return driver.RowsAffected(1), nil
}

type archiveFaultTx struct{ c *archiveFaultConn }

func (archiveFaultTx) Commit() error     { return nil }
func (t archiveFaultTx) Rollback() error { t.c.rollbacks++; return nil }

type archiveFaultRows struct {
	scanFailure bool
	row         int
}

func (*archiveFaultRows) Columns() []string { return []string{"event_id", "payload"} }
func (*archiveFaultRows) Close() error      { return nil }
func (r *archiveFaultRows) Next(dest []driver.Value) error {
	r.row++
	if r.row == 1 {
		dest[0] = "first"
		dest[1] = []byte(`{"event":"first"}`)
		return nil
	}
	if r.scanFailure {
		dest[0] = nil
		dest[1] = []byte(`{}`)
		return nil
	}
	return errors.New("injected rows read failure")
}
func TestArchiveIncompleteReadNeverPublishesOrDeletes(t *testing.T) {
	for _, scanFailure := range []bool{false, true} {
		conn := &archiveFaultConn{scanFailure: scanFailure}
		db := sql.OpenDB(archiveFaultConnector{conn})
		defer db.Close()
		arc := &archiveWriteProbe{fakeArchive: fakeArchive{objs: map[string][]byte{}}}
		archiveThenPruneStream(context.Background(), db, retentionConfig{archive: arc}, "tenant", "audit", time.Now(), time.Now())
		if arc.puts != 0 || conn.deletes != 0 || conn.rollbacks != 1 {
			t.Fatalf("partial read advanced: puts=%d deletes=%d rollback=%d", arc.puts, conn.deletes, conn.rollbacks)
		}
	}
}
