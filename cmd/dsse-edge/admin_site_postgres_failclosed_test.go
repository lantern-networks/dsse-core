package main

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

type siteFailureConnector struct{ conn *siteFailureConn }

func (c siteFailureConnector) Connect(context.Context) (driver.Conn, error) { return c.conn, nil }
func (siteFailureConnector) Driver() driver.Driver                          { return siteFailureDriver{} }

type siteFailureDriver struct{}

func (siteFailureDriver) Open(string) (driver.Conn, error) { return nil, errors.New("unused") }

type siteFailureConn struct {
	site          adminSiteModel
	present       bool
	working       adminSiteModel
	workingExists bool
	inTx          bool
	getError      bool
	nextError     bool
	rotateTo      string
	generation    int64
	rollbacks     int
	operations    []string
}

func (*siteFailureConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*siteFailureConn) Close() error                        { return nil }
func (c *siteFailureConn) Begin() (driver.Tx, error) {
	c.inTx = true
	c.working, c.workingExists = c.site, c.present
	return siteFailureTx{c}, nil
}

type siteFailureTx struct{ conn *siteFailureConn }

func (t siteFailureTx) Commit() error {
	t.conn.site, t.conn.present = t.conn.working, t.conn.workingExists
	t.conn.inTx = false
	return nil
}
func (t siteFailureTx) Rollback() error {
	t.conn.inTx = false
	t.conn.rollbacks++
	return nil
}

func (c *siteFailureConn) state() (*adminSiteModel, *bool) {
	if c.inTx {
		return &c.working, &c.workingExists
	}
	return &c.site, &c.present
}

func (c *siteFailureConn) QueryContext(_ context.Context, q string, args []driver.NamedValue) (driver.Rows, error) {
	c.operations = append(c.operations, q)
	switch {
	case strings.Contains(q, "FROM admin_sites WHERE"):
		if c.getError {
			return nil, errors.New("injected site lookup failure")
		}
		row, present := c.state()
		return &siteFailureRows{site: *row, present: *present}, nil
	case strings.Contains(q, "INSERT INTO admin_sites"):
		c.write(q, args)
		row, present := c.state()
		return &siteFailureRows{site: *row, present: *present}, nil
	case strings.Contains(q, "nextval('admin_sites_config_generation')"):
		if c.nextError {
			return nil, errors.New("injected generation failure")
		}
		c.generation++
		return &siteFailureNumberRows{n: c.generation}, nil
	case strings.Contains(q, "last_value"):
		return &siteFailureNumberRows{n: c.generation}, nil
	default:
		return nil, errors.New("unexpected query: " + q)
	}
}

func (c *siteFailureConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	c.operations = append(c.operations, q)
	switch {
	case strings.Contains(q, "INSERT INTO admin_sites"):
		c.write(q, args)
	case strings.Contains(q, "DELETE FROM admin_sites"):
		_, present := c.state()
		*present = false
	case strings.Contains(q, "pg_advisory_xact_lock"):
	default:
		return nil, errors.New("unexpected exec: " + q)
	}
	return driver.RowsAffected(1), nil
}

func (c *siteFailureConn) write(q string, args []driver.NamedValue) {
	row, present := c.state()
	if c.rotateTo != "" && *present {
		row.BootstrapSecretHash = c.rotateTo
		c.rotateTo = ""
	}
	value := func(i int) string { return args[i].Value.(string) }
	newHash := value(8)
	if !*present {
		row.TenantID, row.SiteID = value(0), value(1)
		row.CreatedAt = siteFailureTimePtr(args[10].Value)
	}
	row.Name, row.Region = value(2), value(3)
	row.ExpectedConnectorCount = int(args[4].Value.(int64))
	row.RoutingNamespace, row.DeploymentType, row.HAPolicy = value(5), value(6), value(7)
	if !*present || newHash != "" || !strings.Contains(q, "CASE WHEN EXCLUDED.bootstrap_secret_hash = ''") {
		row.BootstrapSecretHash = newHash
		row.BootstrapSecretRotatedAt = siteFailureTimePtr(args[9].Value)
	}
	row.UpdatedAt = siteFailureTimePtr(args[11].Value)
	*present = true
}

func siteFailureTimePtr(v any) *string {
	if v == nil {
		return nil
	}
	s := v.(time.Time).UTC().Format(time.RFC3339)
	return &s
}

type siteFailureRows struct {
	site    adminSiteModel
	present bool
	done    bool
}

func (siteFailureRows) Columns() []string { return strings.Split(adminSiteColumns, ", ") }
func (siteFailureRows) Close() error      { return nil }
func (r *siteFailureRows) Next(dest []driver.Value) error {
	if !r.present || r.done {
		return io.EOF
	}
	r.done = true
	created, _ := time.Parse(time.RFC3339, *r.site.CreatedAt)
	updated, _ := time.Parse(time.RFC3339, *r.site.UpdatedAt)
	var rotated any
	if r.site.BootstrapSecretRotatedAt != nil {
		rotated, _ = time.Parse(time.RFC3339, *r.site.BootstrapSecretRotatedAt)
	}
	copy(dest, []driver.Value{r.site.TenantID, r.site.SiteID, r.site.Name, r.site.Region,
		int64(r.site.ExpectedConnectorCount), r.site.RoutingNamespace, r.site.DeploymentType,
		r.site.HAPolicy, r.site.BootstrapSecretHash, rotated, created, updated})
	return nil
}

type siteFailureNumberRows struct {
	n    int64
	done bool
}

func (siteFailureNumberRows) Columns() []string { return []string{"generation"} }
func (siteFailureNumberRows) Close() error      { return nil }
func (r *siteFailureNumberRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.n
	return nil
}

func siteFailureStore(t *testing.T, conn *siteFailureConn) *postgresAdminSiteStore {
	t.Helper()
	db := sql.OpenDB(siteFailureConnector{conn})
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return &postgresAdminSiteStore{db: db}
}

func siteFailureSeed() adminSiteModel {
	now := time.Now().UTC().Format(time.RFC3339)
	return adminSiteModel{TenantID: "tenant-a", SiteID: "site-a", Name: "Before",
		BootstrapSecretHash: connectorRuntimeSecretHash("old-secret"), CreatedAt: &now, UpdatedAt: &now}
}

func TestPostgresSiteMetadataEditDoesNotEraseSecretAfterLookupFailure(t *testing.T) {
	old := siteFailureSeed()
	conn := &siteFailureConn{site: old, present: true, getError: true}
	store := siteFailureStore(t, conn)
	_, _ = store.Upsert(context.Background(), adminSiteModel{TenantID: old.TenantID, SiteID: old.SiteID, Name: "After"}, time.Now())
	if conn.site.BootstrapSecretHash != old.BootstrapSecretHash {
		t.Fatal("metadata edit erased an existing bootstrap secret after lookup failure")
	}
}

func TestPostgresSiteMetadataEditDoesNotUndoConcurrentSecretRotation(t *testing.T) {
	old := siteFailureSeed()
	newHash := connectorRuntimeSecretHash("rotated-secret")
	conn := &siteFailureConn{site: old, present: true, rotateTo: newHash}
	store := siteFailureStore(t, conn)
	if _, err := store.Upsert(context.Background(), adminSiteModel{TenantID: old.TenantID, SiteID: old.SiteID, Name: "After"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if conn.site.BootstrapSecretHash != newHash {
		t.Fatal("metadata edit restored the old bootstrap secret over a concurrent rotation")
	}
}

func TestPostgresSiteGenerationFailureRollsBackWrites(t *testing.T) {
	for _, mutation := range []string{"upsert", "delete"} {
		t.Run(mutation, func(t *testing.T) {
			old := siteFailureSeed()
			conn := &siteFailureConn{site: old, present: true, generation: 7, nextError: true}
			store := siteFailureStore(t, conn)
			var err error
			if mutation == "upsert" {
				_, err = store.Upsert(context.Background(), adminSiteModel{TenantID: old.TenantID, SiteID: old.SiteID, Name: "After"}, time.Now())
			} else {
				err = store.Delete(context.Background(), old.TenantID, old.SiteID)
			}
			if err == nil || !conn.present || conn.site.Name != old.Name || conn.site.BootstrapSecretHash != old.BootstrapSecretHash || conn.generation != 7 {
				t.Fatalf("generation failure must roll back %s: err=%v present=%t generation=%d", mutation, err, conn.present, conn.generation)
			}
		})
	}
}

func TestPostgresSiteSuccessfulWriteAndReadUseGenerationLock(t *testing.T) {
	old := siteFailureSeed()
	conn := &siteFailureConn{site: old, present: true, generation: 7}
	store := siteFailureStore(t, conn)
	saved, err := store.Upsert(context.Background(), adminSiteModel{TenantID: old.TenantID, SiteID: old.SiteID, Name: "After"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if saved.Name != "After" || saved.BootstrapSecretHash != old.BootstrapSecretHash || saved.CreatedAt == nil || *saved.CreatedAt != *old.CreatedAt {
		t.Fatalf("successful metadata save lost authoritative Site fields: %+v", saved)
	}
	if got := store.ConfigGeneration(); got != 8 {
		t.Fatalf("generation after write = %d, want 8", got)
	}
	lock, read := -1, -1
	for i, op := range conn.operations {
		if strings.Contains(op, "pg_advisory_xact_lock") {
			lock = i
		}
		if strings.Contains(op, "last_value") {
			read = i
		}
	}
	if lock < 0 || read <= lock {
		t.Fatalf("generation read did not wait for Site writers: operations=%v", conn.operations)
	}
}
