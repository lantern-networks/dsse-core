package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/policycandidate"
)

// A database/sql driver boundary test, not a live PostgreSQL test. Cancellation
// occurs after the driver accepted UPDATE but before database/sql sees its result.
type blobCancelDB struct {
	mu        sync.Mutex
	raw       []byte
	cancel    context.CancelFunc
	commitErr error
	commits   int
}
type blobCancelConnector struct{ state *blobCancelDB }

func (c blobCancelConnector) Connect(context.Context) (driver.Conn, error) {
	return &blobCancelConn{state: c.state}, nil
}
func (blobCancelConnector) Driver() driver.Driver { return blobCancelDriver{} }

type blobCancelDriver struct{}

func (blobCancelDriver) Open(string) (driver.Conn, error) { return nil, errors.New("use connector") }

type blobCancelConn struct {
	state   *blobCancelDB
	pending []byte
}

func (*blobCancelConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("unused") }
func (*blobCancelConn) Close() error                        { return nil }
func (c *blobCancelConn) Begin() (driver.Tx, error)         { return c, nil }
func (c *blobCancelConn) ExecContext(_ context.Context, q string, args []driver.NamedValue) (driver.Result, error) {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	if strings.HasPrefix(q, "UPDATE") {
		c.pending = append([]byte(nil), args[1].Value.([]byte)...)
		if c.state.cancel != nil {
			c.state.cancel()
			c.state.cancel = nil
		}
		return driver.RowsAffected(1), nil
	}
	if c.state.raw == nil {
		return driver.RowsAffected(1), nil
	}
	return driver.RowsAffected(0), nil
}
func (c *blobCancelConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	return &blobCancelRows{raw: append([]byte(nil), c.state.raw...)}, nil
}
func (c *blobCancelConn) Commit() error {
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	c.state.commits++
	c.state.raw = append([]byte(nil), c.pending...)
	return c.state.commitErr
}
func (c *blobCancelConn) Rollback() error { c.pending = nil; return nil }

type blobCancelRows struct {
	raw  []byte
	done bool
}

func (*blobCancelRows) Columns() []string { return []string{"payload"} }
func (*blobCancelRows) Close() error      { return nil }
func (r *blobCancelRows) Next(dest []driver.Value) error {
	if r.done || r.raw == nil {
		return io.EOF
	}
	r.done = true
	dest[0] = r.raw
	return nil
}

func TestBlobCancellationBeforeCommitKeepsCandidateUsable(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "cancel"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			state := &blobCancelDB{raw: []byte(`{}`)}
			db := sql.OpenDB(blobCancelConnector{state})
			defer db.Close()
			p := postgresBlobPersister{db: db, key: "policy_candidates"}
			s := policycandidate.NewStore()
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := error(context.Canceled)
			if deadline {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				state.cancel = func() { <-ctx.Done() }
				want = context.DeadlineExceeded
			} else {
				state.cancel = cancel
			}
			_, err := s.ObserveCertPinFailure(ctx, "own", "named.example", "", 443, "pin", time.Now())
			state.mu.Lock()
			commits := state.commits
			raw := string(state.raw)
			state.mu.Unlock()
			if commits != 0 || raw != "{}" {
				t.Fatalf("canceled write committed: commits=%d raw=%s", commits, raw)
			}
			if !errors.Is(err, blobstore.ErrWriteNotCommitted) || !errors.Is(err, want) {
				t.Fatalf("definite rollback misclassified: %v", err)
			}
			if _, err = s.List(context.Background(), "own", policycandidate.ListOptions{}); err != nil {
				t.Fatal("store latched unavailable", err)
			}
			c, err := s.ObserveCertPinFailure(context.Background(), "own", "named.example", "", 443, "pin", time.Now())
			if err != nil || c.FailureCount != 1 {
				t.Fatal("retry failed or double counted", c, err)
			}

		})
	}
}

func TestBlobDriverCommitErrorRemainsUnknown(t *testing.T) {
	for _, commitErr := range []error{context.Canceled, context.DeadlineExceeded, errors.New("lost commit response")} {
		t.Run(commitErr.Error(), func(t *testing.T) {
			state := &blobCancelDB{raw: []byte(`{}`), commitErr: commitErr}
			db := sql.OpenDB(blobCancelConnector{state})
			defer db.Close()
			p := postgresBlobPersister{db: db, key: "policy_candidates"}
			s := policycandidate.NewStore()
			if err := s.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			_, err := s.ObserveCertPinFailure(context.Background(), "own", "named.example", "", 443, "pin", time.Now())
			if !errors.Is(err, commitErr) || errors.Is(err, blobstore.ErrWriteNotCommitted) {
				t.Fatal("commit uncertainty lost", err)
			}
			if _, err = s.List(context.Background(), "own", policycandidate.ListOptions{}); !errors.Is(err, policycandidate.ErrUnavailable) {
				t.Fatal("unknown state served", err)
			}
			if state.commits != 1 {
				t.Fatal("driver commit not exercised")
			}
		})
	}
}
