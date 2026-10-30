package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/enrolltoken"
)

type blockingTokenQueryConnector struct{ started chan struct{} }

func (c blockingTokenQueryConnector) Connect(context.Context) (driver.Conn, error) {
	return blockingTokenQueryConn{started: c.started}, nil
}
func (c blockingTokenQueryConnector) Driver() driver.Driver { return blockingTokenQueryDriver{c} }

type blockingTokenQueryDriver struct{ connector blockingTokenQueryConnector }

func (d blockingTokenQueryDriver) Open(string) (driver.Conn, error) {
	return d.connector.Connect(context.Background())
}

type blockingTokenQueryConn struct{ started chan struct{} }

func (c blockingTokenQueryConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unused")
}
func (c blockingTokenQueryConn) Close() error              { return nil }
func (c blockingTokenQueryConn) Begin() (driver.Tx, error) { return nil, errors.New("unused") }
func (c blockingTokenQueryConn) QueryContext(ctx context.Context, _ string, _ []driver.NamedValue) (driver.Rows, error) {
	select {
	case c.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestPostgresTokenVerifyStopsWhenRequestIsCanceled(t *testing.T) {
	started := make(chan struct{}, 1)
	db := sql.OpenDB(blockingTokenQueryConnector{started: started})
	defer db.Close()
	store := newPostgresEnrolmentTokenStore(db)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, err := store.VerifyContext(ctx, "opaque-test-secret", "tenant", time.Now())
		finished <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("verify did not start its DB read")
	}
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, context.Canceled) || !errors.Is(err, enrolltoken.ErrStateUnavailable) {
			t.Fatalf("canceled DB read must fail closed and preserve cause: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DB Verify kept waiting after its request was canceled")
	}
}

func TestVerifyHelperKeepsMemoryAuthorityCompatible(t *testing.T) {
	store := enrolltoken.NewStore()
	now := time.Now().UTC()
	want, secret, err := store.Issue(enrolltoken.DefaultPolicy(), "tenant", "", "", "admin", "", now.Add(time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifyEnrolmentToken(context.Background(), store, secret, "tenant", now)
	if err != nil || got.ID != want.ID {
		t.Fatalf("memory authority fallback changed: id=%q err=%v", got.ID, err)
	}
}

type contextAwareTokenAuthority struct {
	enrolltoken.Authority
	started  chan struct{}
	returned chan struct{}
	release  chan struct{}
}

func (a contextAwareTokenAuthority) VerifyContext(ctx context.Context, _, _ string, _ time.Time) (enrolltoken.Token, error) {
	select {
	case a.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	close(a.returned)
	return enrolltoken.Token{}, ctx.Err()
}

func (a contextAwareTokenAuthority) Verify(_, _ string, _ time.Time) (enrolltoken.Token, error) {
	select {
	case a.started <- struct{}{}:
	default:
	}
	<-a.release
	return enrolltoken.Token{}, enrolltoken.ErrStateUnavailable
}

func TestFleetTokenVerifyUsesHTTPContext(t *testing.T) {
	authority := contextAwareTokenAuthority{started: make(chan struct{}, 1), returned: make(chan struct{}), release: make(chan struct{})}
	mux := http.NewServeMux()
	registerEnrolmentTokenFleetRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, authority, nil)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	defer close(authority.release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/admin/fleet/enrolment-token/verify", strings.NewReader(`{"secret":"opaque-test-secret"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	finished := make(chan error, 1)
	go func() {
		resp, err := srv.Client().Do(req)
		if resp != nil {
			resp.Body.Close()
		}
		finished <- err
	}()
	select {
	case <-authority.started:
	case <-time.After(time.Second):
		t.Fatal("fleet verify did not reach the authority")
	}
	cancel()
	select {
	case <-authority.returned:
	case <-time.After(time.Second):
		t.Fatal("fleet authority remained blocked after client cancellation")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("client did not complete cancellation")
	}
}

type tokenContextRoundTrip func(*http.Request) (*http.Response, error)

func (fn tokenContextRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

type cancelAfterResponseRead struct {
	reader *strings.Reader
	cancel context.CancelFunc
}

func (r *cancelAfterResponseRead) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.cancel()
	return n, err
}
func (*cancelAfterResponseRead) Close() error { return nil }

func TestRemoteTokenVerifyAndSpendUseRequestContext(t *testing.T) {
	for _, operation := range []string{"verify", "spend"} {
		t.Run(operation, func(t *testing.T) {
			started := make(chan struct{}, 1)
			a := &remoteEnrolmentTokenAuthority{url: "https://authority.example", token: "test", client: &http.Client{
				Transport: tokenContextRoundTrip(func(req *http.Request) (*http.Response, error) {
					select {
					case started <- struct{}{}:
					default:
					}
					<-req.Context().Done()
					return nil, req.Context().Err()
				}),
			}}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			finished := make(chan error, 1)
			go func() {
				var err error
				if operation == "verify" {
					_, err = a.VerifyContext(ctx, "secret", "tenant", time.Now())
				} else {
					_, err = a.SpendContext(ctx, "id", "tenant", "device", time.Now())
				}
				finished <- err
			}()
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("remote request never started")
			}
			cancel()
			select {
			case err := <-finished:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("remote request did not preserve cancel cause: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("remote request did not stop")
			}
		})
	}
}

func TestLeadershipRetryKeepsCanceledRequestContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	a := &remoteEnrolmentTokenAuthority{url: "https://authority.example", token: "test", client: &http.Client{
		Transport: tokenContextRoundTrip(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			body, _ := json.Marshal(enrolmentTokenRemoteResponse{Error: "does not hold leadership"})
			return &http.Response{StatusCode: http.StatusOK, Body: &cancelAfterResponseRead{reader: strings.NewReader(string(body)), cancel: cancel}, Header: make(http.Header)}, nil
		}),
	}}
	_, err := a.VerifyContext(ctx, "secret", "tenant", time.Now())
	if !errors.Is(err, context.Canceled) || calls.Load() != 1 {
		t.Fatalf("leadership retry escaped the canceled request: calls=%d err=%v", calls.Load(), err)
	}
}
