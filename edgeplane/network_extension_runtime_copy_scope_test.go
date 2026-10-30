package edgeplane

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type runtimeCopyScopeConn struct {
	mu     sync.Mutex
	writes int
	closed bool
}

func (c *runtimeCopyScopeConn) Read(p []byte) (int, error) { return copy(p, "reply"), nil }
func (c *runtimeCopyScopeConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	c.writes++
	return len(p), nil
}
func (c *runtimeCopyScopeConn) Close() error { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func (c *runtimeCopyScopeConn) state() (int, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes, c.closed
}

type runtimeCopyScopeDialer struct {
	mu    sync.Mutex
	conns []*runtimeCopyScopeConn
}

func (d *runtimeCopyScopeDialer) OpenTCPConnection(context.Context, NetworkExtensionRuntimeCopyTCPRoute) (io.ReadWriteCloser, error) {
	c := &runtimeCopyScopeConn{}
	d.mu.Lock()
	d.conns = append(d.conns, c)
	d.mu.Unlock()
	return c, nil
}
func (d *runtimeCopyScopeDialer) conn(n int) *runtimeCopyScopeConn {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.conns[n]
}

func runtimeCopyScopeRequest(t *testing.T, h http.Handler, tenant, device, operation, requestID string) *httptest.ResponseRecorder {
	t.Helper()
	body, err := json.Marshal(networkExtensionRuntimeCopySessionRequest{
		SchemaVersion: NetworkExtensionRuntimeCopySessionRequestSchema,
		TenantID:      tenant, RequestID: requestID, Operation: operation,
		ApplicationID: "app", DestinationHost: "example.com", DestinationPort: 443,
		UpstreamPayloadBase64: base64.StdEncoding.EncodeToString([]byte("payload")),
	})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, NetworkExtensionRuntimeCopySessionPath, strings.NewReader(string(body)))
	r.Header.Set("X-Test-Tenant", tenant)
	r.Header.Set("X-Test-Device", device)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestRuntimeCopySessionHTTPRejectsCrossTenantAndCrossDeviceUse(t *testing.T) {
	dialer := &runtimeCopyScopeDialer{}
	manager := NewNetworkExtensionRuntimeCopySessionManager(0, 0, nil)
	h := NewNetworkExtensionRuntimeCopySessionHandler(NetworkExtensionRuntimeCopySessionHandlerConfig{
		TenantID: "node", Dialer: dialer, SessionManager: manager,
		DeviceTenant:      func(r *http.Request) (string, bool) { return r.Header.Get("X-Test-Tenant"), true },
		TransportIdentity: func(r *http.Request) (string, bool) { return r.Header.Get("X-Test-Device"), true },
	})
	if w := runtimeCopyScopeRequest(t, h, "tenant-a", "device-a", "open", "known-id"); w.Code != http.StatusOK {
		t.Fatalf("owner open=%d", w.Code)
	}
	owner := dialer.conn(0)
	for _, other := range []struct{ tenant, device string }{{"tenant-b", "device-b"}, {"tenant-a", "device-b"}} {
		if w := runtimeCopyScopeRequest(t, h, other.tenant, other.device, "exchange", "known-id"); w.Code == http.StatusOK {
			t.Fatalf("other owner exchanged session: %s/%s", other.tenant, other.device)
		}
		if w := runtimeCopyScopeRequest(t, h, other.tenant, other.device, "close", "known-id"); w.Code == http.StatusOK {
			t.Fatalf("other owner closed session: %s/%s", other.tenant, other.device)
		}
	}
	wrongApp := networkExtensionRuntimeCopySessionRequest{
		SchemaVersion: NetworkExtensionRuntimeCopySessionRequestSchema,
		TenantID:      "tenant-a", RequestID: "known-id", Operation: "close", ApplicationID: "other-app",
	}
	wrongBody, err := json.Marshal(wrongApp)
	if err != nil {
		t.Fatal(err)
	}
	wrongRequest := httptest.NewRequest(http.MethodPost, NetworkExtensionRuntimeCopySessionPath, strings.NewReader(string(wrongBody)))
	wrongRequest.Header.Set("X-Test-Tenant", "tenant-a")
	wrongRequest.Header.Set("X-Test-Device", "device-a")
	wrongResponse := httptest.NewRecorder()
	h.ServeHTTP(wrongResponse, wrongRequest)
	if wrongResponse.Code == http.StatusOK {
		t.Fatal("another application closed the owner session")
	}
	if writes, closed := owner.state(); writes != 1 || closed {
		t.Fatalf("owner session affected: writes=%d closed=%v", writes, closed)
	}
	if w := runtimeCopyScopeRequest(t, h, "tenant-a", "device-a", "exchange", "known-id"); w.Code != http.StatusOK {
		t.Fatalf("owner exchange=%d", w.Code)
	}
}

func TestRuntimeCopySessionHTTPAllowsSameRequestIDForDifferentOwners(t *testing.T) {
	dialer := &runtimeCopyScopeDialer{}
	h := NewNetworkExtensionRuntimeCopySessionHandler(NetworkExtensionRuntimeCopySessionHandlerConfig{
		TenantID: "node", Dialer: dialer, SessionManager: NewNetworkExtensionRuntimeCopySessionManager(0, 0, nil),
		DeviceTenant:      func(r *http.Request) (string, bool) { return r.Header.Get("X-Test-Tenant"), true },
		TransportIdentity: func(r *http.Request) (string, bool) { return r.Header.Get("X-Test-Device"), true },
	})
	for _, owner := range []struct{ tenant, device string }{{"tenant-a", "device-a"}, {"tenant-b", "device-b"}} {
		if w := runtimeCopyScopeRequest(t, h, owner.tenant, owner.device, "open", "same-id"); w.Code != http.StatusOK {
			t.Fatalf("owner %s/%s open=%d", owner.tenant, owner.device, w.Code)
		}
	}
}

func TestRuntimeCopySessionHTTPDoesNotFallBackAfterResolverRejectsIdentity(t *testing.T) {
	dialer := &runtimeCopyScopeDialer{}
	for _, tenantResolver := range []DeviceTenantFunc{
		func(*http.Request) (string, bool) { return "", false },
		func(*http.Request) (string, bool) { return "node", true },
	} {
		h := NewNetworkExtensionRuntimeCopySessionHandler(NetworkExtensionRuntimeCopySessionHandlerConfig{
			TenantID: "node", Dialer: dialer,
			DeviceTenant:      tenantResolver,
			TransportIdentity: func(*http.Request) (string, bool) { return "", false },
		})
		if w := runtimeCopyScopeRequest(t, h, "node", "", "open", "unknown-owner"); w.Code == http.StatusOK {
			t.Fatal("unverified transport identity inherited a tenant-wide session owner")
		}
	}
}

type runtimeCopyStaleConn struct {
	readStarted chan struct{}
	release     chan struct{}
	once        sync.Once
}

func (c *runtimeCopyStaleConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *runtimeCopyStaleConn) Read([]byte) (int, error) {
	c.once.Do(func() { close(c.readStarted) })
	<-c.release
	return 0, errors.New("old session read failed")
}
func (c *runtimeCopyStaleConn) Close() error { return nil }

type runtimeCopyRaceDialer struct {
	mu    sync.Mutex
	old   *runtimeCopyStaleConn
	new   *runtimeCopyScopeConn
	calls int
}

func (d *runtimeCopyRaceDialer) OpenTCPConnection(context.Context, NetworkExtensionRuntimeCopyTCPRoute) (io.ReadWriteCloser, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.calls++
	if d.calls == 1 {
		return d.old, nil
	}
	return d.new, nil
}

func TestRuntimeCopySessionStaleExchangeCannotCloseReplacement(t *testing.T) {
	dialer := &runtimeCopyRaceDialer{
		old: &runtimeCopyStaleConn{readStarted: make(chan struct{}), release: make(chan struct{})},
		new: &runtimeCopyScopeConn{},
	}
	h := NewNetworkExtensionRuntimeCopySessionHandler(NetworkExtensionRuntimeCopySessionHandlerConfig{
		TenantID: "node", Dialer: dialer,
		SessionManager:    NewNetworkExtensionRuntimeCopySessionManager(0, 0, nil),
		DeviceTenant:      func(r *http.Request) (string, bool) { return r.Header.Get("X-Test-Tenant"), true },
		TransportIdentity: func(r *http.Request) (string, bool) { return r.Header.Get("X-Test-Device"), true },
	})
	oldDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { oldDone <- runtimeCopyScopeRequest(t, h, "tenant-a", "device-a", "open", "reused-id") }()
	select {
	case <-dialer.old.readStarted:
	case <-time.After(time.Second):
		t.Fatal("old exchange did not reach its blocked read")
	}
	if w := runtimeCopyScopeRequest(t, h, "tenant-a", "device-a", "close", "reused-id"); w.Code != http.StatusOK {
		t.Fatalf("old close=%d", w.Code)
	}
	if w := runtimeCopyScopeRequest(t, h, "tenant-a", "device-a", "open", "reused-id"); w.Code != http.StatusOK {
		t.Fatalf("replacement open=%d", w.Code)
	}
	close(dialer.old.release)
	select {
	case <-oldDone:
	case <-time.After(time.Second):
		t.Fatal("old exchange did not finish")
	}
	if _, closed := dialer.new.state(); closed {
		t.Fatal("old exchange completion closed replacement session")
	}
	if w := runtimeCopyScopeRequest(t, h, "tenant-a", "device-a", "exchange", "reused-id"); w.Code != http.StatusOK {
		t.Fatalf("replacement exchange=%d", w.Code)
	}
}
