package main

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Found 2026-11-08 on acceptance C: stopping the leader's entrance cost sign-in at every entrance. The browser
// reached the Console through the two doors that were up, and the Console answered 502 for every sign-in,
// because it left for admin.<host> through the door on its own machine — the one that had been stopped. The
// existing test of a stopped entrance (leader_entrance_failure_test.go) had the Console reach its authority
// directly, so the way out was never part of what it stopped.
func TestTheConsoleSignsInThroughAnotherDoorWhenItsOwnIsStopped(t *testing.T) {
	f := newConsoleLeaderFixture(t)
	var names []string
	var seen atomic.Int32
	authority := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Add(1)
		names = append(names, r.TLS.ServerName+" "+r.Host)
		if r.Method == "POST" && r.URL.Path == "/admin/login/test" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(w, r)
	}))
	authority.TLS = f.tls.Clone()
	authority.StartTLS()
	defer authority.Close()

	// This machine's door: stopped. Its address refuses.
	stopped, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	here := stopped.Addr().String()
	stopped.Close()
	// Another machine's door: up, and routes the same name to the same authority (TLS passes through).
	there := consoleTestEntrance(t, authority.Listener.Addr().String())

	doors, err := newDoorDialer("10.0.0.2:443")
	if err != nil || doors == nil {
		t.Fatalf("door list refused: %v", err)
	}
	var hereDials atomic.Int32
	doors.Dial = func(ctx context.Context, network, address string, wait time.Duration) (net.Conn, error) {
		target := map[string]string{"cp-a.example:443": here, "10.0.0.2:443": there.Addr().String()}[address]
		if address == "cp-a.example:443" {
			hereDials.Add(1)
		}
		if target == "" {
			t.Errorf("dialled %q, which is neither this door nor a listed one", address)
		}
		return (&net.Dialer{Timeout: wait}).DialContext(ctx, network, target)
	}

	signIn := func(proxy http.Handler) int {
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, httptest.NewRequest("POST", "https://console.example/admin/login/test", strings.NewReader(`{}`)))
		return w.Code
	}
	// Without the other doors this is what the administrator saw.
	if got := signIn(newReverseProxy("https://cp-a.example", f.trust.Clone(), nil)); got != http.StatusBadGateway {
		t.Fatalf("with only its own door the Console answered %d; the reproduction no longer reproduces", got)
	}
	if seen.Load() != 0 {
		t.Fatal("the authority was reached without another door")
	}

	proxy := newReverseProxy("https://cp-a.example", f.trust.Clone(), doors)
	for i := 0; i < 3; i++ {
		if got := signIn(proxy); got != http.StatusNoContent {
			t.Fatalf("sign-in %d through another door answered %d", i+1, got)
		}
	}
	// The connection was carried by another door but checked as the name in the URL: same server name, same
	// Host, same certificate check. A door can carry it; it cannot answer for it.
	for _, n := range names {
		if n != "cp-a.example cp-a.example" {
			t.Fatalf("authority saw %q, want the URL's own name in both the TLS server name and Host", n)
		}
	}
	// One wait for the stopped door, not one per request.
	if got := hereDials.Load(); got != 1 {
		t.Fatalf("tried the stopped door %d times in three requests, want once and then rest", got)
	}
}

func TestTheConsoleGoesBackToItsOwnDoorWhenItAnswersAgain(t *testing.T) {
	doors, _ := newDoorDialer("10.0.0.2:443,10.0.0.3:443")
	clock := time.Unix(0, 0)
	doors.Now = func() time.Time { return clock }
	up := false
	var order []string
	doors.Dial = func(_ context.Context, _, address string, _ time.Duration) (net.Conn, error) {
		order = append(order, address)
		if address == "here:443" && !up {
			return nil, &net.OpError{Op: "dial", Err: errRefused{}}
		}
		c, s := net.Pipe()
		s.Close()
		return c, nil
	}
	dial := func() {
		c, err := doors.DialContext(context.Background(), "tcp", "here:443")
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	}
	dial() // here refused -> 10.0.0.2
	dial() // resting: 10.0.0.2 first
	clock = clock.Add(16 * time.Second)
	up = true
	dial() // rest over: here again, and it answers
	dial()
	want := "here:443 10.0.0.2:443 10.0.0.2:443 here:443 here:443"
	if got := strings.Join(order, " "); got != want {
		t.Fatalf("dial order = %s, want %s", got, want)
	}
}

type errRefused struct{}

func (errRefused) Error() string { return "connection refused" }

func TestADoorListTheConsoleCannotReadStopsIt(t *testing.T) {
	for _, raw := range []string{"10.0.0.2", "https://10.0.0.2:443", "10.0.0.2:443/x", ":443"} {
		if _, err := newDoorDialer(raw); err == nil {
			t.Errorf("%q was accepted as a door", raw)
		}
	}
	if d, err := newDoorDialer(" , "); d != nil || err != nil {
		t.Fatalf("an empty list must mean only this machine's door, got %v %v", d, err)
	}
	d, err := newDoorDialer("10.0.0.2:443, 10.0.0.2:443,[fd00::2]:443")
	if err != nil || strings.Join(d.Fallbacks(), ",") != "10.0.0.2:443,[fd00::2]:443" {
		t.Fatalf("doors = %v (%v)", d, err)
	}
}
