package swg

import (
	"context"
	"net"
	"testing"
)

func TestIsBlockedEgressIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1", "::1", // loopback
		"169.254.169.254",        // cloud metadata (link-local)
		"169.254.1.1", "fe80::1", // link-local
		"10.0.0.5", "172.16.0.1", "192.168.100.1", // RFC1918
		"100.64.0.1", "100.127.255.254", // RFC6598 carrier-grade NAT (cloud internal fabric)
		"fc00::1", "fd12::1", // ULA
		"0.0.0.0", "::", // unspecified
	}
	for _, s := range blocked {
		if !IsBlockedEgressIP(net.ParseIP(s)) {
			t.Errorf("expected %s to be BLOCKED (internal egress)", s)
		}
	}
	allowed := []string{
		"1.1.1.1", "8.8.8.8", "93.184.216.34", // public v4
		"100.63.255.255", "100.128.0.0", // just outside RFC6598 on both sides
		"2606:4700:4700::1111", // public v6 (cloudflare)
	}
	for _, s := range allowed {
		if IsBlockedEgressIP(net.ParseIP(s)) {
			t.Errorf("expected %s to be ALLOWED (public forward-proxy egress)", s)
		}
	}
}

func TestSSRFEgressControlGate(t *testing.T) {
	// Disabled (lab default): even an internal address passes the Control (loopback test upstreams work).
	internalBlockEnabled.Store(false)
	if err := EgressControl("tcp", "127.0.0.1:443", nil); err != nil {
		t.Fatalf("guard disabled: loopback must pass, got %v", err)
	}
	// Enabled (production): internal blocked, public allowed.
	internalBlockEnabled.Store(true)
	defer internalBlockEnabled.Store(false)
	if err := EgressControl("tcp", "169.254.169.254:80", nil); err == nil {
		t.Fatal("guard enabled: cloud metadata egress MUST be blocked")
	}
	if err := EgressControl("tcp", "1.1.1.1:443", nil); err != nil {
		t.Fatalf("guard enabled: public egress must pass, got %v", err)
	}
}

// guardTestConn is a stub net.Conn whose RemoteAddr is a real *net.TCPAddr, so GuardDialContext's
// post-connect check exercises the same type switch it hits on a production dial.
type guardTestConn struct {
	net.Conn
	remote net.Addr
	closed bool
}

func (c *guardTestConn) RemoteAddr() net.Addr { return c.remote }
func (c *guardTestConn) Close() error         { c.closed = true; return nil }

// GuardDialContext must enforce the guard on an arbitrary base dialer (one built WITHOUT the Control hook):
// the production egress paths pass plain dialers, and a guard that only lives on the nil-base default is
// dead code — exactly the hole this wrapper closes.
func TestGuardDialContextBlocksInternalPeer(t *testing.T) {
	internalBlockEnabled.Store(true)
	defer internalBlockEnabled.Store(false)

	dialTo := func(ip string) *guardTestConn {
		return &guardTestConn{remote: &net.TCPAddr{IP: net.ParseIP(ip), Port: 80}}
	}
	metadata := dialTo("169.254.169.254")
	guarded := GuardDialContext(func(_ context.Context, _, _ string) (net.Conn, error) {
		return metadata, nil
	})
	if _, err := guarded(context.Background(), "tcp", "rebound.example.com:80"); err == nil {
		t.Fatal("guard enabled: dial that connected to the metadata address MUST be refused")
	}
	if !metadata.closed {
		t.Fatal("blocked connection must be closed before any bytes are sent")
	}

	public := dialTo("93.184.216.34")
	guarded = GuardDialContext(func(_ context.Context, _, _ string) (net.Conn, error) {
		return public, nil
	})
	if _, err := guarded(context.Background(), "tcp", "example.com:80"); err != nil {
		t.Fatalf("guard enabled: public egress must pass, got %v", err)
	}

	// Disabled (lab): internal passes untouched.
	internalBlockEnabled.Store(false)
	loopback := dialTo("127.0.0.1")
	guarded = GuardDialContext(func(_ context.Context, _, _ string) (net.Conn, error) {
		return loopback, nil
	})
	if _, err := guarded(context.Background(), "tcp", "localhost:80"); err != nil {
		t.Fatalf("guard disabled: loopback must pass, got %v", err)
	}
}

// CheckEgressDestination is the guard for egress the Edge does not dial itself (the browser-faithful broker
// re-originates in another process). It is the ONLY SSRF check on that path, so the gate, the IP-literal case and
// the resolved-name case all have to hold — a silent pass here is an open pivot into internal infrastructure.
func TestCheckEgressDestinationGuardsBrokerEgress(t *testing.T) {
	ctx := context.Background()

	// Disabled (lab default): internal destinations pass, so loopback test upstreams keep working.
	internalBlockEnabled.Store(false)
	if err := CheckEgressDestination(ctx, "127.0.0.1"); err != nil {
		t.Fatalf("guard disabled: loopback must pass, got %v", err)
	}

	internalBlockEnabled.Store(true)
	defer internalBlockEnabled.Store(false)

	// IP literals: no resolution involved, decided directly.
	for _, host := range []string{"169.254.169.254", "10.0.0.5", "127.0.0.1", "::1", "fd12::1"} {
		if err := CheckEgressDestination(ctx, host); err == nil {
			t.Errorf("expected %s to be BLOCKED", host)
		}
	}
	if err := CheckEgressDestination(ctx, "1.1.1.1"); err != nil {
		t.Errorf("public literal must pass, got %v", err)
	}

	// A name that resolves to loopback is blocked on the resolved address, not on the string: this is the case an
	// attacker controls (localtest.me and friends resolve to 127.0.0.1 from a public DNS name).
	if _, err := net.DefaultResolver.LookupIPAddr(ctx, "localhost"); err == nil {
		if err := CheckEgressDestination(ctx, "localhost"); err == nil {
			t.Error("expected a name resolving to loopback to be BLOCKED")
		}
	}

	// An empty destination must not be treated as "nothing to check".
	if err := CheckEgressDestination(ctx, ""); err == nil {
		t.Error("expected an empty destination to be REFUSED")
	}
}
