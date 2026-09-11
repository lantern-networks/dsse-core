package interception_test

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/interception"
)

// A host that repeatedly rejects the interception leaf is PROPOSED (observer fired at the threshold) but
// never auto-bypassed: Matches still returns true (it stays an intercept target until an admin approves
// + materializes a bypass).
func TestCertPinDetectionProposesAfterThresholdNoAutoBypass(t *testing.T) {
	eng, err := interception.NewEngine([]string{"*"}, nil, interception.CAOptions{})
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	calls := 0
	eng.SetCertPinObserver(func(r interception.Route, count int) { mu.Lock(); calls++; mu.Unlock() }, 2)

	route := interception.Route{Host: "pinned.example.com", Port: 443}
	for i := 0; i < 2; i++ {
		c, s := net.Pipe()
		go eng.Intercept(s, route)
		_ = c.Close() // client rejects the leaf -> server handshake fails
		time.Sleep(80 * time.Millisecond)
	}
	mu.Lock()
	n := calls
	mu.Unlock()
	if n != 1 {
		t.Fatalf("observer should fire once at the threshold, got %d", n)
	}
	// Detection must NOT auto-bypass: the host is still an intercept target.
	if !eng.Matches(route) {
		t.Fatal("detection must not auto-bypass; host should still match interception")
	}
}
