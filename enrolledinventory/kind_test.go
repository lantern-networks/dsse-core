package enrolledinventory

import "testing"

// An entry that declares nothing is an endpoint. This is the load-bearing default: it is what makes a device
// that VANISHED still fail the coverage checks, which is what they exist for.
func TestUndeclaredKindIsAnEndpoint(t *testing.T) {
	if !(Entry{Identity: "mac-dev-1"}).IsEndpoint() {
		t.Fatal("an entry that declares no kind must read as an endpoint — otherwise a vanished device exempts itself")
	}
	if !(Entry{Identity: "mac-dev-1", Kind: KindEndpoint}).IsEndpoint() {
		t.Fatal("an explicit endpoint must read as an endpoint")
	}
	if (Entry{Identity: "conn-lab-1", Kind: KindService}).IsEndpoint() {
		t.Fatal("a service identity is not an endpoint")
	}
	// Case and whitespace are how a declaration gets typed by a person, not a reason to change its meaning.
	if (Entry{Kind: " Service "}).IsEndpoint() {
		t.Fatal("kind comparison must not depend on case or padding")
	}
}

// A kind the ledger does not understand is REFUSED, not stored. A typo must not silently become
// "not an endpoint" — that is the reading under which silence stops being a finding.
func TestUnknownKindIsRefusedRatherThanStored(t *testing.T) {
	l := NewLedger()
	if _, err := l.EnrollDeviceForTenant("mac-dev-1", "t", "", "", "now"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, _, err := l.SetKind("mac-dev-1", "endpiont", "now"); err == nil {
		t.Fatal("a misspelled kind must be refused")
	}
	e, ok := l.EntryFor("mac-dev-1")
	if !ok || !e.IsEndpoint() {
		t.Fatalf("a refused kind must leave the entry an endpoint, got %#v", e)
	}
	if !ValidKind("") || !ValidKind("endpoint") || !ValidKind("SERVICE") || ValidKind("laptop") {
		t.Fatal("ValidKind disagrees with the kinds the ledger accepts")
	}
}

// Declaring a kind takes effect, and declaring "endpoint" stores absence rather than the word — so the
// default reading and the explicit one can never drift apart.
func TestSetKindStoresTheDefaultAsAbsence(t *testing.T) {
	l := NewLedger()
	if _, err := l.EnrollDeviceForTenant("conn-lab-1", "t", "", "", "now"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, ok, err := l.SetKind("conn-lab-1", KindService, "now"); err != nil || !ok {
		t.Fatalf("SetKind service: ok=%v err=%v", ok, err)
	}
	if e, _ := l.EntryFor("conn-lab-1"); e.Kind != KindService || e.IsEndpoint() {
		t.Fatalf("entry = %#v, want a service that is not an endpoint", e)
	}
	if _, ok, err := l.SetKind("conn-lab-1", KindEndpoint, "later"); err != nil || !ok {
		t.Fatalf("SetKind endpoint: ok=%v err=%v", ok, err)
	}
	e, _ := l.EntryFor("conn-lab-1")
	if e.Kind != "" {
		t.Fatalf("declaring the default must store absence, got kind=%q", e.Kind)
	}
	if !e.IsEndpoint() {
		t.Fatal("back to endpoint")
	}
}

// SetKind on an identity the ledger does not hold reports not-found rather than inventing an entry.
func TestSetKindOnAnUnknownIdentityIsNotFound(t *testing.T) {
	l := NewLedger()
	e, ok, err := l.SetKind("nobody", KindService, "now")
	if ok || err != nil {
		t.Fatalf("want not-found with no error, got ok=%v err=%v entry=%#v", ok, err, e)
	}
}

// Endpoints() answers the question the coverage checks actually ask: which identities are expected to
// report. A service in the ledger is admitted, and is not part of that set.
func TestEndpointsExcludesServiceIdentities(t *testing.T) {
	l := NewLedger()
	for _, id := range []string{"mac-dev-1", "win-dev-1", "conn-lab-1"} {
		if _, err := l.EnrollDeviceForTenant(id, "t", "", "", "now"); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	if _, _, err := l.SetKind("conn-lab-1", KindService, "now"); err != nil {
		t.Fatalf("SetKind: %v", err)
	}
	got := l.Endpoints()
	if len(got) != 2 || got[0].Identity != "mac-dev-1" || got[1].Identity != "win-dev-1" {
		t.Fatalf("Endpoints() = %v, want the two endpoints in order", got)
	}
	// The service is still ENROLLED — it is admitted at the transport, it is simply not expected to report.
	if _, ok := l.EntryFor("conn-lab-1"); !ok {
		t.Fatal("a service identity must remain in the ledger; it authenticates from it")
	}
}
