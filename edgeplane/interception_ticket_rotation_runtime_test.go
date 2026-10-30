package edgeplane

import (
	"testing"
	"time"
)

func TestLongLivedInterceptionEngineRotatesFleetTicketKeys(t *testing.T) {
	t.Setenv("DSSE_INTERCEPTION_SESSION_TICKET_SECRET", "synthetic-fleet-ticket-secret")
	clock := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	engine, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	first := engine.ticketKeysForConnection()
	if len(first) != 2 {
		t.Fatal("expected current and previous fleet ticket keys")
	}
	clock = clock.Add(sessionTicketRotationPeriod)
	second := engine.ticketKeysForConnection()
	if len(second) != 2 || second[0] == first[0] || second[1] != first[0] {
		t.Fatal("a long-lived Edge did not rotate ticket keys with previous-epoch overlap")
	}
	peer, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	if peer.ticketKeysForConnection()[0] != second[0] {
		t.Fatal("the running Edge and a restarted peer derived different fleet keys")
	}
}

func TestOfflineInterceptionEngineSharesAndRotatesFleetTicketKeys(t *testing.T) {
	t.Setenv("DSSE_INTERCEPTION_SESSION_TICKET_SECRET", "synthetic-fleet-ticket-secret")
	clock := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	root, intermediate, key, _ := tenantOfflineBundle(t, "Northwind", clock)
	engine, err := NewNetworkExtensionLabTLSInterceptionOfflineIntermediate(
		[]string{"*"}, func() time.Time { return clock }, root, intermediate, key, "")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := NewNetworkExtensionLabTLSInterceptionOfflineIntermediate(
		[]string{"*"}, func() time.Time { return clock }, root, intermediate, key, "")
	if err != nil {
		t.Fatal(err)
	}
	first := engine.ticketKeysForConnection()
	if len(first) != 2 || peer.ticketKeysForConnection()[0] != first[0] {
		t.Fatal("offline-root Edges did not share the configured fleet ticket key")
	}
	clock = clock.Add(sessionTicketRotationPeriod)
	second := engine.ticketKeysForConnection()
	if len(second) != 2 || second[0] == first[0] || second[1] != first[0] {
		t.Fatal("offline-root Edge did not rotate its fleet ticket key")
	}
}

func TestLocalInterceptionTicketSecretRotatesWithoutCrossProcessSharing(t *testing.T) {
	t.Setenv("DSSE_INTERCEPTION_SESSION_TICKET_SECRET", "")
	clock := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	a, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewNetworkExtensionLabTLSInterception([]string{"*"}, func() time.Time { return clock })
	if err != nil {
		t.Fatal(err)
	}
	first := a.ticketKeysForConnection()
	if len(first) != 2 || b.ticketKeysForConnection()[0] == first[0] {
		t.Fatal("per-process ticket keys were absent or shared")
	}
	clock = clock.Add(sessionTicketRotationPeriod)
	second := a.ticketKeysForConnection()
	if len(second) != 2 || second[0] == first[0] || second[1] != first[0] {
		t.Fatal("per-process ticket keys never rotated on a long-lived Edge")
	}
}
