package main

import "testing"

// A stream the Edge writes and the shipper does not carry is a file that grows on the Edge and reaches
// nobody. On acceptance D (2026-11-09) that file was connector.log.jsonl: the connector attached to a
// dedicated Edge, the control plane's store held no connector row, and the Console's Connector tab stayed empty
// through a registration, two failovers and a deletion.
func TestAConnectorsConnectionsAreShippedToTheControlPlane(t *testing.T) {
	for _, s := range defaultAuditShipStreams {
		if s == "connector.log.jsonl" {
			return
		}
	}
	t.Fatal("connector.log.jsonl is not in defaultAuditShipStreams: an Edge on its own machine writes a connector's connections where nobody reads them")
}

// And the control plane's receiver accepts what the shipper sends: the allowlist is derived from the same list,
// so this guards the derivation staying that way.
func TestTheIngestReceiverAcceptsEveryShippedStream(t *testing.T) {
	allowed := auditIngestAllowedStreams()
	for _, s := range defaultAuditShipStreams {
		if !allowed[s] {
			t.Fatalf("the shipper sends %q but the receiver refuses it", s)
		}
	}
}
