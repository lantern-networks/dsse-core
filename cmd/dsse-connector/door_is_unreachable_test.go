package main

import (
	"errors"
	"fmt"
	"net"
	"testing"
)

// ★ REACHED-AND-REFUSED IS NOT UNREACHABLE. Failing over on "this door does not know me" would carry a
// connector into another region on evidence about its own registration, and re-registering — which is what
// that fault needs — would then happen against a door nobody chose.
func TestOnlyAnUnreachableDoorMovesAConnector(t *testing.T) {
	unreachable := []error{
		fmt.Errorf(`Post "https://agents.osaka.example/heartbeat": dial tcp 1.2.3.4:443: i/o timeout`),
		fmt.Errorf("read tcp 10.0.0.1:1->1.2.3.4:443: read: connection timed out"),
		&net.DNSError{Err: "no such host", Name: "agents.osaka.example"},
		fmt.Errorf("dial tcp 1.2.3.4:443: connect: connection refused"),
		fmt.Errorf("context deadline exceeded"),
	}
	for _, err := range unreachable {
		if !doorIsUnreachable(err) {
			t.Fatalf("this is a door that could not be reached and must move the connector: %v", err)
		}
	}
	refused := []error{
		errors.New("status 401 from https://agents.osaka.example/heartbeat"),
		errors.New("status 404 from https://agents.osaka.example/heartbeat"),
		errors.New("connector is not known to this edge"),
		nil,
	}
	for _, err := range refused {
		if doorIsUnreachable(err) {
			t.Fatalf("this door ANSWERED; moving region on it would hide the real fault: %v", err)
		}
	}
}
