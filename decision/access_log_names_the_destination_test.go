package decision

import (
	"testing"

	"github.com/lantern-networks/dsse-core/model"
)

// Found 2026-11-04: a steered flow denied by an FQDN rule was logged under its IPv6 literal, so searching the
// log for the rule's name found nothing. The row names the destination; the address is kept beside it.
func TestAccessLogNamesAConnectByIPDestination(t *testing.T) {
	ip, name := "2606:4700:10::ac42:9ded", "example.org"
	got := AccessLogFromDecision(model.AccessDecision{Destination: &ip, FQDN: &name})
	if got.Destination == nil || *got.Destination != name {
		t.Fatalf("destination = %v, want %q", got.Destination, name)
	}
	if got.Metadata["destination_ip"] != ip {
		t.Fatalf("metadata destination_ip = %v, want %q", got.Metadata["destination_ip"], ip)
	}

	sni := "www.example.org"
	got = AccessLogFromDecision(model.AccessDecision{Destination: &ip, SNI: &sni})
	if got.Destination == nil || *got.Destination != sni {
		t.Fatalf("SNI fallback destination = %v, want %q", got.Destination, sni)
	}

	// A flow with no name keeps its address, and a named destination is untouched.
	got = AccessLogFromDecision(model.AccessDecision{Destination: &ip})
	if got.Destination == nil || *got.Destination != ip {
		t.Fatalf("unnamed destination = %v, want %q", got.Destination, ip)
	}
	host := "files.internal.example"
	got = AccessLogFromDecision(model.AccessDecision{Destination: &host, FQDN: &name})
	if got.Destination == nil || *got.Destination != host {
		t.Fatalf("named destination = %v, want %q", got.Destination, host)
	}
}
