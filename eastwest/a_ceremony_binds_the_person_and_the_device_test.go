package eastwest

import (
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/policy"
)

// Security review S3 (2026-11-07). The challenge id travels in a URL anybody can forward, and a held flow
// without a subject accepted "somebody in this organization logged in". These tests pin what the ceremony now
// binds: the grant names the person who authenticated, a ceremony that proved nobody issues nothing, and a
// ceremony run on a different device than the one holding the flow releases nothing.

func heldFlowWithoutASubject(now time.Time) (*AuthChallengeStore, AuthChallenge) {
	ch := NewAuthChallengeStore()
	c := ch.Create(AuthChallenge{TenantID: "acme", DeviceID: "laptop-7", Destination: "10.0.0.5:22", Protocol: "ssh"}, now)
	return ch, c
}

func TestTheGrantNamesThePersonWhoAuthenticated(t *testing.T) {
	now := time.Now().UTC()
	store := policy.NewStore(nil)
	ch, c := heldFlowWithoutASubject(now)
	resp, err := CompleteCeremony(store, ch, c.ID, CeremonyProof{TenantID: "acme", SubjectUserID: "alice", DeviceID: "laptop-7"}, now)
	if err != nil {
		t.Fatalf("ceremony on the held flow's own device: %v", err)
	}
	if resp.AuthenticatedBy != "alice" {
		t.Fatalf("the grant does not name who authenticated: %+v", resp)
	}
	if !resp.CeremonyDeviceVerified {
		t.Fatal("the ceremony ran on the held flow's device and the grant does not say so")
	}
	grants := store.EastWestGrantsFor("acme", now)
	if len(grants) != 1 || grants[0].AuthenticatedBy != "alice" || !grants[0].CeremonyDeviceVerified {
		t.Fatalf("stored grant lost the attribution: %+v", grants)
	}
}

func TestACeremonyThatProvedNobodyIssuesNothing(t *testing.T) {
	now := time.Now().UTC()
	store := policy.NewStore(nil)
	ch, c := heldFlowWithoutASubject(now)
	if _, err := CompleteCeremony(store, ch, c.ID, CeremonyProof{TenantID: "acme", SubjectUserID: "  "}, now); err == nil {
		t.Fatal("a subjectless held flow was released by a ceremony that proved no identity")
	}
	if len(ch.ListPending("acme", now)) != 1 {
		t.Fatal("the failed ceremony consumed the challenge")
	}
}

func TestAForwardedLinkOpenedOnAnotherDeviceReleasesNothing(t *testing.T) {
	now := time.Now().UTC()
	store := policy.NewStore(nil)
	ch, c := heldFlowWithoutASubject(now)
	_, err := CompleteCeremony(store, ch, c.ID, CeremonyProof{TenantID: "acme", SubjectUserID: "bob", DeviceID: "desktop-2"}, now)
	if err == nil {
		t.Fatal("a ceremony run on another device released the held flow")
	}
	if !strings.Contains(err.Error(), "ran on device") {
		t.Fatalf("the refusal does not say which device: %v", err)
	}
	if len(store.EastWestGrantsFor("acme", now)) != 0 {
		t.Fatal("a grant was issued for a ceremony on the wrong device")
	}
	if len(ch.ListPending("acme", now)) != 1 {
		t.Fatal("the refused ceremony consumed the challenge; the real user could no longer complete it")
	}
}

func TestACeremonyWhoseDeviceCannotBeKnownIssuesButSaysSo(t *testing.T) {
	now := time.Now().UTC()
	store := policy.NewStore(nil)
	ch, c := heldFlowWithoutASubject(now)
	resp, err := CompleteCeremony(store, ch, c.ID, CeremonyProof{TenantID: "acme", SubjectUserID: "carol"}, now)
	if err != nil {
		t.Fatalf("a ceremony from a browser without a device identity must still issue: %v", err)
	}
	if resp.CeremonyDeviceVerified {
		t.Fatal("the grant claims the device was verified when the browser presented none")
	}
	if resp.AuthenticatedBy != "carol" {
		t.Fatalf("attribution lost: %+v", resp)
	}
}
