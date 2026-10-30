package idpregistry

import (
	"path/filepath"
	"testing"
)

func TestDeviceUserAssignmentRevisionAndIsolation(t *testing.T) {
	s := NewStore()
	path := filepath.Join(t.TempDir(), "registry.json")
	if e := s.SetStatePath(path); e != nil {
		t.Fatal(e)
	}
	const principal = "windows:S-1-5-21-100-200-300-1001"
	c := Connection{IdPID: "corp", TenantID: "tenant", Issuer: "https://idp.example", AuthorizationEndpoint: "https://idp.example/auth", ClientID: "client", DeviceUserBindings: []DeviceUserBinding{{DeviceID: "device", OSPrincipal: principal, Subject: "alice"}}}
	put := func(c Connection) Connection {
		t.Helper()
		got, e := s.Upsert(c)
		if e != nil {
			t.Fatal(e)
		}
		return got
	}
	first := put(c)
	binding, ok := first.AssignedBinding("device", principal)
	if !ok || !ValidOSSession(binding.Revision) {
		t.Fatal("no durable assignment revision")
	}
	first.DeviceUserBindings[0].Subject = "mutated caller"
	got, _ := s.Get("tenant", "corp")
	if sub, _ := got.AssignedSubject("device", principal); sub != "alice" {
		t.Fatal("caller mutated registry")
	}
	// Label-only edits from the existing UI omit the optional array.
	c.DeviceUserBindings = nil
	c.DisplayName = "Edited"
	got = put(c)
	if b, _ := got.AssignedBinding("device", principal); b.Revision != binding.Revision {
		t.Fatal("ordinary edit replaced assignment")
	}
	// Neither echoing nor choosing a revision can restore an earlier assignment.
	c = got
	c.DeviceUserBindings[0].Subject = "bob"
	other := put(c)
	if other.DeviceUserBindings[0].Revision == binding.Revision {
		t.Fatal("reassignment kept revision")
	}
	c.DeviceUserBindings[0] = binding
	restored := put(c)
	if restored.DeviceUserBindings[0].Revision == binding.Revision {
		t.Fatal("restoring prior user revived old evidence")
	}
	c.DeviceUserBindings = []DeviceUserBinding{}
	if rows := put(c).DeviceUserBindings; len(rows) != 0 {
		t.Fatal("explicit removal ignored")
	}
	c.DeviceUserBindings = []DeviceUserBinding{binding}
	recreated := put(c)
	if recreated.DeviceUserBindings[0].Revision == binding.Revision {
		t.Fatal("recreated old revision")
	}
	reload := NewStore()
	if e := reload.SetStatePath(path); e != nil {
		t.Fatal(e)
	}
	persisted, _ := reload.Get("tenant", "corp")
	if b, ok := persisted.AssignedBinding("device", principal); !ok || b.Revision != recreated.DeviceUserBindings[0].Revision {
		t.Fatal("revision did not survive restart")
	}
	if _, ok := persisted.AssignedSubject("other", principal); ok {
		t.Fatal("wrong device matched")
	}
	if _, ok := reload.Get("other", "corp"); ok {
		t.Fatal("assignment crossed tenant")
	}
}
func TestDeviceUserAssignmentRejectsAmbiguity(t *testing.T) {
	good := DeviceUserBinding{DeviceID: "device", OSPrincipal: "windows:S-1-5-21-100-200-300-1001", Subject: "subject"}
	for _, rows := range [][]DeviceUserBinding{{good, good}, {{DeviceID: "device", OSPrincipal: "alice@example.com", Subject: "subject"}}, {{DeviceID: "device", OSPrincipal: good.OSPrincipal, Subject: "subject", Revision: "bad"}}} {
		if validateDeviceUserBindings(rows) == nil {
			t.Fatal("invalid/ambiguous assignment accepted")
		}
	}
	for _, v := range []string{"windows:S-1--100", "windows:S-1-5-01", "windows:S-1-5-4294967296", "macos:not-a-uuid", "user", ""} {
		if ValidOSPrincipal(v) {
			t.Fatalf("invalid principal %q", v)
		}
	}
	if !ValidOSPrincipal("macos:11111111-2222-3333-4444-555555555555") {
		t.Fatal("UUID rejected")
	}
}
