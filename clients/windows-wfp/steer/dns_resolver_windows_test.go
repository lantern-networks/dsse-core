//go:build windows

package main

import (
	"encoding/json"
	"testing"
)

func TestFamilyParams(t *testing.T) {
	if fam, pfx := familyParams("127.0.0.1"); fam != "IPv4" || pfx != "0.0.0.0/0" {
		t.Errorf("familyParams(127.0.0.1) = %q,%q", fam, pfx)
	}
	if fam, pfx := familyParams("::1"); fam != "IPv6" || pfx != "::/0" {
		t.Errorf("familyParams(::1) = %q,%q", fam, pfx)
	}
}

func TestResolverSnapshotRoundTrip(t *testing.T) {
	in := resolverSnapshot{Entries: []resolverEntry{
		{IfIndex: "29", Family: "IPv4", Loopback: "127.0.0.1", Servers: "192.0.2.1"},
		{IfIndex: "29", Family: "IPv6", Loopback: "::1", Servers: "240d:1a::1"},
		{IfIndex: "12", Family: "IPv4", Loopback: "127.0.0.1", Servers: "8.8.8.8,8.8.4.4"},
	}}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out resolverSnapshot
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Entries) != 3 || out.Entries[1].Loopback != "::1" || out.Entries[2].Servers != "8.8.8.8,8.8.4.4" {
		t.Errorf("round-trip mismatch: %+v", out)
	}
}
