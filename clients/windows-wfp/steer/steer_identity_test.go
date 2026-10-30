package main

import (
	"net/url"
	"strings"
	"testing"
)

func TestStepUpOwnerLoginIncarnationAndLaunchBinding(t *testing.T) {
	owner := stepUpOwner{PID: 123, Created: 1, Session: 4, SID: "S-1-5-21-100-200-300-1001", LogonID: 101}
	if owner.authPrincipal() != "windows:"+owner.SID || len(owner.authSession()) != 64 {
		t.Fatal("owner absent")
	}
	child := owner
	child.PID++
	child.Created++
	if child.authSession() != owner.authSession() {
		t.Fatal("same login cannot share evidence")
	}
	for _, other := range []stepUpOwner{{PID: 1, Session: 4, SID: owner.SID, LogonID: 102}, {PID: 1, Session: 5, SID: owner.SID, LogonID: 101}, {PID: 1, Session: 4, SID: "S-1-5-21-100-200-300-1002", LogonID: 101}} {
		if owner.authSession() == other.authSession() {
			t.Fatal("user/login/session isolation lost")
		}
	}
	query := url.Values{"os_principal": {owner.authPrincipal()}, "os_session": {owner.authSession()}}
	u := &url.URL{Scheme: "https", Host: "portal.example", RawQuery: query.Encode()}
	if !stepUpOwnerMatchesURL(owner, u) {
		t.Fatal("matching owner rejected")
	}
	query.Set("os_session", strings.Repeat("f", 64))
	u.RawQuery = query.Encode()
	if stepUpOwnerMatchesURL(owner, u) {
		t.Fatal("other session launched")
	}
	query.Del("os_session")
	u.RawQuery = query.Encode()
	if stepUpOwnerMatchesURL(owner, u) {
		t.Fatal("partial owner launched")
	}
	query = url.Values{}
	u.RawQuery = query.Encode()
	if !stepUpOwnerMatchesURL(owner, u) {
		t.Fatal("released portal rejected during mixed rollout")
	}
	if !strings.Contains(authorityWithAuthOwner("app:22", owner), "\x00op=windows:") {
		t.Fatal("owner not carried by authenticated mux")
	}
	if authorityWithAuthOwner("app:22", stepUpOwner{}) != "app:22" {
		t.Fatal("unknown/system owner invented")
	}
}
