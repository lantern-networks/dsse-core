package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

func TestBuildServerInitiatedExport(t *testing.T) {
	now := time.Now()
	fut := now.Add(24 * time.Hour).UTC().Format(time.RFC3339)
	past := now.Add(-time.Hour).UTC().Format(time.RFC3339)
	exs := []model.LegacyException{
		{ID: "a", BusinessOwner: "o", ExpiresAt: fut, SourceServer: "patchsrv", DeviceGroup: "ws", ServiceFamily: "smb", Port: 445, Mode: "allow", Status: "active"},
		{ID: "b", BusinessOwner: "o", ExpiresAt: past, SourceServer: "old", Mode: "allow", Status: "active"}, // expired -> skip
		{ID: "c", BusinessOwner: "o", ExpiresAt: fut, SourceServer: "rmm", Mode: "warn", Status: "disabled"}, // disabled -> skip
		{ID: "d", BusinessOwner: "o", ExpiresAt: fut, SourceServer: "mon", ServiceFamily: "ssh", Mode: "deny", Status: "active"},
	}
	exp, err := buildServerInitiatedExport(exs, now)
	if err != nil {
		t.Fatal(err)
	}
	if exp.DefaultAction != "deny" {
		t.Fatalf("default action should be deny")
	}
	if exp.RuleCount != 2 {
		t.Fatalf("rule count = %d, want 2 (expired+disabled skipped)", exp.RuleCount)
	}
	if exp.Rules[0].ExceptionID != "a" || exp.Rules[0].Action != "allow" {
		t.Fatalf("rule a wrong: %+v", exp.Rules[0])
	}
	if exp.Rules[1].ExceptionID != "d" || exp.Rules[1].Action != "deny" {
		t.Fatalf("rule d should map deny: %+v", exp.Rules[1])
	}
}

func TestExplicitTCPExportKeepsPortRestriction(t *testing.T) {
	now := time.Now()
	exp, err := buildServerInitiatedExport([]model.LegacyException{{ID: "tcp-selected", Protocol: "tcp", Port: 2222, Mode: "allow", Status: "active", ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(exp.Rules) != 1 || exp.Rules[0].ServiceFamily != "tcp" || exp.Rules[0].Port != 2222 {
		t.Fatalf("TCP port restriction lost: %+v", exp)
	}
}
