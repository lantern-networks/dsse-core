package main

import (
	"slices"
	"testing"
)

func TestNetworkPlanIncludesArchiveEgressOnlyWhenConfigured(t *testing.T) {
	p := threeNodesOneRegionPlan()
	for _, rule := range planNetworkRequirements(p) {
		if rule.Destination == "external S3 archive" {
			t.Fatal("local-only plan unexpectedly needs S3 egress")
		}
	}
	p.Archive = &PlanArchive{Endpoint: "objects.example.test:443", Bucket: "audit", AuthMode: "static", WebhookURL: "https://alerts.example.test/dsse"}
	count := 0
	alertCount := 0
	for _, rule := range planNetworkRequirements(p) {
		if rule.Destination == "archive alert receiver" {
			alertCount++
			if rule.Address != "alerts.example.test" || !slices.Equal(rule.TCPPorts, []int{443}) || len(rule.Sources) != 3 {
				t.Fatalf("wrong alert egress requirement: %+v", rule)
			}
		}
		if rule.Destination != "external S3 archive" {
			continue
		}
		count++
		if rule.Address != "objects.example.test" || !slices.Equal(rule.TCPPorts, []int{443}) || len(rule.Sources) != 3 {
			t.Fatalf("wrong CP archive egress requirement: %+v", rule)
		}
	}
	if count != 1 {
		t.Fatalf("archive egress rules=%d, want one", count)
	}
	if alertCount != 1 {
		t.Fatalf("alert egress rules=%d, want one", alertCount)
	}
}
