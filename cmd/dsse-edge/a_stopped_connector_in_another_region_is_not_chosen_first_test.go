package main

import (
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/model"
)

// Two connectors front an application from another Region and one of them has stopped. The link to that Region
// is up for both, so the link alone chose whichever the list gave first.
func TestAStoppedConnectorInAnotherRegionIsNotChosenFirst(t *testing.T) {
	now := time.Date(2026, 11, 14, 3, 0, 0, 0, time.UTC)
	stopped := model.ConnectorRegistration{ID: "conn-stopped", LastHeartbeatAt: now.Add(-10 * time.Minute).Format(time.RFC3339)}
	running := model.ConnectorRegistration{ID: "conn-running", LastHeartbeatAt: now.Add(-20 * time.Second).Format(time.RFC3339)}
	silent := model.ConnectorRegistration{ID: "conn-never-reported"}

	prefer := func(c model.ConnectorRegistration) bool { return connectorWorthPreferring(c, false, now) }
	got, ok := firstReachableConnector([]model.ConnectorRegistration{stopped, silent, running}, prefer)
	if !ok || got.ID != "conn-running" {
		t.Fatalf("chose %q, want the connector whose heartbeat is fresh", got.ID)
	}
	// A tunnel held here needs no heartbeat to be believed.
	if !connectorWorthPreferring(stopped, true, now) {
		t.Fatal("a connector whose tunnel this node holds was not preferred")
	}
	// When none is alive the first is still named, so the screen reports that connector's state.
	got, ok = firstReachableConnector([]model.ConnectorRegistration{stopped, silent}, prefer)
	if !ok || got.ID != "conn-stopped" {
		t.Fatalf("with nothing alive chose %q ok=%t, want the first registration", got.ID, ok)
	}
}

// Walked on three Regions (2026-11-14): on the node answering for another Region, both connectors' heartbeats
// were six minutes old, so the heartbeat could not tell them apart. What could was the report of the Edge
// holding the live one's tunnel — the fact the connector list already reads.
func TestAConnectorAnotherEdgeReportsHoldingIsPreferredWhenHeartbeatsAreStale(t *testing.T) {
	// The connector list reads the clock itself, so this test is anchored to it rather than to a fixed date.
	now := time.Now().UTC()
	stale := now.Add(-6 * time.Minute).Format(time.RFC3339)
	stopped := model.ConnectorRegistration{ID: "conn-stopped", LastHeartbeatAt: stale,
		Metadata: map[string]any{"tunnel_reported_at": now.Add(-3 * time.Minute).Format(time.RFC3339)}}
	live := model.ConnectorRegistration{ID: "conn-live", LastHeartbeatAt: stale,
		Metadata: map[string]any{"tunnel_reported_at": now.Add(-20 * time.Second).Format(time.RFC3339)}}
	prefer := func(c model.ConnectorRegistration) bool { return connectorWorthPreferring(c, false, now) }
	for _, order := range [][]model.ConnectorRegistration{{stopped, live}, {live, stopped}} {
		got, ok := firstReachableConnector(order, prefer)
		if !ok || got.ID != "conn-live" {
			t.Fatalf("with %s listed first, chose %q", order[0].ID, got.ID)
		}
	}
	// It agrees with the connector list's own answer for both.
	for _, c := range []model.ConnectorRegistration{stopped, live} {
		dto := adminConnectorFromModel(c)
		applyConnectorTunnelStatus(&dto, nil)
		if adminConnectorOnline(dto, now) != prefer(c) {
			t.Errorf("%s: the list says online=%t, the reachability test prefers=%t", c.ID, adminConnectorOnline(dto, now), prefer(c))
		}
	}
}
