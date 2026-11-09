package main

import (
	"errors"
	appcatalog "github.com/lantern-networks/dsse-core/appcatalog"
	policy "github.com/lantern-networks/dsse-core/policy"
	policyrule "github.com/lantern-networks/dsse-core/policyrule"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/model"
)

// TestTheControlPlaneKeepsWhatTheEdgeReportsAboutAConnector reproduces the third walk's connector detail:
// "Tunnel unknown, Version unknown, Uptime unknown" for a connector carrying traffic, because the control plane
// took only the heartbeat time and status from the Edge's reports.
func TestTheControlPlaneKeepsWhatTheEdgeReportsAboutAConnector(t *testing.T) {
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "conn-h1", TenantID: "t1", Status: "registered",
		EdgeRegionID: "region-a", EdgeClusterID: "local-edge-001", PrivateBaseURL: "https://internal.invalid"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	server := connectorReportServer(t, registry)
	beat := time.Now().UTC().Format(time.RFC3339)
	report := model.ConnectorRegistration{ID: "conn-h1", TenantID: "t1", Status: "healthy", LastHeartbeatAt: beat, PrivateBaseURL: "https://internal.invalid",
		Metadata: map[string]any{"version": "0.4.1+source-7bcf53da", "uptime_seconds": 2520}}

	// A node that received a heartbeat but does not hold the tunnel: version and uptime, not the tunnel.
	if code := postConnectorReport(t, server, map[string]any{"registration": report, "tenant_id": "t1", "liveness_only": true}); code != http.StatusNoContent {
		t.Fatalf("liveness report status %d", code)
	}
	got, _ := registry.Get("conn-h1")
	dto := adminConnectorFromModel(got)
	applyConnectorTunnelStatus(&dto, nil)
	if dto.Version != "0.4.1+source-7bcf53da" || dto.UptimeSeconds == nil || *dto.UptimeSeconds != 2520 {
		t.Fatalf("after a heartbeat report the detail reads version=%q uptime=%v", dto.Version, dto.UptimeSeconds)
	}
	if dto.TunnelConnected != nil || dto.TunnelRegion != "" {
		t.Fatalf("a node without the tunnel was taken as saying where it is: connected=%v region=%q", dto.TunnelConnected, dto.TunnelRegion)
	}

	// The node holding the tunnel: now the control plane can say it is connected, and where.
	if code := postConnectorReport(t, server, map[string]any{"registration": report, "tenant_id": "t1", "attached_region_id": "region-a"}); code != http.StatusNoContent {
		t.Fatalf("attachment report status %d", code)
	}
	got, _ = registry.Get("conn-h1")
	dto = adminConnectorFromModel(got)
	applyConnectorTunnelStatus(&dto, nil)
	if dto.TunnelConnected == nil || !*dto.TunnelConnected || dto.TunnelRegion != "region-a" || dto.TunnelReportedAt == "" {
		t.Fatalf("after the tunnel holder's report the detail reads connected=%v region=%q at=%q", dto.TunnelConnected, dto.TunnelRegion, dto.TunnelReportedAt)
	}
	if !dto.Online {
		t.Fatal("a connector whose tunnel was reported a moment ago reads offline")
	}

	// An old report is not evidence: unknown, and the heartbeat decides.
	got.Metadata["tunnel_reported_at"] = time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339)
	dto = adminConnectorFromModel(got)
	applyConnectorTunnelStatus(&dto, nil)
	if dto.TunnelConnected != nil {
		t.Fatalf("a ten-minute-old tunnel report still reads connected=%v", *dto.TunnelConnected)
	}

	// A node that HAS tunnels answers for itself; another node's report does not overrule it.
	no := false
	got.Metadata["tunnel_reported_at"] = time.Now().UTC().Format(time.RFC3339)
	dto = adminConnectorFromModel(got)
	applyConnectorTunnelStatus(&dto, func(string) *bool { return &no })
	if dto.TunnelConnected == nil || *dto.TunnelConnected {
		t.Fatal("an Edge that does not hold the tunnel was overruled by another node's report")
	}
	if adminConnectorMetadataKeyCount(got.Metadata) != 0 {
		t.Fatalf("runtime keys were counted as custom metadata: %d", adminConnectorMetadataKeyCount(got.Metadata))
	}
}

// TestRecordingAConnectorsRuntimeDoesNotMoveTheCatalog: uptime changes on every report; the catalog version
// must not, or every Edge would re-pull the bundle every half minute per connector.
func TestRecordingAConnectorsRuntimeDoesNotMoveTheCatalog(t *testing.T) {
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "conn-1", TenantID: "t1", Status: "registered", PrivateBaseURL: "https://internal.invalid"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	before := registry.ConfigGeneration()
	for i := 1; i <= 3; i++ {
		if _, err := registry.RecordRuntime("t1", "conn-1", map[string]any{"uptime_seconds": int64(i * 30), "tunnel_region": "region-a",
			"runtime_secret_hash": "sha256:" + "00", "name": "renamed"}); err != nil {
			t.Fatal(err)
		}
	}
	if after := registry.ConfigGeneration(); after != before {
		t.Fatalf("recording uptime moved the catalog version %d -> %d", before, after)
	}
	got, _ := registry.Get("conn-1")
	if _, leaked := got.Metadata["runtime_secret_hash"]; leaked || got.Metadata["name"] != nil {
		t.Fatalf("a key outside the runtime set was written: %v", got.Metadata)
	}
}

// TestAnOldReportNeitherFreshensNorRollsBack — review C3-R5: a report replayed from an Edge's outbox an hour
// late read as a tunnel seen just now, and an old report written after a newer one put back the old entrance,
// version and uptime.
func TestAnOldReportNeitherFreshensNorRollsBack(t *testing.T) {
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "conn-h1", TenantID: "t1", Status: "registered",
		PrivateBaseURL: "https://internal.invalid"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	server := connectorReportServer(t, registry)
	hourAgo := time.Now().Add(-time.Hour).UTC()
	old := model.ConnectorRegistration{ID: "conn-h1", TenantID: "t1", Status: "healthy", PrivateBaseURL: "https://internal.invalid",
		LastHeartbeatAt: hourAgo.Format(time.RFC3339), Metadata: map[string]any{"version": "0.4.0", "uptime_seconds": 60}}
	if code := postConnectorReport(t, server, map[string]any{"registration": old, "tenant_id": "t1",
		"attached_region_id": "region-a", "queued_at": hourAgo.Format(time.RFC3339)}); code != http.StatusNoContent {
		t.Fatalf("status %d", code)
	}
	got, _ := registry.Get("conn-h1")
	dto := adminConnectorFromModel(got)
	applyConnectorTunnelStatus(&dto, nil)
	if dto.TunnelConnected != nil {
		t.Fatalf("an hour-old report replayed now reads as a connected tunnel: %v", *dto.TunnelConnected)
	}

	now := time.Now().UTC()
	fresh := old
	fresh.LastHeartbeatAt = now.Format(time.RFC3339)
	fresh.Metadata = map[string]any{"version": "0.4.1", "uptime_seconds": 3600}
	if code := postConnectorReport(t, server, map[string]any{"registration": fresh, "tenant_id": "t1",
		"attached_region_id": "region-b", "queued_at": now.Format(time.RFC3339)}); code != http.StatusNoContent {
		t.Fatalf("status %d", code)
	}
	// The old one again, late.
	if code := postConnectorReport(t, server, map[string]any{"registration": old, "tenant_id": "t1",
		"attached_region_id": "region-a", "queued_at": hourAgo.Format(time.RFC3339)}); code != http.StatusNoContent {
		t.Fatalf("status %d", code)
	}
	got, _ = registry.Get("conn-h1")
	dto = adminConnectorFromModel(got)
	applyConnectorTunnelStatus(&dto, nil)
	if dto.Version != "0.4.1" || dto.TunnelRegion != "region-b" || dto.UptimeSeconds == nil || *dto.UptimeSeconds != 3600 {
		t.Fatalf("an old report rolled the detail back: version=%q region=%q uptime=%v", dto.Version, dto.TunnelRegion, dto.UptimeSeconds)
	}
	if dto.TunnelConnected == nil || !*dto.TunnelConnected {
		t.Fatal("the fresh report's tunnel reads unknown")
	}
}

// TestRecordingRuntimeDoesNotWriteIntoAMapAReaderHolds — review C3-R6, run under -race in CI.
func TestRecordingRuntimeDoesNotWriteIntoAMapAReaderHolds(t *testing.T) {
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "c", TenantID: "t1", Status: "registered",
		PrivateBaseURL: "https://internal.invalid", Metadata: map[string]any{"k": "v"}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	held, _ := registry.Get("c")
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			_, _ = registry.RecordRuntime("t1", "c", map[string]any{"uptime_seconds": int64(i + 1)})
			_, _ = registry.Heartbeat(model.ConnectorHeartbeat{ID: "c", TenantID: "t1", UptimeSeconds: int64(i + 1)}, time.Now())
		}
	}()
	for i := 0; i < 200; i++ {
		for k := range held.Metadata {
			_ = held.Metadata[k]
		}
	}
	<-done
	if _, ok := held.Metadata["uptime_seconds"]; ok {
		t.Fatal("a registration handed to a reader was changed after it was handed out")
	}
}

// TestARegistrationReplayDoesNotRollBackRuntime — review C3-RR2: a plain registration report, replayed from an
// outbox after a newer attachment report, replaced the stored registration and put back the old version and
// uptime, erasing where the tunnel is.
func TestARegistrationReplayDoesNotRollBackRuntime(t *testing.T) {
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "conn-h1", TenantID: "t1", Status: "registered",
		PrivateBaseURL: "https://internal.invalid"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	server := connectorReportServer(t, registry)
	now := time.Now().UTC()
	hourAgo := now.Add(-time.Hour)
	fresh := model.ConnectorRegistration{ID: "conn-h1", TenantID: "t1", Status: "healthy", PrivateBaseURL: "https://internal.invalid",
		LastHeartbeatAt: now.Format(time.RFC3339), Metadata: map[string]any{"version": "0.4.1", "uptime_seconds": 120}}
	if code := postConnectorReport(t, server, map[string]any{"registration": fresh, "tenant_id": "t1",
		"attached_region_id": "region-b", "queued_at": now.Format(time.RFC3339)}); code != http.StatusNoContent {
		t.Fatalf("status %d", code)
	}
	old := fresh
	old.LastHeartbeatAt = hourAgo.Format(time.RFC3339)
	old.Metadata = map[string]any{"version": "0.4.0", "uptime_seconds": 86400}
	if code := postConnectorReport(t, server, map[string]any{"registration": old, "tenant_id": "t1",
		"queued_at": hourAgo.Format(time.RFC3339)}); code != http.StatusNoContent {
		t.Fatalf("status %d", code)
	}
	got, _ := registry.Get("conn-h1")
	dto := adminConnectorFromModel(got)
	if dto.Version != "0.4.1" || dto.UptimeSeconds == nil || *dto.UptimeSeconds != 120 || dto.TunnelRegion != "region-b" ||
		adminConnectorMetadataString(got.Metadata, connector.RuntimeObservedAtKey) == "" {
		t.Fatalf("a replayed registration rolled the runtime back: version=%q uptime=%v region=%q meta=%v",
			dto.Version, dto.UptimeSeconds, dto.TunnelRegion, got.Metadata)
	}
	// A newer plain registration does bring its facts in.
	newer := fresh
	newer.Metadata = map[string]any{"version": "0.4.2", "uptime_seconds": 5}
	later := now.Add(time.Minute)
	if later.After(time.Now()) {
		later = time.Now().UTC()
	}
	if code := postConnectorReport(t, server, map[string]any{"registration": newer, "tenant_id": "t1",
		"queued_at": later.Format(time.RFC3339Nano)}); code != http.StatusNoContent {
		t.Fatalf("status %d", code)
	}
	got, _ = registry.Get("conn-h1")
	if v := adminConnectorVersion(got.Metadata); v != "0.4.2" {
		t.Fatalf("a newer registration's version was not taken: %q", v)
	}
	if adminConnectorMetadataString(got.Metadata, "tunnel_region") != "region-b" {
		t.Fatal("a registration report without a tunnel erased where the tunnel is")
	}
}

// TestARegistrationKeepsAFactRecordedJustBeforeIt — review C3-RRR2: the held facts were read before Register and
// written back by it, so a newer fact recorded in between was lost along with the observation time that would
// have protected it. The store keeps them now, inside the lock that writes.
func TestARegistrationKeepsAFactRecordedJustBeforeIt(t *testing.T) {
	registry := connector.NewRegistry()
	if _, err := registry.Register(model.ConnectorRegistration{ID: "conn-h1", TenantID: "t1", Status: "registered",
		PrivateBaseURL: "https://internal.invalid"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	t1 := time.Now().Add(-time.Minute).UTC()
	if _, err := registry.RecordRuntime("t1", "conn-h1", map[string]any{"version": "0.4.1", "uptime_seconds": int64(120),
		"tunnel_region": "region-b", connector.RuntimeObservedAtKey: t1.Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	// The intervening report, recorded after a registration report was read off the wire and before it is written.
	t2 := time.Now().UTC()
	if _, err := registry.RecordRuntime("t1", "conn-h1", map[string]any{"version": "0.4.2", "uptime_seconds": int64(10),
		"tunnel_region": "region-c", connector.RuntimeObservedAtKey: t2.Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	old := model.ConnectorRegistration{ID: "conn-h1", TenantID: "t1", Status: "healthy", PrivateBaseURL: "https://internal.invalid",
		Metadata: map[string]any{"version": "0.4.0", "uptime_seconds": 86400, "tunnel_region": "region-b",
			connector.RuntimeObservedAtKey: t1.Format(time.RFC3339Nano)}}
	if _, err := registry.Register(old, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, _ := registry.Get("conn-h1")
	if v := adminConnectorVersion(got.Metadata); v != "0.4.2" || adminConnectorMetadataString(got.Metadata, "tunnel_region") != "region-c" ||
		adminConnectorMetadataString(got.Metadata, connector.RuntimeObservedAtKey) != t2.Format(time.RFC3339Nano) {
		t.Fatalf("the registration put back an older fact: %v", got.Metadata)
	}
}

// TestAnEdgeTakesNewerRuntimeFactsFromTheBundle — fourth review: once Register kept the held facts, an Edge
// applying the control plane's catalogue stopped taking newer version, uptime and tunnel facts from it. They are
// offered through the observation-time check, so newer ones are taken and older ones are not.
func TestAnEdgeTakesNewerRuntimeFactsFromTheBundle(t *testing.T) {
	edge := connector.NewRegistry()
	t1 := time.Now().Add(-time.Hour).UTC()
	base := model.ConnectorRegistration{ID: "conn-h1", TenantID: "tenant_lab_001", Status: "registered", PrivateBaseURL: "https://internal.invalid",
		Metadata: map[string]any{"version": "0.4.0", "tunnel_region": "region-a", connector.RuntimeObservedAtKey: t1.Format(time.RFC3339Nano)}}
	if _, err := edge.Register(base, time.Now()); err != nil {
		t.Fatal(err)
	}
	t2 := time.Now().UTC()
	newer := base
	newer.Metadata = map[string]any{"version": "0.4.1", "tunnel_region": "region-b", connector.RuntimeObservedAtKey: t2.Format(time.RFC3339Nano)}
	source := configBundleSource{tenantID: "tenant_lab_001"}
	apply := func(conn model.ConnectorRegistration) {
		t.Helper()
		payload := configBundlePayload{Connectors: &connectorCatalogBundle{Connectors: []model.ConnectorRegistration{conn}}}
		if _, err := source.apply(payload, configApplyTargets{policyStore: policy.NewStore(nil), rules: policyrule.NewStore(),
			applications: appcatalog.NewStore(), dlp: dlpStoresForTest("bundle-runtime"), connectors: edge}); err != nil {
			t.Fatal(err)
		}
	}
	apply(newer)
	got, _ := edge.Get("conn-h1")
	if adminConnectorVersion(got.Metadata) != "0.4.1" || adminConnectorMetadataString(got.Metadata, "tunnel_region") != "region-b" {
		t.Fatalf("the Edge did not take newer facts from the control plane: %v", got.Metadata)
	}
	apply(base) // an older catalogue copy
	got, _ = edge.Get("conn-h1")
	if adminConnectorVersion(got.Metadata) != "0.4.1" {
		t.Fatalf("an older catalogue copy rolled the Edge back: %v", got.Metadata)
	}
}

// TestADelayedCatalogueDoesNotOverwriteAFreshHeartbeat — review C3-R5-1, the chain as measured: the Edge holds a
// catalogue fact from T0, a heartbeat at T2 brings the running build, a catalogue copy from T1 (T0 < T1 < T2)
// arrives late, and the next tunnel report must carry the heartbeat's build to the control plane.
func TestADelayedCatalogueDoesNotOverwriteAFreshHeartbeat(t *testing.T) {
	now := time.Now().UTC()
	t0, t1, t2 := now.Add(-3*time.Minute), now.Add(-2*time.Minute), now.Add(-time.Minute)
	edge := connector.NewRegistry()
	base := model.ConnectorRegistration{ID: "conn-h1", TenantID: "tenant_lab_001", Status: "registered", PrivateBaseURL: "https://internal.invalid",
		Metadata: map[string]any{"version": "0.3.9", "uptime_seconds": 10, connector.RuntimeObservedAtKey: t0.Format(time.RFC3339Nano)}}
	if _, err := edge.Register(base, now); err != nil {
		t.Fatal(err)
	}
	if _, err := edge.Heartbeat(model.ConnectorHeartbeat{ID: "conn-h1", TenantID: "tenant_lab_001", Version: "0.4.1+887c76fb2",
		UptimeSeconds: 42, Timestamp: t2.Format(time.RFC3339)}, now); err != nil {
		t.Fatal(err)
	}
	late := base
	late.EdgeRegionID = "region-b" // an ordinary catalogue change rides along
	late.Metadata = map[string]any{"version": "0.4.0", "uptime_seconds": 86400, connector.RuntimeObservedAtKey: t1.Format(time.RFC3339Nano)}
	source := configBundleSource{tenantID: "tenant_lab_001"}
	if _, err := source.apply(configBundlePayload{Connectors: &connectorCatalogBundle{Connectors: []model.ConnectorRegistration{late}}},
		configApplyTargets{policyStore: policy.NewStore(nil), rules: policyrule.NewStore(), applications: appcatalog.NewStore(),
			dlp: dlpStoresForTest("delayed-catalogue"), connectors: edge}); err != nil {
		t.Fatal(err)
	}
	held, _ := edge.Get("conn-h1")
	if v := adminConnectorVersion(held.Metadata); v != "0.4.1+887c76fb2" {
		t.Fatalf("a catalogue copy older than the heartbeat replaced the running build on the Edge: %q", v)
	}

	// The control plane, which the Console reads, given the Edge's next tunnel report (made now).
	cp := connector.NewRegistry()
	if _, err := cp.Register(model.ConnectorRegistration{ID: "conn-h1", TenantID: "t1", Status: "registered", PrivateBaseURL: "https://internal.invalid"}, now); err != nil {
		t.Fatal(err)
	}
	server := connectorReportServer(t, cp)
	report := held
	report.TenantID = "t1"
	if code := postConnectorReport(t, server, map[string]any{"registration": report, "tenant_id": "t1",
		"attached_region_id": "region-b", "queued_at": now.Format(time.RFC3339)}); code != http.StatusNoContent {
		t.Fatalf("status %d", code)
	}
	got, _ := cp.Get("conn-h1")
	dto := adminConnectorFromModel(got)
	if dto.Version != "0.4.1+887c76fb2" || dto.UptimeSeconds == nil || *dto.UptimeSeconds != 42 {
		t.Fatalf("the Console reads version=%q uptime=%v; want the heartbeat's build", dto.Version, dto.UptimeSeconds)
	}
}

// TestATunnelReportIsNotRefusedForAnOlderVersion — the two groups are judged apart: an Edge that holds the tunnel
// and has not heard a heartbeat for a while still says where the tunnel is, and its older process facts do not
// replace the newer ones another Edge reported.
func TestATunnelReportIsNotRefusedForAnOlderVersion(t *testing.T) {
	now := time.Now().UTC()
	cp := connector.NewRegistry()
	if _, err := cp.Register(model.ConnectorRegistration{ID: "c", TenantID: "t1", Status: "registered", PrivateBaseURL: "https://internal.invalid"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := cp.RecordRuntime("t1", "c", map[string]any{"version": "0.4.2", connector.RuntimeObservedAtKey: now.Add(-10 * time.Second).Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	server := connectorReportServer(t, cp)
	holder := model.ConnectorRegistration{ID: "c", TenantID: "t1", Status: "healthy", PrivateBaseURL: "https://internal.invalid",
		Metadata: map[string]any{"version": "0.4.1", connector.RuntimeObservedAtKey: now.Add(-time.Hour).Format(time.RFC3339Nano)}}
	if code := postConnectorReport(t, server, map[string]any{"registration": holder, "tenant_id": "t1",
		"attached_region_id": "region-c", "queued_at": now.Format(time.RFC3339)}); code != http.StatusNoContent {
		t.Fatalf("status %d", code)
	}
	got, _ := cp.Get("c")
	dto := adminConnectorFromModel(got)
	applyConnectorTunnelStatus(&dto, nil)
	if dto.Version != "0.4.2" {
		t.Fatalf("an hour-old version from the tunnel holder replaced a newer one: %q", dto.Version)
	}
	if dto.TunnelRegion != "region-c" || dto.TunnelConnected == nil || !*dto.TunnelConnected {
		t.Fatalf("the tunnel report was refused along with the old version: region=%q connected=%v", dto.TunnelRegion, dto.TunnelConnected)
	}
}

// TestAPollAtTheSameGenerationCarriesNewerRuntimeFacts — fifth review, observation: a poll whose generation had
// not moved updated only where the connector is attached, so the Edge's version and uptime fell behind.
func TestAPollAtTheSameGenerationCarriesNewerRuntimeFacts(t *testing.T) {
	now := time.Now().UTC()
	edge := connector.NewRegistry()
	if _, err := edge.Register(model.ConnectorRegistration{ID: "c", TenantID: "t1", Status: "registered", PrivateBaseURL: "https://internal.invalid",
		Metadata: map[string]any{"version": "0.4.0", connector.RuntimeObservedAtKey: now.Add(-time.Hour).Format(time.RFC3339Nano)}}, now); err != nil {
		t.Fatal(err)
	}
	fresh := model.ConnectorRegistration{ID: "c", TenantID: "t1", AttachedRegionID: "region-a",
		Metadata: map[string]any{"version": "0.4.1", connector.RuntimeObservedAtKey: now.Format(time.RFC3339Nano)}}
	applyConnectorRuntimeFacts(configBundlePayload{Connectors: &connectorCatalogBundle{Connectors: []model.ConnectorRegistration{fresh}}},
		configApplyTargets{connectors: edge})
	got, _ := edge.Get("c")
	if v := adminConnectorVersion(got.Metadata); v != "0.4.1" {
		t.Fatalf("a same-generation poll left the Edge at %q", v)
	}
	stale := fresh
	stale.Metadata = map[string]any{"version": "0.3.0", connector.RuntimeObservedAtKey: now.Add(-2 * time.Hour).Format(time.RFC3339Nano)}
	applyConnectorRuntimeFacts(configBundlePayload{Connectors: &connectorCatalogBundle{Connectors: []model.ConnectorRegistration{stale}}},
		configApplyTargets{connectors: edge})
	got, _ = edge.Get("c")
	if v := adminConnectorVersion(got.Metadata); v != "0.4.1" {
		t.Fatalf("a stale same-generation poll rolled the Edge back to %q", v)
	}
}

// TestAPollDoesNotWriteAnotherOrganizationsRuntimeIntoThisOnes — review C3-R6-1: the Edge holds the ID for
// organization A, the control plane for B; the full catalogue apply refused B's registration, and the
// same-generation poll then wrote B's version, uptime and tunnel into A's row by ID alone.
func TestAPollDoesNotWriteAnotherOrganizationsRuntimeIntoThisOnes(t *testing.T) {
	now := time.Now().UTC()
	edge := connector.NewRegistry()
	mine := model.ConnectorRegistration{ID: "shared-id", TenantID: "tenant_lab_001", Status: "registered", PrivateBaseURL: "https://a.internal.invalid",
		Metadata: map[string]any{"version": "own-build", "tunnel_region": "own-region",
			connector.RuntimeObservedAtKey: now.Add(-time.Minute).Format(time.RFC3339Nano), "tunnel_reported_at": now.Add(-time.Minute).Format(time.RFC3339Nano)}}
	if _, err := edge.Register(mine, now); err != nil {
		t.Fatal(err)
	}
	foreign := model.ConnectorRegistration{ID: "shared-id", TenantID: "tenant_other", Status: "healthy", PrivateBaseURL: "https://b.internal.invalid",
		AttachedRegionID: "foreign-region",
		Metadata: map[string]any{"version": "other-tenant-build", "uptime_seconds": 987, "tunnel_region": "foreign-region",
			connector.RuntimeObservedAtKey: now.Format(time.RFC3339Nano), "tunnel_reported_at": now.Format(time.RFC3339Nano)}}
	payload := configBundlePayload{Connectors: &connectorCatalogBundle{Connectors: []model.ConnectorRegistration{foreign}}}
	source := configBundleSource{tenantID: "tenant_lab_001"}
	_, _ = source.apply(payload, configApplyTargets{policyStore: policy.NewStore(nil), rules: policyrule.NewStore(),
		applications: appcatalog.NewStore(), dlp: dlpStoresForTest("foreign-runtime"), connectors: edge})
	applyConnectorRuntimeFacts(payload, configApplyTargets{connectors: edge})
	got, _ := edge.Get("shared-id")
	if got.TenantID != "tenant_lab_001" || adminConnectorVersion(got.Metadata) != "own-build" ||
		adminConnectorMetadataString(got.Metadata, "tunnel_region") != "own-region" || got.AttachedRegionID == "foreign-region" {
		t.Fatalf("another organization's facts were written into this organization's registration: %+v", got)
	}
	// And the recorders themselves refuse a caller naming the wrong, or no, organization.
	for _, tenant := range []string{"tenant_other", ""} {
		if _, err := edge.RecordRuntime(tenant, "shared-id", map[string]any{"version": "x", connector.RuntimeObservedAtKey: now.Add(time.Second).Format(time.RFC3339Nano)}); !errors.Is(err, connector.ErrNotThisTenantsConnector) {
			t.Fatalf("RecordRuntime for tenant %q: %v", tenant, err)
		}
		if _, err := edge.RecordAttachedRegion(tenant, "shared-id", "elsewhere"); !errors.Is(err, connector.ErrNotThisTenantsConnector) {
			t.Fatalf("RecordAttachedRegion for tenant %q: %v", tenant, err)
		}
	}
}

// TestThePostgresAttachmentUpdateCannotRecreateARow — seventh review: the update read the row, then wrote it
// back through Register (an upsert) in a second transaction, so a removal in between was undone. An UPDATE
// cannot insert; this holds the function to that shape.
func TestThePostgresAttachmentUpdateCannotRecreateARow(t *testing.T) {
	b, err := os.ReadFile("connector_registry_postgres.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	start := strings.Index(src, "func (store postgresConnectorRegistryStore) RecordAttachedRegion(")
	if start < 0 {
		t.Fatal("RecordAttachedRegion not found")
	}
	body := src[start:]
	if end := strings.Index(body, "\n}\n"); end > 0 {
		body = body[:end]
	}
	for _, forbidden := range []string{"store.Register(", "INSERT INTO"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("RecordAttachedRegion contains %q: a late attachment could re-create a removed connector", forbidden)
		}
	}
	for _, required := range []string{"queryPostgresConnectorRegistryByID(ctx, tx, id, true)", "UPDATE connector_registrations SET payload"} {
		if !strings.Contains(body, required) {
			t.Errorf("RecordAttachedRegion no longer contains %q (lock the row, update only what exists)", required)
		}
	}
}
