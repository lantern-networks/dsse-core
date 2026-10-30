package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	devicestore "github.com/lantern-networks/dsse-core/device"
	"github.com/lantern-networks/dsse-core/model"
)

// This opt-in test uses a disposable PostgreSQL schema. It exercises the
// selected migrations and actual concurrent SQL writes, not SQL text alone.
func TestPostgresDeviceInventoryDomainParity(t *testing.T) {
	dsn := os.Getenv("DSSE_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("set DSSE_TEST_POSTGRES_DSN for the real PostgreSQL device inventory check")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme == "" {
		t.Skip("this isolated-schema check requires a PostgreSQL URL DSN")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	schema := fmt.Sprintf("device_review_%d_%d", os.Getpid(), time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE SCHEMA "` + schema + `"`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(`DROP SCHEMA "` + schema + `" CASCADE`); err != nil {
			t.Errorf("clean up disposable device schema: %v", err)
		}
	})
	query := u.Query()
	query.Set("search_path", schema)
	u.RawQuery = query.Encode()
	privateDSN := u.String()
	ctx := context.Background()
	opened, closeDevice, err := setupEdgeDeviceStore(ctx, edgeDeviceStoreConfig{
		Mode: "postgres", DSN: privateDSN, MigrationDir: "../../migrations", RunMigrations: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeDevice()
	pg := opened.(*postgresDeviceInventoryStore)
	telemetry, closeTelemetry, err := setupEdgeAgentTelemetryStore(ctx, edgeAgentTelemetryStoreConfig{
		Mode: "postgres", DSN: privateDSN, MigrationDir: "../../migrations", RunMigrations: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTelemetry()

	policy := devicestore.PosturePolicy{
		RequireDiskEncryption: true, RequireFirewall: true, RequireEnforcementAgentHealthy: true,
	}
	if err := pg.SetPosturePolicy(policy); err != nil {
		t.Fatal(err)
	}
	mem := devicestore.NewStore()
	if err := mem.SetPosturePolicy(policy); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 23, 0, 0, 0, 0, time.UTC)
	bundle := model.PolicyBundle{ID: "policy", Version: "1", TenantID: "tenant-a"}
	initial := model.Device{
		ID: "device-a", TenantID: "tenant-a", UserID: "user-a", Hostname: "host-a",
		OS: "macos", AgentVersion: "0.4.0", DeviceTrustLevel: "managed",
	}
	for label, store := range map[string]deviceRuntimeStore{"memory": mem, "postgres": pg} {
		registered, err := store.Register(initial, bundle, now)
		if err != nil || registered.DeviceTrustLevel != "unknown" {
			t.Fatalf("%s accepted self-declared registration trust: trust=%q err=%v", label, registered.DeviceTrustLevel, err)
		}
	}
	no, yes := false, true
	heartbeat := model.DeviceHeartbeat{
		ID: "device-a", TenantID: "tenant-a", DeviceTrustLevel: "managed",
		Posture:  &model.DevicePostureSignals{DiskEncryptionEnabled: &no, FirewallEnabled: &yes},
		Metadata: map[string]any{"admin_high_risk": false, "risk_state_severity": "none"},
	}
	for label, store := range map[string]deviceRuntimeStore{"memory": mem, "postgres": pg} {
		updated, err := store.Heartbeat(heartbeat, bundle, now.Add(time.Second))
		if err != nil || updated.DeviceTrustLevel != devicestore.PostureTrustNonCompliant || updated.Metadata["posture_compliant"] != false {
			t.Fatalf("%s did not derive noncompliant posture: trust=%q err=%v", label, updated.DeviceTrustLevel, err)
		}
	}
	// With the ordinary signals healthy, only the configured enforcement-agent
	// requirement can make this report noncompliant.
	heartbeat.Posture = &model.DevicePostureSignals{
		DiskEncryptionEnabled: &yes, FirewallEnabled: &yes, EnforcementAgentHealthy: &no,
	}
	for label, store := range map[string]deviceRuntimeStore{"memory": mem, "postgres": pg} {
		updated, err := store.Heartbeat(heartbeat, bundle, now.Add(time.Second))
		if err != nil || updated.DeviceTrustLevel != devicestore.PostureTrustNonCompliant || updated.Metadata["posture_compliant"] != false {
			t.Fatalf("%s ignored configured agent-health policy: trust=%q err=%v", label, updated.DeviceTrustLevel, err)
		}
	}
	if err := telemetry.RecordStatus(ctx, model.AgentStatus{
		DeviceID: "device-a", TenantID: "tenant-a", PolicyBundleID: bundle.ID,
		PolicyBundleVersion: bundle.Version, BundleSource: "remote",
		DeviceTrustLevel: devicestore.PostureTrustNonCompliant, Status: "healthy",
		Timestamp: now.Add(time.Second).Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("agent telemetry rejected derived noncompliant trust: %v", err)
	}

	signal := model.RiskSignal{EntityType: "device", EntityID: "device-a", Severity: "high", Source: "manual_high_risk"}
	for label, store := range map[string]riskSignalDeviceApplier{"memory": mem, "postgres": pg} {
		updated, found, high, err := store.ApplyRiskSignal("device-a", signal, now.Add(2*time.Second))
		if err != nil || !found || !high || updated.Metadata["risk_state_severity"] != "high" {
			t.Fatalf("%s failed authoritative risk fold: found=%t high=%t err=%v", label, found, high, err)
		}
	}
	for label, store := range map[string]deviceRuntimeStore{"memory": mem, "postgres": pg} {
		reported := initial
		reported.Metadata = map[string]any{"risk_state_severity": "none", "admin_high_risk": false}
		updated, err := store.Register(reported, bundle, now.Add(3*time.Second))
		if err != nil || updated.Metadata["risk_state_severity"] != "high" || updated.Metadata["admin_high_risk"] != true {
			t.Fatalf("%s re-registration cleared administrative risk: err=%v", label, err)
		}
	}
	if _, err := pg.Register(model.Device{
		ID: "device-a", TenantID: "tenant-b", UserID: "user-b", Hostname: "host-b",
		OS: "macos", AgentVersion: "0.4.0",
	}, model.PolicyBundle{ID: "other", Version: "1", TenantID: "tenant-b"}, now); err == nil {
		t.Fatal("another tenant took over an existing device ID")
	}
	if _, err := pg.Heartbeat(model.DeviceHeartbeat{ID: "device-a", TenantID: "tenant-b"}, bundle, now); err == nil {
		t.Fatal("another tenant updated the device by heartbeat")
	}
	if _, ok, err := pg.GetByTenant("tenant-b", "device-a"); err != nil || ok {
		t.Fatalf("cross-tenant device read succeeded: found=%t err=%v", ok, err)
	}
	var storedTenant, storedTrust, storedStatus string
	var metadataJSON, payloadJSON []byte
	if err := pg.DB.QueryRow(`SELECT tenant_id, device_trust_level, status, metadata, payload FROM device_inventory WHERE device_id = 'device-a'`).Scan(
		&storedTenant, &storedTrust, &storedStatus, &metadataJSON, &payloadJSON,
	); err != nil {
		t.Fatal(err)
	}
	var storedMetadata map[string]any
	var storedPayload model.Device
	if err := json.Unmarshal(metadataJSON, &storedMetadata); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payloadJSON, &storedPayload); err != nil {
		t.Fatal(err)
	}
	if storedTenant != "tenant-a" || storedTrust != storedPayload.DeviceTrustLevel || storedStatus != storedPayload.Status ||
		storedMetadata["risk_state_severity"] != storedPayload.Metadata["risk_state_severity"] {
		t.Fatal("device inventory columns and payload disagree")
	}

	// An administrator revocation is authoritative even when the same tenant's
	// device re-registers or sends a healthy heartbeat. Check both row and JSON.
	revoked := initial
	revoked.ID = "revoked-device"
	if _, err := pg.Register(revoked, bundle, now); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.DB.Exec(`UPDATE device_inventory SET status = 'revoked', payload = jsonb_set(payload, '{status}', '"revoked"'::jsonb, true) WHERE device_id = $1`, revoked.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := pg.Register(revoked, bundle, now.Add(time.Second)); err != nil || got.Status != "revoked" {
		t.Fatalf("re-registration cleared administrative revocation: status=%q err=%v", got.Status, err)
	}
	if got, err := pg.Heartbeat(model.DeviceHeartbeat{ID: revoked.ID, TenantID: revoked.TenantID, Status: "healthy"}, bundle, now.Add(2*time.Second)); err != nil || got.Status != "revoked" {
		t.Fatalf("heartbeat cleared administrative revocation: status=%q err=%v", got.Status, err)
	}
	var revokedColumn, revokedPayload string
	if err := pg.DB.QueryRow(`SELECT status, payload->>'status' FROM device_inventory WHERE device_id = $1`, revoked.ID).Scan(&revokedColumn, &revokedPayload); err != nil || revokedColumn != "revoked" || revokedPayload != "revoked" {
		t.Fatalf("revocation row and payload diverged: column=%q payload=%q err=%v", revokedColumn, revokedPayload, err)
	}

	// Two independent Edge store instances race a same-device re-registration
	// against an administrator risk mark. Either order must retain high risk.
	peer := &postgresDeviceInventoryStore{DB: pg.DB}
	for i := range 8 {
		id := fmt.Sprintf("race-device-%d", i)
		reported := initial
		reported.ID = id
		if _, err := pg.Register(reported, bundle, now); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := pg.Register(reported, bundle, now.Add(time.Second))
			errs <- err
		}()
		go func() {
			defer wg.Done()
			_, _, _, err := peer.ApplyRiskSignal(id, model.RiskSignal{
				EntityType: "device", EntityID: id, Severity: "high", Source: "manual_high_risk",
			}, now.Add(time.Second))
			errs <- err
		}()
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatal(err)
			}
		}
		if got, ok := pg.Get(id); !ok || got.Metadata["risk_state_severity"] != "high" {
			t.Fatalf("concurrent registration cleared admin risk for %s", id)
		}
	}

	// A new Store after a restart reads the durable verdict and risk state.
	restarted, closeRestarted, err := setupEdgeDeviceStore(ctx, edgeDeviceStoreConfig{Mode: "postgres", DSN: privateDSN})
	if err != nil {
		t.Fatal(err)
	}
	defer closeRestarted()
	if got, ok := restarted.Get("device-a"); !ok || got.TenantID != "tenant-a" || got.Metadata["risk_state_severity"] != "high" {
		t.Fatal("restart did not restore the tenant-owned risk state")
	}
	if _, ok, err := pg.GetByTenant("tenant-a", "device-a"); err != nil || !ok {
		t.Fatalf("own tenant lost its device: found=%t err=%v", ok, err)
	}
}
