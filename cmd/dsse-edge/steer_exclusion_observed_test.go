package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/lantern-networks/dsse-core/enrolledinventory"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	steerexclusion "github.com/lantern-networks/dsse-core/steerexclusion"

	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/decision"
	"github.com/lantern-networks/dsse-core/model"
)

// observedTestServer wires both the admin steer-exclusion store and the reverse-telemetry observed store so a
// test can drive the full G2 loop: a device REPORTS its effective set, an admin READS it back.
func observedTestServer(t *testing.T, store *steerexclusion.Store, observed *observedExclusionStore) http.Handler {
	t.Helper()
	// ★ Real devices are enrolled; the fallback that let an unenrolled one be served the NODE's organization
	// is gone (2026-09-05). The harness says which organization each device is in, as the control plane does.
	ledger := enrolledinventory.NewLedger()
	stamp := time.Now().UTC().Format(time.RFC3339)
	for _, id := range []string{"mac-dev-1", "win-dev-1"} {
		if _, err := ledger.Enroll(id, "t1", "", stamp); err != nil {
			t.Fatalf("enroll %s: %v", id, err)
		}
	}
	return newServerWithConfig(serverConfig{
		Evaluator:          decision.Evaluator{PolicyBundle: model.PolicyBundle{TenantID: "t1"}},
		EnrolledLedger:     ledger,
		Registry:           connector.NewRegistry(),
		AdminAuth:          newAdminAuthStore(),
		SteerExclusions:    store,
		ObservedExclusions: observed,
	})
}

func TestEffectiveReportRequiresVerifiedIdentity(t *testing.T) {
	handler := observedTestServer(t, steerexclusion.NewStore(), newObservedExclusionStore(0))
	body, _ := json.Marshal(map[string]any{"platform": "macos", "effective_app_signing_ids": []string{"com.x"}})
	req := httptest.NewRequest(http.MethodPost, "/steer/agent-policy/effective", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without a verified transport identity", rec.Code)
	}
}

func TestEffectiveReportIsVisibleToAdminObserved(t *testing.T) {
	observed := newObservedExclusionStore(0)
	handler := observedTestServer(t, steerexclusion.NewStore(), observed)

	// A device reports the merged set it actually applies: a local floor/scaffold (incl. a hardcoded local
	// self-exclusion) plus 1 admin-issued entry. server_app_signing_id_count tells the admin how many are admin.
	body, _ := json.Marshal(map[string]any{
		"platform":                    "macos",
		"effective_app_signing_ids":   []string{"com.anthropic.claudefordesktop", "automation", "com.admin.set"},
		"server_app_signing_id_count": 1,
	})
	cert := leafWithCN(t, "mac-dev-1")
	req := httptest.NewRequest(http.MethodPost, "/steer/agent-policy/effective", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("report status = %d, want 204, body=%s", rec.Code, rec.Body.String())
	}

	// The admin now sees exactly what the device excludes — including a device-local scaffold that no admin authored.
	adminReq := httptest.NewRequest(http.MethodGet, "/admin/steer-exclusions/observed", nil)
	adminRec := httptest.NewRecorder()
	handler.ServeHTTP(adminRec, adminReq)
	if adminRec.Code != http.StatusOK {
		t.Fatalf("observed status = %d, want 200, body=%s", adminRec.Code, adminRec.Body.String())
	}
	var resp struct {
		Observed []observedExclusionEntry `json:"observed"`
	}
	if err := json.Unmarshal(adminRec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Observed) != 1 {
		t.Fatalf("observed entries = %d, want 1", len(resp.Observed))
	}
	got := resp.Observed[0]
	if got.DeviceIdentity != "mac-dev-1" || got.Platform != "macos" || got.ServerAppSigningIDCount != 1 {
		t.Fatalf("observed entry = %#v, want device mac-dev-1/macos/serverCount 1", got)
	}
	hasDeviceLocalScaffold := false
	for _, id := range got.EffectiveAppSigningIDs {
		if strings.Contains(id, "com.anthropic.") {
			hasDeviceLocalScaffold = true
		}
	}
	if !hasDeviceLocalScaffold {
		t.Fatalf("observed effective set %v does not surface the hardcoded self-exclusion (the whole point of G2)", got.EffectiveAppSigningIDs)
	}
}

// TestEffectiveReportCarriesDeviceState asserts the Phase 1 device-state fields (posture, fail-open, region-
// failover, active region, server-initiated count) reported alongside the effective set are stored and visible
// to the admin observed read — and that an unknown/injected posture is clamped to "" (a device cannot paint an
// arbitrary label on the console).
func TestEffectiveReportCarriesDeviceState(t *testing.T) {
	observed := newObservedExclusionStore(0)
	handler := observedTestServer(t, steerexclusion.NewStore(), observed)

	body, _ := json.Marshal(map[string]any{
		"platform":                    "windows",
		"effective_app_signing_ids":   []string{"com.anthropic.claudefordesktop"},
		"server_app_signing_id_count": 0,
		"posture":                     "disarmed",
		"fail_open_configured":        true,
		"region_failover_enabled":     true,
		"active_region":               "edge-tokyo",
		"server_initiated_rule_count": 3,
	})
	cert := leafWithCN(t, "win-dev-1")
	req := httptest.NewRequest(http.MethodPost, "/steer/agent-policy/effective", bytes.NewReader(body))
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("report status = %d, want 204, body=%s", rec.Code, rec.Body.String())
	}

	adminReq := httptest.NewRequest(http.MethodGet, "/admin/steer-exclusions/observed", nil)
	adminRec := httptest.NewRecorder()
	handler.ServeHTTP(adminRec, adminReq)
	var resp struct {
		Observed []observedExclusionEntry `json:"observed"`
	}
	if err := json.Unmarshal(adminRec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Observed) != 1 {
		t.Fatalf("observed entries = %d, want 1", len(resp.Observed))
	}
	got := resp.Observed[0]
	if got.Posture != "disarmed" || !got.FailOpenConfigured || !got.RegionFailoverEnabled || got.ActiveRegion != "edge-tokyo" || got.ServerInitiatedRuleCount != 3 {
		t.Fatalf("device-state not stored/returned: %#v", got)
	}

	// A second report with an UNKNOWN posture must clamp to "" (no arbitrary label).
	body2, _ := json.Marshal(map[string]any{
		"platform":                  "windows",
		"effective_app_signing_ids": []string{"com.anthropic.claudefordesktop"},
		"posture":                   "totally-pwned",
	})
	req2 := httptest.NewRequest(http.MethodPost, "/steer/agent-policy/effective", bytes.NewReader(body2))
	req2.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("second report status = %d, want 204", rec2.Code)
	}
	adminRec2 := httptest.NewRecorder()
	handler.ServeHTTP(adminRec2, httptest.NewRequest(http.MethodGet, "/admin/steer-exclusions/observed", nil))
	resp.Observed = nil
	json.Unmarshal(adminRec2.Body.Bytes(), &resp)
	if len(resp.Observed) != 1 || resp.Observed[0].Posture != "" {
		t.Fatalf("unknown posture must clamp to \"\", got %#v", resp.Observed)
	}
}

func TestEffectiveReportTenantScopedAndDeviceKeyed(t *testing.T) {
	observed := newObservedExclusionStore(0)
	// Pre-seed a report for another tenant directly; the admin (tenant t1) must never see it.
	observed.Record(observedExclusionEntry{TenantID: "other-tenant", DeviceIdentity: "x", EffectiveAppSigningIDs: []string{"com.secret"}, ReportedAt: time.Now()})
	handler := observedTestServer(t, steerexclusion.NewStore(), observed)

	adminReq := httptest.NewRequest(http.MethodGet, "/admin/steer-exclusions/observed", nil)
	adminRec := httptest.NewRecorder()
	handler.ServeHTTP(adminRec, adminReq)
	var resp struct {
		Observed []observedExclusionEntry `json:"observed"`
	}
	_ = json.Unmarshal(adminRec.Body.Bytes(), &resp)
	if len(resp.Observed) != 0 {
		t.Fatalf("tenant t1 admin saw %d cross-tenant reports, want 0", len(resp.Observed))
	}
}

func TestResolvedForDevicePreview(t *testing.T) {
	store := steerexclusion.NewStore()
	now := time.Now().UTC()
	if _, err := store.Upsert(steerexclusion.Policy{TenantID: "t1", ScopeType: "tenant", ExcludedAppSigningIDs: []string{"com.tenant.wide"}}, now); err != nil {
		t.Fatal(err)
	}
	handler := observedTestServer(t, store, newObservedExclusionStore(0))

	req := httptest.NewRequest(http.MethodGet, "/admin/steer-exclusions/resolved?device=mac-dev-1", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("resolved status = %d, want 200, body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		DeviceIdentity        string   `json:"device_identity"`
		ResolvedAppSigningIDs []string `json:"resolved_app_signing_ids"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.DeviceIdentity != "mac-dev-1" || len(resp.ResolvedAppSigningIDs) != 1 || resp.ResolvedAppSigningIDs[0] != "com.tenant.wide" {
		t.Fatalf("resolved = %#v, want the tenant-wide admin set", resp)
	}

	// resolved requires a device parameter.
	bad := httptest.NewRequest(http.MethodGet, "/admin/steer-exclusions/resolved", nil)
	badRec := httptest.NewRecorder()
	handler.ServeHTTP(badRec, bad)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("resolved without device = %d, want 400", badRec.Code)
	}
}

func TestClassifyEffectiveExclusions(t *testing.T) {
	resolved := adminResolvedSet([]string{"team-id:ADMIN1", "com.admin.app"})
	floor := []string{"a.out", "limactl-*"}
	admin, unmanaged := classifyEffectiveExclusions(
		[]string{"com.admin.app", "a.out", "limactl-abc123", "com.rogue.app", "team-id:ADMIN1"},
		resolved, floor)
	// admin: com.admin.app + team-id:ADMIN1 ; floor (dropped): a.out, limactl-abc123 ; unmanaged: com.rogue.app
	if len(admin) != 2 {
		t.Fatalf("admin = %v, want the 2 resolved entries", admin)
	}
	if len(unmanaged) != 1 || unmanaged[0] != "com.rogue.app" {
		t.Fatalf("unmanaged = %v, want [com.rogue.app] (a.out/limactl are floor, admin entries excluded)", unmanaged)
	}
}

func seedObserved(s *observedExclusionStore, tenant, device, group string, effective, admin, unmanaged []string, t time.Time) {
	s.Record(observedExclusionEntry{
		TenantID: tenant, DeviceIdentity: device, DeviceGroup: group,
		Platform: "macos", EffectiveAppSigningIDs: effective,
		AdminAppSigningIDs: admin, UnmanagedAppSigningIDs: unmanaged, ReportedAt: t,
	})
}

func TestObservedQueryFilterAndPaginate(t *testing.T) {
	s := newObservedExclusionStore(0)
	now := time.Now().UTC()
	seedObserved(s, "t1", "mac-1", "eng", []string{"com.admin.app"}, []string{"com.admin.app"}, nil, now)
	seedObserved(s, "t1", "mac-2", "eng", []string{"com.rogue.app"}, nil, []string{"com.rogue.app"}, now.Add(time.Second))
	seedObserved(s, "t1", "win-1", "sales", []string{"evil.exe"}, nil, []string{"evil.exe"}, now.Add(2*time.Second))
	seedObserved(s, "other", "x", "", []string{"com.secret"}, nil, []string{"com.secret"}, now)

	// tenant scope: only t1's 3.
	if r := s.Query("t1", observedQueryFilter{Limit: 50}); r.Total != 3 {
		t.Fatalf("total = %d, want 3 (tenant-scoped)", r.Total)
	}
	// device prefix.
	if r := s.Query("t1", observedQueryFilter{Device: "mac-*", Limit: 50}); r.Total != 2 {
		t.Fatalf("device prefix total = %d, want 2", r.Total)
	}
	// group.
	if r := s.Query("t1", observedQueryFilter{Group: "sales", Limit: 50}); r.Total != 1 || r.Entries[0].DeviceIdentity != "win-1" {
		t.Fatalf("group filter = %#v, want only win-1", r.Entries)
	}
	// app membership.
	if r := s.Query("t1", observedQueryFilter{App: "com.rogue.app", Limit: 50}); r.Total != 1 || r.Entries[0].DeviceIdentity != "mac-2" {
		t.Fatalf("app filter = %#v, want only mac-2", r.Entries)
	}
	// anomalous only: mac-2 + win-1.
	if r := s.Query("t1", observedQueryFilter{AnomalousOnly: true, Limit: 50}); r.Total != 2 {
		t.Fatalf("anomalous total = %d, want 2", r.Total)
	}
	// pagination: limit 2 from 3, then offset 2 gets the last.
	p1 := s.Query("t1", observedQueryFilter{Limit: 2})
	if len(p1.Entries) != 2 || p1.Total != 3 {
		t.Fatalf("page1 = %d entries / total %d, want 2/3", len(p1.Entries), p1.Total)
	}
	p2 := s.Query("t1", observedQueryFilter{Limit: 2, Offset: 2})
	if len(p2.Entries) != 1 {
		t.Fatalf("page2 = %d entries, want 1", len(p2.Entries))
	}
}

func TestObservedByApp(t *testing.T) {
	s := newObservedExclusionStore(0)
	now := time.Now().UTC()
	// com.admin.app: admin on 2 devices. com.rogue.app: unmanaged on 1.
	seedObserved(s, "t1", "mac-1", "", []string{"com.admin.app"}, []string{"com.admin.app"}, nil, now)
	seedObserved(s, "t1", "mac-2", "", []string{"com.admin.app", "com.rogue.app"}, []string{"com.admin.app"}, []string{"com.rogue.app"}, now)
	res := s.ByApp("t1", 50)
	if res.DeviceTotal != 2 {
		t.Fatalf("device total = %d, want 2", res.DeviceTotal)
	}
	byID := map[string]observedByAppEntry{}
	for _, a := range res.Apps {
		byID[a.AppID] = a
	}
	if byID["com.admin.app"].DeviceCount != 2 || byID["com.admin.app"].Class != appClassAdmin {
		t.Fatalf("com.admin.app = %#v, want count 2 class admin", byID["com.admin.app"])
	}
	if byID["com.rogue.app"].DeviceCount != 1 || byID["com.rogue.app"].Class != appClassUnmanaged {
		t.Fatalf("com.rogue.app = %#v, want count 1 class unmanaged", byID["com.rogue.app"])
	}
	// unmanaged sorts first.
	if res.Apps[0].Class != appClassUnmanaged {
		t.Fatalf("first app class = %s, want unmanaged sorted first", res.Apps[0].Class)
	}
}

// Readiness before rotating the transport CA. The question is not "how many devices look fine" but "is there
// any device that would be cut off", because a device that misses the changeover cannot recover on its own.
func TestTransportCAReadiness(t *testing.T) {
	const next = "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233" + "44"
	const other = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	store := newObservedExclusionStore(100)
	record := func(device string, pins ...string) {
		store.Record(observedExclusionEntry{
			TenantID: "t1", DeviceIdentity: device, PinnedTransportCASHA256: pins, ReportedAt: time.Now(),
		})
	}
	record("mac-1", next)
	record("win-1", other)       // reported, but does not hold the new CA
	record("mac-2", other, next) // holds both — an overlap, which is the normal mid-rotation state
	// "linux-1" never reports at all.

	got := store.TransportCAReadiness("t1", next, []string{"mac-1", "win-1", "mac-2", "linux-1"})

	if len(got.Ready) != 2 {
		t.Fatalf("ready=%v, want mac-1 and mac-2", got.Ready)
	}
	if len(got.NotReady) != 1 || got.NotReady[0] != "win-1" {
		t.Fatalf("not_ready=%v, want [win-1]", got.NotReady)
	}
	// Silent is counted apart from NotReady on purpose: a device that has said nothing may simply be switched
	// off, and cutting over while it is off is exactly how it comes back dead.
	if len(got.Silent) != 1 || got.Silent[0] != "linux-1" {
		t.Fatalf("silent=%v, want [linux-1] — a device that has never reported must not be lumped in with one "+
			"that reported a different CA; only the second is fixable by waiting", got.Silent)
	}
	if got.SafeToCut {
		t.Fatal("reported safe to cut over with a device still missing the CA and another silent — that is how " +
			"a rotation strands the devices that cannot recover")
	}

	// Everyone holds it: only then is it safe.
	record("win-1", next)
	record("linux-1", next)
	all := store.TransportCAReadiness("t1", next, []string{"mac-1", "win-1", "mac-2", "linux-1"})
	if !all.SafeToCut || all.ReadyPct != 100 {
		t.Fatalf("with every device holding the CA: safe=%v pct=%d, want true/100", all.SafeToCut, all.ReadyPct)
	}
}

// Device-reported fingerprints are clamped, not trusted.
func TestReportedFingerprintsAreSanitized(t *testing.T) {
	good := "aa11bb22cc33dd44ee55ff6600112233445566778899aabbccddeeff00112233"
	// The SAME CA, written with colons and in upper case — how a human pastes a fingerprint.
	sameWithColons := "AA:11:BB:22:CC:33:DD:44:EE:55:FF:66:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33"
	different := "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"

	out := normalizeReportedFingerprints([]string{good, sameWithColons, different, "short", "zz" + good[2:], ""})

	// Two DISTINCT CAs. One CA reported in two notations must not be counted twice, or a device holding a
	// single CA would look like it had already picked up the new one.
	if len(out) != 2 {
		t.Fatalf("got %d fingerprints (%v), want two distinct CAs with the colon/upper-case duplicate folded in",
			len(out), out)
	}
	if out[0] != good || out[1] != different {
		t.Fatalf("unexpected fingerprints %v", out)
	}
	for _, fp := range out {
		if len(fp) != 64 {
			t.Fatalf("fingerprint %q is not 64 hex chars", fp)
		}
	}

	// A flood must be bounded: a device pins one or two CAs during an overlap, and hundreds is a bug or an
	// attempt to bloat the telemetry store.
	many := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		many = append(many, fmt.Sprintf("%064x", i))
	}
	if n := len(normalizeReportedFingerprints(many)); n > 8 {
		t.Fatalf("accepted %d fingerprints from one report — unbounded telemetry from a device", n)
	}
}

// A device can now say what it received and deliberately did NOT apply, so the console states the device's own
// reason instead of inferring one from an AppID's shape. Two properties matter and are easy to get wrong: the
// set must survive the round trip verbatim, and an agent that does not send it must leave nil — "did not say",
// never "ignored nothing", because the second reads as an assertion the device never made.
func TestEffectiveReportCarriesWhatTheDeviceIgnored(t *testing.T) {
	observed := newObservedExclusionStore(0)
	handler := observedTestServer(t, steerexclusion.NewStore(), observed)
	cert := leafWithCN(t, "mac-dev-1")

	report := func(payload map[string]any) {
		t.Helper()
		body, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/steer/agent-policy/effective", bytes.NewReader(body))
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("report status = %d, want 204, body=%s", rec.Code, rec.Body.String())
		}
	}
	read := func() observedExclusionEntry {
		t.Helper()
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/steer-exclusions/observed", nil))
		var resp struct {
			Observed []observedExclusionEntry `json:"observed"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.Observed) != 1 {
			t.Fatalf("observed entries = %d, want 1", len(resp.Observed))
		}
		return resp.Observed[0]
	}

	report(map[string]any{
		"platform":                  "macos",
		"effective_app_signing_ids": []string{"com.example.agent"},
		"ignored_app_signing_ids":   []string{`\program files\jpki\`, "publisher:Example Corp"},
	})
	got := read()
	if len(got.IgnoredAppSigningIDs) != 2 ||
		got.IgnoredAppSigningIDs[0] != `\program files\jpki\` ||
		got.IgnoredAppSigningIDs[1] != "publisher:Example Corp" {
		t.Fatalf("ignored set did not survive the round trip verbatim: %#v", got.IgnoredAppSigningIDs)
	}

	// An older agent omits the field entirely. That must read as "did not say".
	observed2 := newObservedExclusionStore(0)
	handler = observedTestServer(t, steerexclusion.NewStore(), observed2)
	report(map[string]any{"platform": "macos", "effective_app_signing_ids": []string{"com.example.agent"}})
	if silent := read(); silent.IgnoredAppSigningIDs != nil {
		t.Fatalf("an agent that said nothing must leave nil, got %#v — an empty list is a claim it never made", silent.IgnoredAppSigningIDs)
	}
}

// Equal report timestamps must not reshuffle devices between cursor pages.
func TestObservedPaginationEqualTimestamps(t *testing.T) {
	s := newObservedExclusionStore(0)
	now := time.Now()
	for i := 0; i < 55; i++ {
		s.Record(observedExclusionEntry{TenantID: "t1", DeviceIdentity: fmt.Sprintf("device-%03d", i), ReportedAt: now})
	}
	s.Record(observedExclusionEntry{TenantID: "t2", DeviceIdentity: "foreign", ReportedAt: now.Add(time.Hour)})
	for pass := 0; pass < 5; pass++ {
		first := s.Query("t1", observedQueryFilter{Limit: 50})
		last := s.Query("t1", observedQueryFilter{Limit: 50, Offset: 50})
		if first.Total != 55 || last.Total != 55 || len(first.Entries) != 50 || len(last.Entries) != 5 {
			t.Fatalf("unexpected page sizes: %+v %+v", first, last)
		}
		all := append(first.Entries, last.Entries...)
		for i, e := range all {
			if want := fmt.Sprintf("device-%03d", i); e.DeviceIdentity != want {
				t.Fatalf("page %d row %d = %s, want %s", pass, i, e.DeviceIdentity, want)
			}
		}
	}
}
