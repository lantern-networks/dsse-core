package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var threeDoors = []string{"tokyo=https://agents.tokyo.example", "osaka=https://agents.osaka.example", "fukuoka=https://agents.fukuoka.example"}

// TestASiteChoosesWhichDoorItsConnectorsUseFirst — the operator during acceptance C's third walk: an Osaka site
// whose connectors dial Tokyo first is a problem, and the administrator has to be able to say so. Failover is
// kept: every door stays in the list.
func TestASiteChoosesWhichDoorItsConnectorsUseFirst(t *testing.T) {
	cases := []struct {
		name   string
		order  []string
		region string
		want   []string
	}{
		{"nothing chosen, no region: the deployment's order", nil, "", threeDoors},
		{"nothing chosen: the site's own region first", nil, "osaka", []string{threeDoors[1], threeDoors[0], threeDoors[2]}},
		{"a chosen order wins over the site's region", []string{"fukuoka", "osaka"}, "tokyo", []string{threeDoors[2], threeDoors[1], threeDoors[0]}},
		{"a partial order puts the rest after it, in the deployment's order", []string{"fukuoka"}, "", []string{threeDoors[2], threeDoors[0], threeDoors[1]}},
		{"a region this organization cannot use adds nothing", []string{"sapporo", "osaka"}, "", []string{threeDoors[1], threeDoors[0], threeDoors[2]}},
		{"case does not matter", []string{"OSAKA"}, "", []string{threeDoors[1], threeDoors[0], threeDoors[2]}},
	}
	for _, c := range cases {
		got := orderDoorsForSite(append([]string(nil), threeDoors...), c.order, c.region)
		if strings.Join(got, ";") != strings.Join(c.want, ";") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
		if len(got) != len(threeDoors) {
			t.Errorf("%s: %d doors, want every one of %d — losing one would lose failover", c.name, len(got), len(threeDoors))
		}
	}
	if got := orderDoorListForSite(strings.Join(threeDoors, ";"), []string{"osaka"}, ""); !strings.HasPrefix(got, threeDoors[1]+";") {
		t.Errorf("the enrolment list did not start with osaka: %s", got)
	}
}

func TestADoorOrderHoldsOnlyRegions(t *testing.T) {
	got, err := normalizeSiteDoorOrder([]string{" osaka ", "tokyo", "osaka", ""})
	if err != nil || strings.Join(got, ",") != "osaka,tokyo" {
		t.Fatalf("got %v, %v; want trimmed, without repeats", got, err)
	}
	for _, bad := range []string{"osaka,tokyo", "https://agents.osaka.example", "../x"} {
		if _, err := normalizeSiteDoorOrder([]string{bad}); err == nil {
			t.Errorf("%q was accepted as a region", bad)
		}
	}
}

// TestTheConnectorReadsItsSitesOrder: the order reaches a connector already in the field on its next profile
// poll, and a connector added later gets it in its settings file.
func TestTheConnectorReadsItsSitesOrder(t *testing.T) {
	mux := http.NewServeMux()
	registerConnectorProfileRoute(mux,
		func(http.ResponseWriter, *http.Request, string) (string, bool) { return "org-1", true },
		"https://fallback.example", func(context.Context, string) ([]regionEndpoint, error) {
			return []regionEndpoint{{Region: "tokyo", Endpoint: "https://agents.tokyo.example"},
				{Region: "osaka", Endpoint: "https://agents.osaka.example"}}, nil
		}, func(_ context.Context, tenant, cid string) (string, []string, string) {
			if tenant != "org-1" || cid != "conn-osaka" {
				t.Fatalf("site looked up for %s/%s", tenant, cid)
			}
			return "osaka-branch", []string{"osaka"}, "tokyo"
		})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/connectors/conn-osaka/profile", nil))
	var p connectorProfile
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &p) != nil {
		t.Fatalf("profile status=%d body=%s", w.Code, w.Body.String())
	}
	if len(p.EdgeEndpoints) != 2 || p.EdgeEndpoints[0] != "osaka=https://agents.osaka.example" {
		t.Fatalf("doors = %v; the site put osaka first", p.EdgeEndpoints)
	}

	ctx := context.Background()
	store := newAdminSiteStore()
	now := time.Now().UTC()
	if _, err := store.Upsert(ctx, adminSiteModel{SiteID: "osaka-branch", TenantID: "org-1", Region: "tokyo", DoorOrder: []string{"osaka"}}, now); err != nil {
		t.Fatal(err)
	}
	resp, ok, err := adminSiteEnrollmentCommandIssue(ctx, store, "org-1", "osaka-branch", enrollmentTokenParams{
		EdgeURL: "https://agents.tokyo.example", EdgeEndpoints: "tokyo=https://agents.tokyo.example;osaka=https://agents.osaka.example"}, now)
	if err != nil || !ok {
		t.Fatalf("issue: %v %v", ok, err)
	}
	if resp.Profile.EdgeEndpoints[0] != "osaka=https://agents.osaka.example" {
		t.Fatalf("settings file doors = %v; the first tunnel would go to tokyo", resp.Profile.EdgeEndpoints)
	}
	raw, err := base64.RawURLEncoding.DecodeString(resp.Token)
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(resp.Token)
	}
	if err != nil || !strings.Contains(string(raw), `"edge_endpoints":"osaka=https://agents.osaka.example;tokyo=`) {
		t.Fatalf("token doors are not in the site's order: %s (%v)", raw, err)
	}
	if got, _, _ := store.Get(ctx, "org-1", "osaka-branch"); len(got.DoorOrder) != 1 {
		t.Fatalf("issuing a command lost the site's order: %+v", got)
	}
}

func TestPostgresAdminSiteDoorOrderMigrationMatches(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "migrations", "061_admin_site_door_order.sql"))
	if err != nil {
		t.Fatal(err)
	}
	var body []string
	for _, line := range strings.Split(string(data), "\n") {
		if s := strings.TrimSpace(line); s != "" && !strings.HasPrefix(s, "--") {
			body = append(body, s)
		}
	}
	got := strings.TrimSuffix(strings.Join(body, " "), ";")
	if want := strings.Join(postgresAdminSiteDoorOrderSQL(), " "); got != want {
		t.Fatalf("migration = %q\nhelper    = %q", got, want)
	}
	for _, v := range postgresAdminSiteMigrationVersions() {
		if v == postgresMigrationAdminSiteDoorOrder {
			return
		}
	}
	t.Fatal("the site store does not apply the door-order migration")
}

func TestPostgresSiteKeepsItsDoorOrder(t *testing.T) {
	db := reviewAuthSitePostgresDB(t)
	ctx := context.Background()
	for _, stmt := range append(postgresAdminSiteSchemaSQL(), postgresAdminSiteDoorOrderSQL()...) {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatal(err)
		}
	}
	if err := createSiteGenerationSequence(ctx, db); err != nil {
		t.Fatal(err)
	}
	s := &postgresAdminSiteStore{db: db}
	if _, err := s.Upsert(ctx, adminSiteModel{TenantID: "org-1", SiteID: "osaka-branch", DoorOrder: []string{"osaka", "tokyo"}}, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Get(ctx, "org-1", "osaka-branch")
	if err != nil || !ok || strings.Join(got.DoorOrder, ",") != "osaka,tokyo" {
		t.Fatalf("read back %+v ok=%v err=%v", got.DoorOrder, ok, err)
	}
	if _, err := s.Upsert(ctx, adminSiteModel{TenantID: "org-1", SiteID: "osaka-branch"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := s.Get(ctx, "org-1", "osaka-branch"); len(got.DoorOrder) != 0 {
		t.Fatalf("clearing the order kept %v", got.DoorOrder)
	}
}

// TestTheSiteScreenReadsTheOrderBack: the Console confirms a save by reading the field back from the answer and
// from the list. A field the projection dropped would read as an unconfirmed save every time.
func TestTheSiteScreenReadsTheOrderBack(t *testing.T) {
	got := adminSiteApplyMeta(adminSite{SiteID: "osaka-branch"}, adminSiteModel{SiteID: "osaka-branch", DoorOrder: []string{"osaka", "tokyo"}})
	b, _ := json.Marshal(got)
	if !strings.Contains(string(b), `"door_order":["osaka","tokyo"]`) {
		t.Fatalf("the site the Console reads has no door order: %s", b)
	}
}
