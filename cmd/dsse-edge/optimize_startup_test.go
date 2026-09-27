package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/lantern-networks/dsse-core/inspectionposture"
	"github.com/lantern-networks/dsse-core/policyrule"
)

func seedOptimizeStartup(t *testing.T, dir string) {
	t.Helper()
	seedCertPinStartup(t, dir)
	posture := inspectionposture.NewStore()
	if _, err := posture.SetStatePath(filepath.Join(dir, "posture.json")); err != nil {
		t.Fatal(err)
	}
	p := posture.Get()
	p.BypassGroups = []string{"m365_optimize", "google_optimize", "slack_media", "zoom_media"}
	if _, err := posture.Set(p); err != nil {
		t.Fatal(err)
	}
	rules := policyrule.NewStore()
	if err := rules.SetStatePath(filepath.Join(dir, "rules.json")); err != nil {
		t.Fatal(err)
	}
	for _, r := range []policyrule.Rule{
		{ID: "optimize-bypass-m365_optimize", TenantID: "startup-own", Plane: "egress", Priority: 60, Name: "Disabled Microsoft", Source: []string{"*"}, Destination: []string{"bi-grp-m365_optimize"}, Action: policyrule.Action{Access: "allow", Inspection: "bypass"}, Status: "disabled"},
		{ID: "optimize-bypass-google_optimize", TenantID: "startup-own", Plane: "egress", Priority: 60, Name: "Inspect Google", Source: []string{"*"}, Destination: []string{"bi-grp-google_optimize"}, Action: policyrule.Action{Access: "allow", Inspection: "inspect"}, Status: "active"},
		{ID: "explicit-zoom", TenantID: "startup-own", Plane: "egress", Priority: 60, Name: "Explicit Zoom", Source: []string{"*"}, Destination: []string{"bi-grp-zoom_media"}, Action: policyrule.Action{Access: "allow", Inspection: "bypass"}, Status: "active"},
		{ID: "foreign-slack", TenantID: "startup-other", Plane: "egress", Priority: 60, Name: "Foreign Slack", Source: []string{"*"}, Destination: []string{"bi-grp-slack_media"}, Action: policyrule.Action{Access: "allow", Inspection: "bypass"}, Status: "active"},
	} {
		if _, err := rules.Upsert(r); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLegacyOptimizeStartupPreservesSavedIntent(t *testing.T) {
	for _, sourced := range []bool{false, true} {
		name := "local"
		if sourced {
			name = "configuration-pulling"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			seedOptimizeStartup(t, dir)
			saved := map[string][]byte{}
			for _, f := range []string{"posture", "rules", "assets", "candidates"} {
				b, e := os.ReadFile(filepath.Join(dir, f+".json"))
				if e != nil {
					t.Fatal(e)
				}
				saved[f] = b
			}
			for restart := 0; restart < 2; restart++ {
				base, stop := startCertPinMain(t, dir, sourced, "-inspection-posture-store", filepath.Join(dir, "posture.json"))
				for host, want := range map[string]string{"work.sharepoint.com": "inspect", "video.googlevideo.com": "inspect", "files.slack.com": "inspect", "video.cloudfront.zoom.us": "bypass", "control.example": "inspect"} {
					var actual effectivePolicyResponse
					certPinStartupGet(t, base, "/admin/effective-policy?destination="+host, &actual)
					if actual.Inspection.Decision != want {
						t.Errorf("restart %d %s: %+v want %s", restart, host, actual.Inspection, want)
					}
				}
				var list effectiveEgressRuleListResponse
				certPinStartupGet(t, base, "/admin/egress-effective-rules", &list)
				for _, r := range list.Rules {
					if r.Kind == "optimize_bypass" {
						t.Errorf("legacy selection became active row: %+v", r)
					}
				}
				stop()
				for f, before := range saved {
					after, e := os.ReadFile(filepath.Join(dir, f+".json"))
					if e != nil {
						t.Fatal(e)
					}
					if !bytes.Equal(before, after) {
						t.Errorf("restart %d rewrote %s", restart, f)
					}
				}
			}
		})
	}
}
