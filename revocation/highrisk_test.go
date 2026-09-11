package revocation

import (
	"path/filepath"
	"testing"
)

// Shared high-risk overlay: Mark/Clear (change-detected generation), IsHighRisk, ReplaceSynced
// (puller side), and persistence (a CP restart must not silently clear high-risk markings).
func TestHighRiskDeviceOverlay(t *testing.T) {
	o := NewHighRiskOverlay()
	if _, ok := o.IsHighRisk("dev-1"); ok {
		t.Fatalf("nothing high-risk initially")
	}
	o.Mark("dev-1", "high") // device ids are case-sensitive (preserved for grant-store interop)
	if o.ConfigGeneration() == 0 {
		t.Fatalf("Mark must advance the generation")
	}
	g := o.ConfigGeneration()
	o.Mark("dev-1", "high") // idempotent — same severity, no bump
	if o.ConfigGeneration() != g {
		t.Fatalf("an idempotent Mark must not bump the generation")
	}
	if sev, ok := o.IsHighRisk("dev-1"); !ok || sev != "high" {
		t.Fatalf("dev-1 should be high-risk (high), got %q ok=%v", sev, ok)
	}
	o.Clear("dev-1")
	if _, ok := o.IsHighRisk("dev-1"); ok {
		t.Fatalf("dev-1 cleared")
	}

	// ReplaceSynced (puller side) replaces the whole set from the CP feed.
	o.ReplaceSynced(map[string]string{"dev-cp": "critical"})
	if sev, ok := o.IsHighRisk("dev-cp"); !ok || sev != "critical" {
		t.Fatalf("synced high-risk should apply, got %q ok=%v", sev, ok)
	}
}

func TestHighRiskDeviceOverlayPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hr.json")
	o := NewHighRiskOverlay()
	o.SetStatePath(path)
	o.Mark("dev-1", "high")

	restored := NewHighRiskOverlay() // simulate restart
	restored.SetStatePath(path)
	if _, ok := restored.IsHighRisk("dev-1"); !ok {
		t.Fatalf("a high-risk marking must survive a restart via the durable store")
	}
}
