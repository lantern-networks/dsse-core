package main

import (
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/inspectionposture"
)

// A test double for the Edge's posture: the pair the process already uses, so these exercise the same shape the
// apply does rather than a stand-in.
type postureHolder struct {
	p inspectionposture.Posture
}

func (h *postureHolder) get() inspectionposture.Posture { return h.p }
func (h *postureHolder) set(p inspectionposture.Posture, _ string) (inspectionposture.Posture, error) {
	h.p = p.Normalized()
	return h.p, nil
}

func bypassDefaultWith(hosts ...string) inspectionposture.Posture {
	return inspectionposture.Posture{
		Mode:                  inspectionposture.ModeBypassDefault,
		DecryptAllowlistHosts: hosts,
		KnownBypassEnabled:    true,
	}
}

// The defect this exists for: two Edges of one fleet answering differently about which hosts they decrypt.
func TestAnEdgeTakesTheControlPlanesInspectionPosture(t *testing.T) {
	cp := &postureHolder{p: bypassDefaultWith("accounts.google.com")}
	edge := &postureHolder{p: inspectionposture.DefaultPosture()}

	section := inspectionPostureBundleSection(cp.get)
	if section == nil {
		t.Fatal("a control plane holding a posture published no section")
	}
	if !applyInspectionPostureBundleSection(section, edge.get, edge.set, nil) {
		t.Fatal("the Edge did not take the control plane's posture")
	}
	if edge.get().Mode != inspectionposture.ModeBypassDefault {
		t.Fatalf("mode = %q, want bypass_default", edge.get().Mode)
	}
	if got := edge.get().DecryptAllowlistHosts; len(got) != 1 || got[0] != "accounts.google.com" {
		t.Fatalf("allowlist = %v: which hosts an Edge decrypts still depends on which Edge you ask", got)
	}
}

// ★ THE ALLOWLIST HAS TO TRAVEL, not just the mode. Carrying the mode alone would put every Edge in
// bypass_default and decrypt NOTHING, which reads as "applied" on every screen and silently stops inspection.
func TestTheAllowlistTravelsAndNotOnlyTheMode(t *testing.T) {
	cp := &postureHolder{p: inspectionposture.Posture{
		Mode:                   inspectionposture.ModeBypassDefault,
		DecryptAllowlistHosts:  []string{"login.microsoftonline.com", "accounts.google.com"},
		DecryptAllowlistGroups: []string{"google_auth"},
		KnownBypassEnabled:     false,
	}}
	edge := &postureHolder{p: inspectionposture.DefaultPosture()}
	applyInspectionPostureBundleSection(inspectionPostureBundleSection(cp.get), edge.get, edge.set, nil)

	got := edge.get()
	if len(got.DecryptAllowlistHosts) != 2 {
		t.Fatalf("allowlist hosts = %v: the Edge is in bypass_default and decrypts less than the operator chose", got.DecryptAllowlistHosts)
	}
	if len(got.DecryptAllowlistGroups) != 1 {
		t.Fatalf("allowlist groups = %v", got.DecryptAllowlistGroups)
	}
	if got.KnownBypassEnabled {
		t.Fatal("known_bypass_enabled did not travel: the Edge bypasses a set the operator turned off")
	}
}

// An unchanged posture is not re-applied, so the log records CHANGES and not polls. A poll every 40 seconds
// that logs "applied" is a log nobody reads, which is how the previous divergence stayed invisible.
func TestAnUnchangedPostureIsNotReapplied(t *testing.T) {
	cp := &postureHolder{p: bypassDefaultWith("accounts.google.com")}
	edge := &postureHolder{p: bypassDefaultWith("accounts.google.com")}
	if applyInspectionPostureBundleSection(inspectionPostureBundleSection(cp.get), edge.get, edge.set, nil) {
		t.Fatal("an identical posture was reported as a change")
	}
}

// A control plane that does not author the posture leaves this Edge's alone — the pointer is the whole of the
// authority question, because a posture has no "empty" that could be confused with absence.
func TestAControlPlaneThatAuthorsNoPostureChangesNothing(t *testing.T) {
	edge := &postureHolder{p: bypassDefaultWith("accounts.google.com")}
	if applyInspectionPostureBundleSection(nil, edge.get, edge.set, nil) {
		t.Fatal("an absent section changed this Edge's posture")
	}
	if inspectionPostureBundleSection(nil) != nil {
		t.Fatal("a node holding no posture published a section claiming it authors one")
	}
	if got := edge.get().DecryptAllowlistHosts; len(got) != 1 {
		t.Fatalf("the Edge's own posture was disturbed: %v", got)
	}
}

// ★★★ THE GENERATION. A section that does not move the aggregate is published in every bundle and applied by
// nobody — measured on the Site catalogue the day before this was written.
func TestChangingThePostureChangesItsGeneration(t *testing.T) {
	store := inspectionposture.NewStore()
	start := store.ConfigGeneration()
	if _, err := store.Set(bypassDefaultWith("accounts.google.com")); err != nil {
		t.Fatalf("set: %v", err)
	}
	if after := store.ConfigGeneration(); after <= start {
		t.Fatalf("generation stayed at %d: a posture change alters the bundle's contents and not its version, "+
			"so no Edge re-pulls", after)
	}
}

// ★ AND THE SUM ADDS IT, and the publisher actually calls the section builder. The store having a number and
// the route having a section are two different things, and Go compiles an unused function without complaint.
func TestTheBundlePublishesAndCountsTheInspectionPosture(t *testing.T) {
	src := readSourceFile(t, "admin_policy_routes.go")
	if !strings.Contains(src, "inspectionPostureBundleSection(") {
		t.Fatal("the config bundle never builds an inspection-posture section: the posture stays a per-node store")
	}
	if !strings.Contains(src, "+ postureGen") {
		t.Fatal("the posture's generation is not added to the bundle's aggregate: the section would be published " +
			"in every bundle and applied by nobody")
	}
	apply := readSourceFile(t, "config_bundle_sync.go")
	if !strings.Contains(apply, "applyInspectionPostureBundleSection(") {
		t.Fatal("the Edge never applies the inspection-posture section")
	}
}

// An Edge that pulls its config must refuse to author the posture locally, or the two authors race and only the
// node that received the write knows.
func TestAConfigPullingEdgeRefusesToAuthorThePosture(t *testing.T) {
	src := readSourceFile(t, "admin_effective_policy_routes.go")
	i := strings.Index(src, `mux.HandleFunc("POST /admin/inspection-posture"`)
	if i < 0 {
		t.Fatal("the posture write route is gone")
	}
	window := src[i:]
	if j := strings.Index(window[1:], "mux.HandleFunc("); j > 0 {
		window = window[:j]
	}
	if !strings.Contains(window, "configWriteRejectedWhenSourced(") {
		t.Fatal("POST /admin/inspection-posture accepts writes on a config-pulling Edge: the next poll would " +
			"silently overwrite them, on that node only")
	}
}
