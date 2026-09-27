package main

import (
	"fmt"

	"github.com/lantern-networks/dsse-core/inspectionposture"
)

// config_bundle_inspection_posture.go — carrying the deployment's inspection posture to the Edges.
//
// ★★★ MEASURED, AND THE STORE ITSELF ALREADY RECORDED IT (2026-08-21, then again 2026-08-23). Read by the same
// administrator from two Edges of one fleet seconds apart, GET /admin/inspection-posture answered
// decrypt_allowlist_hosts=["accounts.google.com"] on one and [] on the other. Which Edge a flow happens to land
// on then decides whether it is decrypted.
//
// The answer at the time was to give both nodes a SHARED store, which is how the enforcement Edges came to hold
// a Postgres connection. Measured again a day later, that had not held either: the reference deployment has
// -inspection-posture-store on ONE of its two Edges, so the fleet still does not agree and nothing says so.
//
// ★ THE POSTURE IS CONFIGURATION, so it travels the way configuration travels — authored on the control plane,
// carried in the signed bundle, applied by every Edge. That removes the shared store rather than fixing its
// symptom, which is the difference between this and the previous attempt.
//
// ★ THERE IS NO "EMPTY" HERE, which makes this simpler than the sections around it. A posture always has a
// value: decrypt-all with the curated bypass list is the default, not an absence. So the only question is
// whether the control plane is the AUTHORITY — answered by the pointer, as everywhere else. Present means "I
// author this"; absent leaves the Edge's own posture untouched, which is what an older control plane does.

// inspectionPostureBundle carries the deployment's posture.
type inspectionPostureBundle struct {
	Posture inspectionposture.Posture `json:"posture"`
}

// inspectionPostureBundleSection builds the section the control plane publishes, or nil when this node has no
// posture to author — then it is not the authority and must not appear to be one.
func inspectionPostureBundleSection(get func() inspectionposture.Posture) *inspectionPostureBundle {
	if get == nil {
		return nil
	}
	return &inspectionPostureBundle{Posture: get().Normalized()}
}

// applyInspectionPostureBundleSection makes this Edge's posture the control plane's.
//
// It returns whether anything changed, so the caller can log a CHANGE rather than a poll — this is enforcement,
// and "every Edge silently started decrypting a different set" is exactly the event an operator needs in the
// log with a before and an after.
func applyInspectionPostureBundleSection(section *inspectionPostureBundle, current func() inspectionposture.Posture,
	set func(inspectionposture.Posture, string) (inspectionposture.Posture, error),
	logf func(string, ...interface{})) (changed bool, err error) {
	if section == nil {
		return false, nil
	}
	if set == nil || current == nil {
		return false, fmt.Errorf("inspection posture target is unavailable")
	}
	next, err := inspectionposture.Validate(section.Posture)
	if err != nil {
		return false, err
	}
	if inspectionPostureEqual(current(), next) {
		return false, nil
	}
	before := current()
	if _, err := set(next, ""); err != nil {
		// Keep this generation unapplied when the target cannot save it.
		if logf != nil {
			logf("config_bundle_inspection_posture_apply_failed err=%v", err)
		}
		return false, err
	}
	if logf != nil {
		logf("config_bundle_inspection_posture_applied from_mode=%q to_mode=%q from_allowlist=%d to_allowlist=%d",
			before.Mode, next.Mode, len(before.DecryptAllowlistHosts), len(next.DecryptAllowlistHosts))
	}
	return true, nil
}

// inspectionPostureEqual compares two normalized postures. Written out rather than reflect.DeepEqual so a field
// added to Posture without being added here fails a test rather than being silently ignored — a posture that
// travels with one field missing decrypts a different set than the operator chose.
func inspectionPostureEqual(a, b inspectionposture.Posture) bool {
	a, b = a.Normalized(), b.Normalized()
	if a.Mode != b.Mode || a.KnownBypassEnabled != b.KnownBypassEnabled {
		return false
	}
	return stringSlicesEqual(a.DecryptAllowlistHosts, b.DecryptAllowlistHosts) &&
		stringSlicesEqual(a.DecryptAllowlistGroups, b.DecryptAllowlistGroups) &&
		stringSlicesEqual(a.BypassGroups, b.BypassGroups)
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
