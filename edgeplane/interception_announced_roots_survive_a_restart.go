package edgeplane

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lantern-networks/dsse-core/durablefile"
)

// interception_announced_roots_survive_a_restart.go — which interception roots an organization is still told
// about after the process that decided it has gone.
//
// ★★★ WHY (2026-08-21, measured while migrating the reference deployment). Replacing an organization's
// issuing authority keeps the OUTGOING root announced, so a device that has not adopted the new one yet still
// verifies. That overlap lived in offlineTenantRetiringRoots — a map in memory, recorded only when
// LoadOfflineTenantIntermediate ran on a LIVE engine.
//
// The procedure an operator actually uses is to replace the files and recreate the Edge. A restarted engine
// has no memory of the previous root, and the same-named files have been overwritten, so there is nothing to
// retire and nothing to announce: the announcement goes straight from the old root to the new one with no
// overlap at all. Measured exactly that on the lab. Nothing broke, because adoption had been measured first —
// but the safety net that was described to the other endpoint was not running, and a device that had missed
// the distribution would have lost every site at that moment.
//
// ★ AND ONLY THE FINGERPRINT IS NEEDED. What a device is told is "look for these roots"; the certificate is
// distributed out of band. So the retiring set is kept as FINGERPRINTS, which means the node can go on
// announcing a root whose certificate it no longer holds — which is precisely the case a file replacement
// creates.
//
// restart-durability: durable — this is the record that makes the overlap outlive the process. It sits beside
// the issuer bundles it describes, so an operator moving those files moves this with them.
type announcedRootsRecord struct {
	CurrentSHA256  string   `json:"current_sha256"`
	RetiringSHA256 []string `json:"retiring_sha256,omitempty"`
}

func announcedRootsPath(dir, tenantID string) string {
	return filepath.Join(dir, strings.ToLower(strings.TrimSpace(tenantID))+".announced-roots.json")
}

func readAnnouncedRoots(dir, tenantID string) announcedRootsRecord {
	var rec announcedRootsRecord
	if strings.TrimSpace(dir) == "" {
		return rec
	}
	raw, err := os.ReadFile(announcedRootsPath(dir, tenantID))
	if err != nil {
		return rec
	}
	_ = json.Unmarshal(raw, &rec)
	return rec
}

// recordAnnouncedRoot notes which root this organization is signing under now, and keeps the one it was
// signing under before in the retiring set. Returns the fingerprints that should still be announced besides
// the current one.
//
// ★ IT IS CALLED ON EVERY LOAD, not only on a live replacement. That is the whole point: a restart that finds
// different material is exactly the case the in-memory version could not see.
func recordAnnouncedRoot(dir, tenantID, currentSHA256 string) []string {
	dir = strings.TrimSpace(dir)
	current := strings.ToLower(strings.TrimSpace(currentSHA256))
	if dir == "" || current == "" {
		return nil
	}
	rec := readAnnouncedRoots(dir, tenantID)
	previous := strings.ToLower(strings.TrimSpace(rec.CurrentSHA256))
	retiring := map[string]bool{}
	for _, fp := range rec.RetiringSHA256 {
		if fp = strings.ToLower(strings.TrimSpace(fp)); fp != "" && fp != current {
			retiring[fp] = true
		}
	}
	if previous != "" && previous != current {
		retiring[previous] = true
	}
	out := make([]string, 0, len(retiring))
	for fp := range retiring {
		out = append(out, fp)
	}
	sort.Strings(out)
	if previous == current && sameFingerprintSet(out, rec.RetiringSHA256) {
		// Nothing moved; do not rewrite a file on every start-up.
		return out
	}
	next := announcedRootsRecord{CurrentSHA256: current, RetiringSHA256: out}
	blob, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return out
	}
	if werr := durablefile.Write(announcedRootsPath(dir, tenantID), blob, 0o600); werr != nil {
		// Said rather than swallowed: without this record the next restart loses the overlap, which is the
		// defect this file exists to fix.
		log.Printf("network_extension_lab_tls WARNING announced_roots_not_recorded tenant=%q err=%v — the "+
			"overlap will not survive a restart, so a device that has not adopted the new root could lose "+
			"every site when this node next starts", tenantID, werr)
	}
	return out
}

// forgetRetiringRoot drops one fingerprint from the record, so a withdrawal outlives the process too.
func forgetRetiringRoot(dir, tenantID, sha256Hex string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil
	}
	target := strings.ToLower(strings.TrimSpace(sha256Hex))
	rec := readAnnouncedRoots(dir, tenantID)
	kept := make([]string, 0, len(rec.RetiringSHA256))
	for _, fp := range rec.RetiringSHA256 {
		if strings.ToLower(strings.TrimSpace(fp)) != target {
			kept = append(kept, fp)
		}
	}
	rec.RetiringSHA256 = kept
	blob, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	if err := durablefile.Write(announcedRootsPath(dir, tenantID), blob, 0o600); err != nil {
		return fmt.Errorf("record the withdrawal so it survives a restart: %w", err)
	}
	return nil
}

func sameFingerprintSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if !strings.EqualFold(strings.TrimSpace(x[i]), strings.TrimSpace(y[i])) {
			return false
		}
	}
	return true
}
