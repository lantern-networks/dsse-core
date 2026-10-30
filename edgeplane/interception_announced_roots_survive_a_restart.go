package edgeplane

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lantern-networks/dsse-core/durablefile"
	"github.com/lantern-networks/dsse-core/internal/strictjson"
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
	// A tombstone is authoritative even if a stale retiring PEM survives a
	// failed unlink or a writer that started before withdrawal.
	WithdrawnSHA256 []string `json:"withdrawn_sha256,omitempty"`
}

func announcedRootsPath(dir, tenantID string) string {
	return filepath.Join(dir, interceptionTenantFileKey(tenantID)+".announced-roots.json")
}

func readAnnouncedRoots(dir, tenantID string) (announcedRootsRecord, error) {
	var rec announcedRootsRecord
	if strings.TrimSpace(dir) == "" {
		return rec, nil
	}
	raw, err := os.ReadFile(announcedRootsPath(dir, tenantID))
	if os.IsNotExist(err) {
		return rec, nil
	}
	if err != nil {
		return rec, err
	}
	if err := strictjson.RejectDuplicateKeys(raw); err != nil {
		return rec, err
	}
	if strings.TrimSpace(string(raw)) == "null" {
		return rec, fmt.Errorf("announced roots record is null")
	}
	if err := json.Unmarshal(raw, &rec); err != nil {
		return rec, err
	}
	if rec.CurrentSHA256 == "" && len(rec.WithdrawnSHA256) == 0 {
		return rec, fmt.Errorf("announced roots record has no current root or withdrawal decision")
	}
	all := append(append([]string{}, rec.RetiringSHA256...), rec.WithdrawnSHA256...)
	if rec.CurrentSHA256 != "" {
		all = append(all, rec.CurrentSHA256)
	}
	for _, fp := range all {
		if !validInterceptionFingerprint(fp) {
			return announcedRootsRecord{}, fmt.Errorf("invalid announced root fingerprint")
		}
	}
	return rec, nil
}

func validInterceptionFingerprint(fp string) bool {
	b, err := hex.DecodeString(fp)
	return err == nil && len(b) == 32
}

// recordAnnouncedRoot notes which root this organization is signing under now, and keeps the one it was
// signing under before in the retiring set. Returns the fingerprints that should still be announced besides
// the current one.
//
// ★ IT IS CALLED ON EVERY LOAD, not only on a live replacement. That is the whole point: a restart that finds
// different material is exactly the case the in-memory version could not see.
func recordAnnouncedRoot(dir, tenantID, currentSHA256 string) ([]string, error) {
	return recordAnnouncedRootExcludingRevoked(dir, tenantID, currentSHA256, nil)
}

// recordAnnouncedRootExcludingRevoked is used when a replacement follows a
// compromised authority. A durable revocation must never become a retiring
// announcement merely because it was the current root in an older record.
func recordAnnouncedRootExcludingRevoked(dir, tenantID, currentSHA256 string, revoked map[string]string) ([]string, error) {
	dir = strings.TrimSpace(dir)
	current := strings.ToLower(strings.TrimSpace(currentSHA256))
	if dir == "" || current == "" {
		return nil, nil
	}
	if !validInterceptionFingerprint(current) {
		return nil, fmt.Errorf("invalid current root fingerprint")
	}
	rec, err := readAnnouncedRoots(dir, tenantID)
	if err != nil {
		return nil, fmt.Errorf("read announced roots: %w", err)
	}
	previous := strings.ToLower(strings.TrimSpace(rec.CurrentSHA256))
	withdrawn := map[string]bool{}
	for _, fp := range rec.WithdrawnSHA256 {
		if fp = strings.ToLower(fp); fp != current {
			withdrawn[fp] = true
		}
	}
	retiring := map[string]bool{}
	for _, fp := range rec.RetiringSHA256 {
		fp = strings.ToLower(strings.TrimSpace(fp))
		if _, dead := revoked[fp]; dead {
			withdrawn[fp] = true
		}
		if fp != "" && fp != current && !withdrawn[fp] {
			retiring[fp] = true
		}
	}
	if _, dead := revoked[previous]; dead && previous != current {
		withdrawn[previous] = true
	}
	if previous != "" && previous != current && !withdrawn[previous] {
		retiring[previous] = true
	}
	out := make([]string, 0, len(retiring))
	for fp := range retiring {
		out = append(out, fp)
	}
	sort.Strings(out)
	withdrawnList := make([]string, 0, len(withdrawn))
	for fp := range withdrawn {
		withdrawnList = append(withdrawnList, fp)
	}
	sort.Strings(withdrawnList)
	if previous == current && sameFingerprintSet(out, rec.RetiringSHA256) && sameFingerprintSet(withdrawnList, rec.WithdrawnSHA256) {
		// Nothing moved; do not rewrite a file on every start-up.
		return out, nil
	}
	next := announcedRootsRecord{CurrentSHA256: current, RetiringSHA256: out, WithdrawnSHA256: withdrawnList}
	blob, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create announced roots directory: %w", err)
	}
	if werr := durablefile.Write(announcedRootsPath(dir, tenantID), blob, 0o600); werr != nil {
		return nil, fmt.Errorf("persist announced roots: %w", werr)
	}
	return out, nil
}

// forgetRetiringRoot drops one fingerprint from the record, so a withdrawal outlives the process too.
func forgetRetiringRoot(dir, tenantID, sha256Hex string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil
	}
	target := strings.ToLower(strings.TrimSpace(sha256Hex))
	if !validInterceptionFingerprint(target) {
		return fmt.Errorf("invalid retiring root fingerprint")
	}
	rec, err := readAnnouncedRoots(dir, tenantID)
	if err != nil {
		return err
	}
	if strings.EqualFold(rec.CurrentSHA256, target) {
		return fmt.Errorf("cannot withdraw the current root")
	}
	kept := make([]string, 0, len(rec.RetiringSHA256))
	for _, fp := range rec.RetiringSHA256 {
		if strings.ToLower(strings.TrimSpace(fp)) != target {
			kept = append(kept, fp)
		}
	}
	rec.RetiringSHA256 = kept
	found := false
	for _, fp := range rec.WithdrawnSHA256 {
		if strings.EqualFold(fp, target) {
			found = true
		}
	}
	if !found {
		rec.WithdrawnSHA256 = append(rec.WithdrawnSHA256, target)
	}
	sort.Strings(rec.WithdrawnSHA256)
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
