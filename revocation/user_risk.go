package revocation

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// UserRisk identifies a directory record within one tenant. Subjects are retained
// with the mark so enforcing nodes can match the authenticated subject without a
// directory lookup for each request. They never share the device namespace.
type UserRisk struct {
	TenantID string   `json:"tenant_id"`
	ID       string   `json:"id"`
	Subjects []string `json:"subjects,omitempty"`
	Severity string   `json:"severity"`
}

var ErrRiskSave = errors.New("risk state could not be saved")
var ErrRiskUnavailable = errors.New("risk state is unavailable")
var ErrLegacyUnattributed = errors.New("legacy risk mark cannot be attributed")
var ErrLegacyRiskNotFound = errors.New("unattributed legacy risk mark not found")
var ErrLegacyRiskChanged = errors.New("unattributed legacy risk mark changed")

func userRiskKey(tenant, id string) string { return tenant + "\x00" + id }
func normalizeUserRisk(mark UserRisk) (UserRisk, error) {
	mark.TenantID = strings.TrimSpace(mark.TenantID)
	mark.ID = strings.TrimSpace(mark.ID)
	mark.Severity = strings.ToLower(strings.TrimSpace(mark.Severity))
	if mark.TenantID == "" || mark.ID == "" || strings.ContainsRune(mark.TenantID, '\x00') || strings.ContainsRune(mark.ID, '\x00') {
		return UserRisk{}, fmt.Errorf("risk tenant and user id are required")
	}
	if mark.Severity != "medium" && mark.Severity != "high" && mark.Severity != "critical" && mark.Severity != "none" && mark.Severity != "low" && mark.Severity != "" {
		return UserRisk{}, fmt.Errorf("invalid user risk severity")
	}
	seen := map[string]bool{mark.ID: true}
	subjects := []string{mark.ID}
	for _, s := range mark.Subjects {
		s = strings.TrimSpace(s)
		if s != "" && !strings.ContainsRune(s, '\x00') && !seen[s] {
			subjects = append(subjects, s)
			seen[s] = true
		}
	}
	sort.Strings(subjects)
	mark.Subjects = subjects
	return mark, nil
}
func riskRank(sev string) int {
	switch sev {
	case "medium":
		return 1
	case "high":
		return 2
	case "critical":
		return 3
	}
	return 0
}
func cloneUserRisks(in map[string]UserRisk) map[string]UserRisk {
	out := make(map[string]UserRisk, len(in))
	for k, v := range in {
		v.Subjects = append([]string(nil), v.Subjects...)
		out[k] = v
	}
	return out
}
func (o *HighRiskOverlay) rebuildUserIndexLocked() {
	o.userIndex = map[string]string{}
	for _, mark := range o.users {
		for _, subject := range mark.Subjects {
			k := userRiskKey(mark.TenantID, subject)
			if riskRank(mark.Severity) > riskRank(o.userIndex[k]) {
				o.userIndex[k] = mark.Severity
			}
		}
	}
}

// SetUserRisk saves before publishing. A repeated request also re-saves, so retry
// can recover a previous weak save. The warning reports an already committed save.
func (o *HighRiskOverlay) SetUserRisk(mark UserRisk) (warning bool, err error) {
	if o == nil {
		return false, ErrRiskUnavailable
	}
	mark, err = normalizeUserRisk(mark)
	if err != nil {
		return false, err
	}
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	if o.loadErr != nil || o.legacy || o.deviceSavePending {
		return false, ErrRiskUnavailable
	}
	candidate := cloneUserRisks(o.users)
	key := userRiskKey(mark.TenantID, mark.ID)
	if riskRank(mark.Severity) == 0 {
		delete(candidate, key)
	} else {
		candidate[key] = mark
	}
	warning, err = o.saveStateLocked(o.devices, candidate)
	if err != nil {
		return false, err
	}
	o.mu.Lock()
	o.users = candidate
	o.rebuildUserIndexLocked()
	o.generation.Add(1)
	o.mu.Unlock()
	return warning, nil
}
func (o *HighRiskOverlay) UserSeverity(tenant, subject string) (string, bool) {
	if o == nil {
		return "", false
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	sev, ok := o.userIndex[userRiskKey(strings.TrimSpace(tenant), strings.TrimSpace(subject))]
	if legacy := o.legacyUnattributed[strings.TrimSpace(subject)]; riskRank(legacy) > riskRank(sev) {
		return legacy, true
	}
	return sev, ok
}

// LegacySeverity preserves v1's raw ID match without guessing a tenant or type.
func (o *HighRiskOverlay) LegacySeverity(id string) string {
	if o == nil {
		return ""
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.legacyUnattributed[strings.TrimSpace(id)]
}

func (o *HighRiskOverlay) LegacyUnattributedSnapshot() map[string]string {
	out := map[string]string{}
	if o == nil {
		return out
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	for id, severity := range o.legacyUnattributed {
		out[id] = severity
	}
	return out
}

func (o *HighRiskOverlay) LegacyUnattributedCount() int {
	if o == nil {
		return 0
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.legacyUnattributed)
}

// DiscardLegacyUnattributed is an explicit operator resolution. Ordinary
// device/user clears must not remove an ID whose original type is unknown.
// The expected severity protects an operator against resolving a changed mark.
func (o *HighRiskOverlay) DiscardLegacyUnattributed(id, expectedSeverity string) (bool, error) {
	if o == nil {
		return false, ErrRiskUnavailable
	}
	id = NormalizeDeviceID(id)
	expectedSeverity = strings.ToLower(strings.TrimSpace(expectedSeverity))
	if id == "" || strings.ContainsRune(id, '\x00') || riskRank(expectedSeverity) == 0 {
		return false, fmt.Errorf("legacy risk id and expected severity are required")
	}
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	if o.loadErr != nil || o.legacy || o.deviceSavePending {
		return false, ErrRiskUnavailable
	}
	current, ok := o.legacyUnattributed[id]
	if !ok {
		return false, ErrLegacyRiskNotFound
	}
	if current != expectedSeverity {
		return false, ErrLegacyRiskChanged
	}
	candidate := make(map[string]string, len(o.legacyUnattributed)-1)
	for key, severity := range o.legacyUnattributed {
		if key != id {
			candidate[key] = severity
		}
	}
	warning, err := o.saveStateLocked(o.devices, o.users, candidate)
	if err != nil {
		return false, err
	}
	o.mu.Lock()
	o.legacyUnattributed = candidate
	o.generation.Add(1)
	o.mu.Unlock()
	return warning, nil
}
func (o *HighRiskOverlay) UserSnapshot() []UserRisk {
	out := []UserRisk{}
	if o == nil {
		return out
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	for _, mark := range o.users {
		mark.Subjects = append([]string(nil), mark.Subjects...)
		out = append(out, mark)
	}
	sort.Slice(out, func(i, j int) bool {
		return userRiskKey(out[i].TenantID, out[i].ID) < userRiskKey(out[j].TenantID, out[j].ID)
	})
	return out
}
func (o *HighRiskOverlay) Health() error {
	if o == nil {
		return ErrRiskUnavailable
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.healthLocked()
}
func (o *HighRiskOverlay) healthLocked() error {
	if o.loadErr != nil {
		return o.loadErr
	}
	if o.legacy {
		return fmt.Errorf("legacy risk state requires attribution before serving")
	}
	return nil
}

// CheckedSnapshot returns both namespaces and their availability under one
// lock. An unavailable store must not be presented as an empty, healthy set.
func (o *HighRiskOverlay) CheckedSnapshot() (map[string]string, []UserRisk, error) {
	if o == nil {
		return nil, nil, ErrRiskUnavailable
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	if err := o.healthLocked(); err != nil {
		return nil, nil, ErrRiskUnavailable
	}
	devices := make(map[string]string, len(o.devices))
	for id, severity := range o.devices {
		devices[id] = severity
	}
	users := make([]UserRisk, 0, len(o.users))
	for _, mark := range o.users {
		mark.Subjects = append([]string(nil), mark.Subjects...)
		users = append(users, mark)
	}
	sort.Slice(users, func(i, j int) bool {
		return userRiskKey(users[i].TenantID, users[i].ID) < userRiskKey(users[j].TenantID, users[j].ID)
	})
	return devices, users, nil
}
func (o *HighRiskOverlay) NeedsMigration() bool {
	if o == nil {
		return false
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.legacy
}

// MigrateLegacy classifies proven old IDs and preserves ambiguous ones in a
// separate raw-ID namespace. No tenant or type is guessed and no mark is lost.
func (o *HighRiskOverlay) MigrateLegacy(resolve func(string) (*UserRisk, error)) error {
	if o == nil {
		return nil
	}
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	if o.loadErr != nil {
		return o.loadErr
	}
	if !o.legacy {
		return nil
	}
	devices := map[string]string{}
	users := cloneUserRisks(o.users)
	legacy := map[string]string{}
	for id, sev := range o.devices {
		mark, err := resolve(id)
		if err != nil {
			if !errors.Is(err, ErrLegacyUnattributed) {
				return err
			}
			legacy[id] = sev
			continue
		}
		if mark == nil {
			devices[id] = sev
			continue
		}
		mark.Severity = sev
		normalized, err := normalizeUserRisk(*mark)
		if err != nil {
			return err
		}
		key := userRiskKey(normalized.TenantID, normalized.ID)
		if riskRank(normalized.Severity) > riskRank(users[key].Severity) {
			users[key] = normalized
		}
	}
	if _, err := o.saveStateLocked(devices, users, legacy); err != nil {
		return err
	}
	o.mu.Lock()
	o.devices = devices
	o.users = users
	o.legacyUnattributed = legacy
	o.legacy = false
	o.rebuildUserIndexLocked()
	o.generation.Add(1)
	o.mu.Unlock()
	return nil
}

// ReplaceSyncedUsers accepts only the explicit typed-user feed. A missing field
// from an older authority cannot silently clear risk already held on this node.
func (o *HighRiskOverlay) ReplaceSyncedUsers(marks []UserRisk) error {
	return o.ReplaceSyncedUserRisks(marks, nil)
}

// ReplaceSyncedUserRisks publishes the typed and unresolved v1 namespaces
// together, after validating the entire CP feed.
func (o *HighRiskOverlay) ReplaceSyncedUserRisks(marks []UserRisk, unresolved map[string]string) error {
	if o == nil {
		return nil
	}
	fresh := map[string]UserRisk{}
	for _, mark := range marks {
		n, err := normalizeUserRisk(mark)
		if err != nil || riskRank(n.Severity) == 0 {
			return fmt.Errorf("invalid user risk feed")
		}
		k := userRiskKey(n.TenantID, n.ID)
		if _, ok := fresh[k]; ok {
			return fmt.Errorf("duplicate user risk feed entry")
		}
		fresh[k] = n
	}
	legacy := map[string]string{}
	for id, severity := range unresolved {
		if id == "" || id != NormalizeDeviceID(id) || riskRank(severity) == 0 {
			return fmt.Errorf("invalid legacy risk feed")
		}
		legacy[id] = severity
	}
	o.writeMu.Lock()
	defer o.writeMu.Unlock()
	o.mu.Lock()
	defer o.mu.Unlock()
	o.users = fresh
	o.legacyUnattributed = legacy
	o.rebuildUserIndexLocked()
	return nil
}
func (o *HighRiskOverlay) CountUsers(tenant string) int {
	if o == nil {
		return 0
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	n := 0
	for _, m := range o.users {
		if m.TenantID == tenant {
			n++
		}
	}
	return n
}
func (o *HighRiskOverlay) RemoveUsers(tenant string) (int, error) {
	return o.RemoveTenantRisksChecked(tenant, nil)
}

// UserSeverities returns canonical user IDs and severities for one tenant.
// Decision enrichment does not need the sorted, alias-bearing admin snapshot.
func (o *HighRiskOverlay) UserSeverities(tenant string) map[string]string {
	result := map[string]string{}
	if o == nil {
		return result
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	for _, mark := range o.users {
		if mark.TenantID == tenant {
			result[mark.ID] = mark.Severity
		}
	}
	return result
}

// DiscardLegacyUnattributedContext resolves only the selected raw ID in the
// latest shared snapshot, preserving concurrent changes from other writers.
func (o *HighRiskOverlay) DiscardLegacyUnattributedContext(ctx context.Context, id, expectedSeverity string) (bool, error) {
	id = NormalizeDeviceID(id)
	expectedSeverity = strings.ToLower(strings.TrimSpace(expectedSeverity))
	if id == "" || strings.ContainsRune(id, '\x00') || riskRank(expectedSeverity) == 0 {
		return false, fmt.Errorf("legacy risk id and expected severity are required")
	}
	handled, err := o.changeRiskContextChecked(ctx, func(f *highRiskOverlayStateFile) error {
		current, ok := f.LegacyUnattributed[id]
		if !ok {
			return ErrLegacyRiskNotFound
		}
		if current != expectedSeverity {
			return ErrLegacyRiskChanged
		}
		delete(f.LegacyUnattributed, id)
		return nil
	})
	if !handled {
		return o.DiscardLegacyUnattributed(id, expectedSeverity)
	}
	return false, err
}
