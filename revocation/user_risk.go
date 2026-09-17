package revocation

import (
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
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.loadErr != nil || o.legacy {
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
	o.users = candidate
	o.rebuildUserIndexLocked()
	o.generation.Add(1)
	return warning, nil
}
func (o *HighRiskOverlay) UserSeverity(tenant, subject string) (string, bool) {
	if o == nil {
		return "", false
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	sev, ok := o.userIndex[userRiskKey(strings.TrimSpace(tenant), strings.TrimSpace(subject))]
	return sev, ok
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
	if o.loadErr != nil {
		return o.loadErr
	}
	if o.legacy {
		return fmt.Errorf("legacy risk state requires attribution before serving")
	}
	return nil
}
func (o *HighRiskOverlay) NeedsMigration() bool {
	if o == nil {
		return false
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return o.legacy
}

// MigrateLegacy classifies every old untyped ID before changing anything. The
// resolver must have a complete directory and device inventory. Ambiguous and
// orphaned marks stop the upgrade instead of clearing or copying them to tenants.
func (o *HighRiskOverlay) MigrateLegacy(resolve func(string) (*UserRisk, error)) error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.loadErr != nil {
		return o.loadErr
	}
	if !o.legacy {
		return nil
	}
	devices := map[string]string{}
	users := cloneUserRisks(o.users)
	for id, sev := range o.devices {
		mark, err := resolve(id)
		if err != nil {
			return err
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
	if _, err := o.saveStateLocked(devices, users); err != nil {
		return err
	}
	o.devices = devices
	o.users = users
	o.legacy = false
	o.rebuildUserIndexLocked()
	o.generation.Add(1)
	return nil
}

// ReplaceSyncedUsers accepts only the explicit typed-user feed. A missing field
// from an older authority cannot silently clear risk already held on this node.
func (o *HighRiskOverlay) ReplaceSyncedUsers(marks []UserRisk) error {
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
	o.mu.Lock()
	defer o.mu.Unlock()
	o.users = fresh
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
