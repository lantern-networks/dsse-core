package enrolledinventory

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Group is a first-class device group: a named, creatable scope object (the REGISTRY). It is distinct from
// Entry.Group (the per-device assignment string): the registry is the authoritative catalog of groups that
// EXIST, so the Console offers created groups for tab-select assignment instead of free-form typing. `ID` is
// stable across renames; `Name` is the display/label and the value a device assignment references today.
type Group struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id,omitempty"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Risk        string `json:"risk,omitempty"` // "" | medium | high | critical (matches the device-row vocabulary)
	CreatedAt   string `json:"created_at,omitempty"`
	UpdatedAt   string `json:"updated_at,omitempty"`
}

// NormalizeGroupName is the uniqueness key for group names (trim + casefold). Table-stakes normalization that
// folds the SPELLING VARIANTS free-form entry produced (finance / Finance / "finance ").
func NormalizeGroupName(name string) string { return strings.ToLower(strings.TrimSpace(name)) }

// sameGroupTenant reports whether two tenant ids denote the same tenant scope (trim + casefold). Used to scope
// the name-uniqueness invariant and the risk-floor lookup PER TENANT: multi-tenancy is a system premise, so two
// DIFFERENT tenants may each own a group named "finance" without colliding, and a device's floor must resolve
// within its OWN tenant (never another tenant's same-named group). Empty == empty (the unscoped/legacy case).
func sameGroupTenant(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func newGroupID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Never fall back to a fixed id (it would collide). Surface the error so CreateGroup fails cleanly.
		return "", fmt.Errorf("generate group id: %w", err)
	}
	return "dg_" + hex.EncodeToString(b[:]), nil
}

// CreateGroup adds a new group to the registry. `name` is required and must be unique (normalized) WITHIN THE
// TENANT — a different tenant may hold a group with the same name (multi-tenant premise). Returns the created
// group, or an error on empty / duplicate name.
func (l *Ledger) CreateGroup(name, tenantID, description, risk, now string) (Group, error) {
	n := strings.TrimSpace(name)
	if n == "" {
		return Group{}, fmt.Errorf("group name is required")
	}
	key := NormalizeGroupName(n)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.groups == nil {
		l.groups = map[string]Group{}
	}
	for _, g := range l.groups {
		if sameGroupTenant(g.TenantID, tenantID) && NormalizeGroupName(g.Name) == key {
			return Group{}, fmt.Errorf("a group named %q already exists", n)
		}
	}
	id, err := newGroupID()
	if err != nil {
		return Group{}, err
	}
	g := Group{
		ID:          id,
		TenantID:    strings.TrimSpace(tenantID),
		Name:        n,
		Description: strings.TrimSpace(description),
		Risk:        strings.TrimSpace(risk),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	l.groups[g.ID] = g
	l.generation.Add(1) // registry is part of the durable config surface; advance so a re-pull sees it
	return g, l.persistCheckedLocked()
}

// ListGroups returns the registry sorted by name (stable response).
func (l *Ledger) ListGroups() []Group {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Group, 0, len(l.groups))
	for _, g := range l.groups {
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// ReplaceAllGroups atomically replaces the WHOLE device-group registry with the given groups (config
// distribution: a config-pulling Edge swaps in the control plane's authoritative registry, mirroring
// ReplaceAll for entries). Groups with an empty id are skipped; an empty slice empties the registry. Bumps the
// generation + persists.
func (l *Ledger) ReplaceAllGroups(groups []Group, now string) {
	if l == nil {
		return
	}
	fresh := make(map[string]Group, len(groups))
	for _, g := range groups {
		if strings.TrimSpace(g.ID) == "" {
			continue
		}
		if strings.TrimSpace(g.UpdatedAt) == "" {
			g.UpdatedAt = now
		}
		fresh[g.ID] = g
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.groups = fresh
	l.generation.Add(1)
	l.persistLocked()
}

// GroupRiskByName returns the risk floor of the group with the given (case-insensitive) name WITHIN the given
// tenant, or "" if no such group / no risk set. Scoping by tenant is required under the multi-tenant premise: two
// tenants may each own a "finance" group with different floors, so a device's floor MUST resolve against its own
// tenant's group — never another tenant's same-named group. Used to resolve a device's group risk floor for
// effective-risk = max(device, group).
func (l *Ledger) GroupRiskByName(tenantID, name string) string {
	if l == nil {
		return ""
	}
	key := NormalizeGroupName(name)
	if key == "" {
		return ""
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, g := range l.groups {
		if sameGroupTenant(g.TenantID, tenantID) && NormalizeGroupName(g.Name) == key {
			return g.Risk
		}
	}
	return ""
}

// GroupRiskForDevice resolves the risk floor for an enrolled device: its assigned group's floor, looked up WITHIN
// the device's OWN tenant (the entry's TenantID), or "" if the device is unknown / unassigned / the group carries
// no floor. Resolving against the entry's own tenant — not the caller's request tenant — is what guarantees a
// device can never inherit another tenant's same-named group floor under the multi-tenant premise. This is the
// production floor-resolution entry point (the decision path); GroupRiskByName is the lower-level by-name query.
func (l *Ledger) GroupRiskForDevice(deviceID string) string {
	if l == nil {
		return ""
	}
	k := NormalizeIdentity(deviceID)
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[k]
	if !ok {
		return ""
	}
	key := NormalizeGroupName(e.Group)
	if key == "" {
		return ""
	}
	for _, g := range l.groups {
		if sameGroupTenant(g.TenantID, e.TenantID) && NormalizeGroupName(g.Name) == key {
			return g.Risk
		}
	}
	return ""
}

// UpdateGroup applies a PARTIAL update (PATCH) to the registry group with the given id. Each of name /
// description / risk is a pointer: nil leaves that field unchanged; a non-nil value sets it. The id is
// immutable. A rename is validated for the normalized-name uniqueness invariant (a collision with a
// DIFFERENT group is rejected) and then CASCADES to member devices: because a device assignment references the
// group by NAME today (Entry.Group), every entry whose assignment matches the old name is re-pointed to the new
// name so the assignment — and the name-keyed risk floor (GroupRiskByName) — stay attached. (Migrating
// assignments to id references is future work; until then the cascade keeps rename lossless.) Returns the
// updated group, the number of device assignments re-pointed by a rename, and an error on absent id / empty new
// name / name collision. Bumps the generation + persists once.
func (l *Ledger) UpdateGroup(id string, name, description, risk *string, now string) (Group, int, error) {
	key := strings.TrimSpace(id)
	l.mu.Lock()
	defer l.mu.Unlock()
	g, ok := l.groups[key]
	if !ok {
		return Group{}, 0, fmt.Errorf("device group %q not found", id)
	}
	oldName := g.Name
	reassigned := 0
	if name != nil {
		n := strings.TrimSpace(*name)
		if n == "" {
			return Group{}, 0, fmt.Errorf("group name is required")
		}
		newKey := NormalizeGroupName(n)
		for otherID, other := range l.groups {
			if otherID == key {
				continue
			}
			// Collision only within the SAME tenant — a same-named group owned by a different tenant is fine.
			if sameGroupTenant(other.TenantID, g.TenantID) && NormalizeGroupName(other.Name) == newKey {
				return Group{}, 0, fmt.Errorf("a group named %q already exists", n)
			}
		}
		// Cascade the rename to member device assignments (assignment is by normalized name today). SCOPE the
		// cascade to devices in the SAME tenant as the group: assignment is name-keyed and a name is only unique
		// within a tenant, so an un-scoped cascade would rewrite a DIFFERENT tenant's identically-named-group
		// members and (because the floor resolves per tenant) silently drop their group risk floor — a
		// cross-tenant corruption + fail-open. Only this group's tenant is affected.
		if NormalizeGroupName(oldName) != newKey {
			oldKey := NormalizeGroupName(oldName)
			for eid, e := range l.entries {
				if sameGroupTenant(e.TenantID, g.TenantID) && NormalizeGroupName(e.Group) == oldKey {
					e.Group = n
					e.UpdatedAt = now
					l.entries[eid] = e
					reassigned++
				}
			}
		}
		g.Name = n
	}
	if description != nil {
		g.Description = strings.TrimSpace(*description)
	}
	if risk != nil {
		g.Risk = strings.TrimSpace(*risk)
	}
	g.UpdatedAt = now
	l.groups[key] = g
	l.generation.Add(1)
	return g, reassigned, l.persistCheckedLocked()
}

// GroupByID returns the registry group with the given id, or ok=false if absent.
func (l *Ledger) GroupByID(id string) (Group, bool) {
	if l == nil {
		return Group{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	g, ok := l.groups[strings.TrimSpace(id)]
	return g, ok
}

// DeleteGroup removes a group from the registry by id. Returns false if absent. Device assignments that
// reference the name are intentionally left as-is (they fall back to an unregistered label until reassigned);
// the API layer decides whether to refuse or force when a group is still referenced.
// ★ IT REPORTS WHETHER THE DELETION LASTED (2026-08-13, thirty-first review #8). This used the best-effort
// seam, so an administrator removing a group was told it was gone while the durable save failed silently — and
// the next control-plane restart brought the group, and every device's membership of it, back.
func (l *Ledger) DeleteGroup(id string) (bool, error) {
	key := strings.TrimSpace(id)
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.groups[key]; !ok {
		return false, nil
	}
	delete(l.groups, key)
	l.generation.Add(1)
	return true, l.persistCheckedLocked()
}
