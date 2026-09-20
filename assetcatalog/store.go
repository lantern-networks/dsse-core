package assetcatalog

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Store is an in-memory catalog of endpoints, groups, and services for one or more tenants, with a shared
// per-tenant alias namespace (so an alias is unique across all three kinds). Methods are safe for
// concurrent use. The admin API persists/serves it; the proprietary Console reads/writes through that API.
type Store struct {
	mu              sync.Mutex
	seq             int
	endpoints       map[string]map[string]Endpoint // tenant -> id -> endpoint
	groups          map[string]map[string]Group    // tenant -> id -> group
	services        map[string]map[string]Service  // tenant -> id -> service
	aliases         map[string]map[string]string   // tenant -> alias -> ownerID (the shared namespace)
	enrolledAliases map[string]map[string]string   // tenant -> inventory ID -> operator alias; never identity
	persister       blobstore.Persister            // when set, operator-authored entries are persisted here (survive restart)
	// builtInEndpoints / builtInGroups are the shipped SaaS catalog presented as endpoint groups: tenant-
	// agnostic, read-only, NOT persisted (re-seeded from code each boot), not deletable. They are unioned into
	// List/Get/Resolve so a rule can reference a catalog group and the engine resolves it to the host patterns.
	builtInEndpoints map[string]Endpoint
	builtInGroups    map[string]Group
	// builtInServices are shipped well-known services (SSH/RDP/SMB/HTTPS/…): tenant-agnostic, read-only, not
	// persisted, not deletable; unioned into ListServices so every tenant has them without hand-registering.
	builtInServices map[string]Service
	// generation is bumped on every AUTHORED mutation so a control plane can advertise "the catalog changed".
	// See distribution.go — a rule is meaningless on an Edge whose catalog lacks the ids it names.
	generation uint64
}

func NewStore() *Store {
	return &Store{
		endpoints:        map[string]map[string]Endpoint{},
		enrolledAliases:  map[string]map[string]string{},
		groups:           map[string]map[string]Group{},
		services:         map[string]map[string]Service{},
		aliases:          map[string]map[string]string{},
		builtInEndpoints: map[string]Endpoint{},
		builtInGroups:    map[string]Group{},
		builtInServices:  map[string]Service{},
	}
}

// SetBuiltInServices installs the shipped well-known services as read-only built-ins (tenant-agnostic).
// Replaces any previous set. Unioned into ListServices; a tenant-authored service with the same alias shadows
// the built-in. Never persisted, never deletable.
func (s *Store) SetBuiltInServices(services []Service) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.builtInServices = map[string]Service{}
	for _, svc := range services {
		svc.BuiltIn = true
		s.builtInServices[svc.ID] = copyService(svc)
	}
}

// SetBuiltInCatalog installs the shipped SaaS catalog as read-only built-in endpoints + groups (tenant-
// agnostic). Replaces any previous built-in set. Built-ins are never persisted and never deletable; they are
// unioned into List/Get/Resolve so a rule's destination can be a catalog group and resolve to its host patterns.
func (s *Store) SetBuiltInCatalog(endpoints []Endpoint, groups []Group) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.builtInEndpoints = map[string]Endpoint{}
	s.builtInGroups = map[string]Group{}
	for _, e := range endpoints {
		e.BuiltIn = true
		s.builtInEndpoints[e.ID] = copyEndpoint(e)
	}
	for _, g := range groups {
		g.BuiltIn = true
		s.builtInGroups[g.ID] = copyGroup(g)
	}
}

func (s *Store) nextIDLocked(prefix string) string {
	s.seq++
	return prefix + "-" + strconv.Itoa(s.seq)
}

// releaseAliasLocked frees any alias currently owned by ownerID (so an update can re-claim or rename).
func (s *Store) releaseAliasLocked(tenant, ownerID string) {
	for a, owner := range s.aliases[tenant] {
		if owner == ownerID {
			delete(s.aliases[tenant], a)
		}
	}
}

// claimAliasLocked reserves a tenant-unique alias for ownerID (auto-suffixed on collision) and records it.
func (s *Store) claimAliasLocked(tenant, desired, ownerID string) string {
	s.releaseAliasLocked(tenant, ownerID)
	a := s.uniqueAliasLocked(tenant, desired, ownerID)
	if s.aliases[tenant] == nil {
		s.aliases[tenant] = map[string]string{}
	}
	s.aliases[tenant][a] = ownerID
	return a
}

// These helpers mutate an isolated candidate. The public wrappers persist and
// publish it atomically. Enrolled-derived endpoints alone update volatile state.
// Alias allocation and validation are shared with batch reconciliation.
func (s *Store) upsertEndpoint(e Endpoint) (Endpoint, error) {
	e.TenantID = strings.TrimSpace(e.TenantID)
	if e.TenantID == "" {
		return Endpoint{}, fmt.Errorf("tenant_id is required")
	}
	if e.Kind != KindSteeredDevice && e.Kind != KindNetwork {
		return Endpoint{}, fmt.Errorf("endpoint kind %q is invalid", e.Kind)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.upsertEndpointLocked(e)
}

func (s *Store) upsertEndpointLocked(e Endpoint) (Endpoint, error) {
	if strings.TrimSpace(e.ID) == "" {
		e.ID = s.nextIDLocked("ep")
	}
	e.Alias = s.claimAliasLocked(e.TenantID, e.Alias, e.ID)
	if s.endpoints[e.TenantID] == nil {
		s.endpoints[e.TenantID] = map[string]Endpoint{}
	}
	s.endpoints[e.TenantID][e.ID] = copyEndpoint(e)
	// Enrolled-device endpoints are re-derived from the enrolled inventory on boot, so they do not trigger a
	// persist (avoids per-list churn and stale lingering); only operator-authored endpoints are persisted.
	if e.Source != SourceEnrolled {
		s.generation++
	}
	return e, nil
}

// UpsertGroup stores a group (static and/or dynamic membership) with a tenant-unique alias.
func (s *Store) upsertGroup(g Group) (Group, error) {
	g.TenantID = strings.TrimSpace(g.TenantID)
	if g.TenantID == "" {
		return Group{}, fmt.Errorf("tenant_id is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(g.ID) == "" {
		g.ID = s.nextIDLocked("grp")
	}
	g.Alias = s.claimAliasLocked(g.TenantID, g.Alias, g.ID)
	if s.groups[g.TenantID] == nil {
		s.groups[g.TenantID] = map[string]Group{}
	}
	s.groups[g.TenantID][g.ID] = copyGroup(g)
	s.generation++
	return g, nil
}

// UpsertService stores a named port/protocol service with a tenant-unique alias.
func (s *Store) upsertService(svc Service) (Service, error) {
	svc.TenantID = strings.TrimSpace(svc.TenantID)
	if svc.TenantID == "" {
		return Service{}, fmt.Errorf("tenant_id is required")
	}
	var err error
	svc, err = normalizeServiceTransports(svc)
	if err != nil {
		return Service{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.TrimSpace(svc.ID) == "" {
		svc.ID = s.nextIDLocked("svc")
	}
	svc.Alias = s.claimAliasLocked(svc.TenantID, svc.Alias, svc.ID)
	if s.services[svc.TenantID] == nil {
		s.services[svc.TenantID] = map[string]Service{}
	}
	s.services[svc.TenantID][svc.ID] = copyService(svc)
	s.generation++
	return svc, nil
}

// DeleteEndpoint removes an endpoint and frees its alias. Returns false if it was not present. A group that
// still lists the deleted endpoint as a static member resolves gracefully (missing members are skipped).
// Public mutations publish this candidate only after persistence succeeds.
func (s *Store) deleteEndpoint(tenant, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.builtInEndpoints[id]; ok {
		return false, nil // built-in catalog endpoints are read-only
	}
	if _, ok := s.endpoints[tenant][id]; !ok {
		return false, nil
	}
	delete(s.endpoints[tenant], id)
	s.releaseAliasLocked(tenant, id)
	s.generation++
	return true, nil
}

// DeleteGroup removes a group and frees its alias. Returns false if it was not present. Error semantics as
// DeleteEndpoint.
func (s *Store) deleteGroup(tenant, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.builtInGroups[id]; ok {
		return false, nil // built-in catalog groups are read-only
	}
	if _, ok := s.groups[tenant][id]; !ok {
		return false, nil
	}
	delete(s.groups[tenant], id)
	s.releaseAliasLocked(tenant, id)
	s.generation++
	return true, nil
}

// DeleteService removes a service and frees its alias. Returns false if it was not present. Error semantics
// as DeleteEndpoint.
func (s *Store) deleteService(tenant, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.services[tenant][id]; !ok {
		return false, nil
	}
	delete(s.services[tenant], id)
	s.releaseAliasLocked(tenant, id)
	s.generation++
	return true, nil
}

// GetEndpoint returns the endpoint by id for the tenant (or a built-in catalog endpoint).
func (s *Store) GetEndpoint(tenant, id string) (Endpoint, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.endpoints[tenant][id]; ok {
		return copyEndpoint(e), true
	}
	e, ok := s.builtInEndpoints[id]
	return copyEndpoint(e), ok
}

// ListEndpoints returns an alias-sorted snapshot for the tenant, including the built-in catalog endpoints.
func (s *Store) ListEndpoints(tenant string) []Endpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Endpoint, 0, len(s.endpoints[tenant])+len(s.builtInEndpoints))
	for _, e := range s.endpoints[tenant] {
		out = append(out, copyEndpoint(e))
	}
	for _, e := range s.builtInEndpoints {
		out = append(out, copyEndpoint(e))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out
}

// ListGroups returns an alias-sorted snapshot for the tenant, including the built-in catalog groups.
func (s *Store) ListGroups(tenant string) []Group {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Group, 0, len(s.groups[tenant])+len(s.builtInGroups))
	for _, g := range s.groups[tenant] {
		out = append(out, copyGroup(g))
	}
	for _, g := range s.builtInGroups {
		out = append(out, copyGroup(g))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out
}

// ListServices returns an alias-sorted snapshot for the tenant.
func (s *Store) ListServices(tenant string) []Service {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Service, 0, len(s.services[tenant])+len(s.builtInServices))
	seen := map[string]bool{} // lowercased alias -> a tenant-authored service shadows a built-in of the same name
	for _, svc := range s.services[tenant] {
		out = append(out, copyService(svc))
		seen[strings.ToLower(svc.Alias)] = true
	}
	for _, svc := range s.builtInServices {
		if !seen[strings.ToLower(svc.Alias)] {
			out = append(out, copyService(svc))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Alias < out[j].Alias })
	return out
}

// ResolveGroupMembers returns the endpoint ids in a group: its static members (that still exist) plus any
// endpoint matching the group's dynamic membership rule. The result is sorted and deduplicated.
func (s *Store) ResolveGroupMembers(tenant, groupID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Built-in catalog group: its static members are built-in endpoint ids.
	if bg, ok := s.builtInGroups[groupID]; ok {
		set := map[string]bool{}
		for _, id := range bg.StaticMembers {
			if _, exists := s.builtInEndpoints[id]; exists {
				set[id] = true
			}
		}
		out := make([]string, 0, len(set))
		for id := range set {
			out = append(out, id)
		}
		sort.Strings(out)
		return out
	}
	g, ok := s.groups[tenant][groupID]
	if !ok {
		return nil
	}
	set := map[string]bool{}
	for _, id := range g.StaticMembers {
		if _, exists := s.endpoints[tenant][id]; exists {
			set[id] = true
		}
	}
	if g.Dynamic != nil {
		for id, e := range s.endpoints[tenant] {
			if endpointMatchesRule(e, *g.Dynamic) {
				set[id] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
