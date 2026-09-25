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
	mu        sync.Mutex
	seq       int
	endpoints map[string]map[string]Endpoint // tenant -> id -> endpoint
	groups    map[string]map[string]Group    // tenant -> id -> group
	services  map[string]map[string]Service  // tenant -> id -> service
	aliases   map[string]map[string]string   // tenant -> alias -> ownerID (the shared namespace)
	persister blobstore.Persister            // when set, operator-authored entries are persisted here (survive restart)
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
		s.builtInServices[svc.ID] = svc
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
		s.builtInEndpoints[e.ID] = e
	}
	for _, g := range groups {
		g.BuiltIn = true
		s.builtInGroups[g.ID] = g
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

// UpsertEndpoint stores an endpoint, assigning an id if absent and a tenant-unique alias (auto-suffixed on
// collision). Returns the stored endpoint with its resolved id and alias.
func (s *Store) UpsertEndpoint(e Endpoint) (Endpoint, error) {
	return s.upsertEndpoint(e, false, false)
}

// UpsertApplicationEndpoint owns the stable destination used by a published app.
// An existing manual endpoint may only be adopted by an endpoint administrator.
func (s *Store) UpsertApplicationEndpoint(applicationID string, e Endpoint, allowManual bool) (Endpoint, error) {
	applicationID = strings.TrimSpace(applicationID)
	if applicationID == "" {
		return Endpoint{}, fmt.Errorf("application_id is required")
	}
	e.ID, e.Source = "app-"+applicationID, SourceApplication
	return s.upsertEndpoint(e, true, allowManual)
}

func (s *Store) upsertEndpoint(e Endpoint, application, allowManual bool) (Endpoint, error) {
	e.TenantID = strings.TrimSpace(e.TenantID)
	if e.TenantID == "" {
		return Endpoint{}, fmt.Errorf("tenant_id is required")
	}
	if e.Kind != KindSteeredDevice && e.Kind != KindNetwork {
		return Endpoint{}, fmt.Errorf("endpoint kind %q is invalid", e.Kind)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previousSeq := s.seq
	if e.Source == SourceApplication && !application {
		return Endpoint{}, fmt.Errorf("application endpoints are managed by application publish")
	}
	if strings.TrimSpace(e.ID) == "" {
		e.ID = s.nextIDLocked("ep")
	}
	if current, found := s.endpoints[e.TenantID][e.ID]; found {
		if application && current.Source != SourceApplication && !(allowManual && (current.Source == SourceManual || current.Source == "")) {
			return Endpoint{}, fmt.Errorf("admin.endpoints.write is required to replace the existing destination")
		}
		if !application && current.Source == SourceApplication {
			return Endpoint{}, fmt.Errorf("application endpoints are managed by application publish")
		}
	}
	previous, hadPrevious := s.endpoints[e.TenantID][e.ID]
	previousAliases := make(map[string]string, len(s.aliases[e.TenantID]))
	for alias, owner := range s.aliases[e.TenantID] {
		previousAliases[alias] = owner
	}
	e.Alias = s.claimAliasLocked(e.TenantID, e.Alias, e.ID)
	if s.endpoints[e.TenantID] == nil {
		s.endpoints[e.TenantID] = map[string]Endpoint{}
	}
	s.endpoints[e.TenantID][e.ID] = e
	// Enrolled-device endpoints are re-derived from the enrolled inventory on boot, so they do not trigger a
	// persist (avoids per-list churn and stale lingering); only operator-authored endpoints are persisted.
	if e.Source != SourceEnrolled {
		s.generation++
		if err := s.persistLocked(); err != nil {
			if hadPrevious {
				s.endpoints[e.TenantID][e.ID] = previous
			} else {
				delete(s.endpoints[e.TenantID], e.ID)
			}
			s.aliases[e.TenantID] = previousAliases
			s.seq = previousSeq
			s.generation--
			return Endpoint{}, fmt.Errorf("endpoint %s update was not confirmed persisted: %w", e.ID, err)
		}
	}
	return e, nil
}

// UpsertGroup stores a group (static and/or dynamic membership) with a tenant-unique alias.
func (s *Store) UpsertGroup(g Group) (Group, error) {
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
	s.groups[g.TenantID][g.ID] = g
	s.generation++
	if err := s.persistLocked(); err != nil {
		return g, fmt.Errorf("group %s stored in memory but not persisted (will not survive a restart): %w", g.ID, err)
	}
	return g, nil
}

// UpsertService stores a named port/protocol service with a tenant-unique alias.
func (s *Store) UpsertService(svc Service) (Service, error) {
	svc.TenantID = strings.TrimSpace(svc.TenantID)
	if svc.TenantID == "" {
		return Service{}, fmt.Errorf("tenant_id is required")
	}
	if len(svc.Ports) == 0 {
		return Service{}, fmt.Errorf("service requires at least one port")
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
	s.services[svc.TenantID][svc.ID] = svc
	s.generation++
	if err := s.persistLocked(); err != nil {
		return svc, fmt.Errorf("service %s stored in memory but not persisted (will not survive a restart): %w", svc.ID, err)
	}
	return svc, nil
}

// DeleteEndpoint removes an endpoint and frees its alias. Returns false if it was not present. A group that
// still lists the deleted endpoint as a static member resolves gracefully (missing members are skipped).
// A failed snapshot restores the previous in-memory endpoint so a retry can persist the delete.
func (s *Store) DeleteEndpoint(tenant, id string) (bool, error) {
	return s.deleteEndpoint(tenant, id, false, false)
}

// DeleteApplicationEndpoint removes only a destination owned by the application,
// or a legacy manual destination when the caller has endpoint-write permission.
func (s *Store) DeleteApplicationEndpoint(tenant, applicationID string, allowManual bool) (bool, error) {
	applicationID = strings.TrimSpace(applicationID)
	if applicationID == "" {
		return false, fmt.Errorf("application_id is required")
	}
	return s.deleteEndpoint(tenant, "app-"+applicationID, true, allowManual)
}

func (s *Store) deleteEndpoint(tenant, id string, application, allowManual bool) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.builtInEndpoints[id]; ok {
		return false, nil // built-in catalog endpoints are read-only
	}
	previous, ok := s.endpoints[tenant][id]
	if !ok {
		return false, nil
	}
	if application && previous.Source != SourceApplication && !(allowManual && (previous.Source == SourceManual || previous.Source == "")) {
		return false, fmt.Errorf("admin.endpoints.write is required to remove the existing destination")
	}
	if !application && previous.Source == SourceApplication {
		return false, fmt.Errorf("application endpoints are managed by application publish")
	}
	previousAliases := make(map[string]string, len(s.aliases[tenant]))
	for alias, owner := range s.aliases[tenant] {
		previousAliases[alias] = owner
	}
	delete(s.endpoints[tenant], id)
	s.releaseAliasLocked(tenant, id)
	s.generation++
	if err := s.persistLocked(); err != nil {
		s.endpoints[tenant][id] = previous
		s.aliases[tenant] = previousAliases
		s.generation--
		return false, fmt.Errorf("endpoint %s deletion was not confirmed persisted: %w", id, err)
	}
	return true, nil
}

// DeleteGroup removes a group and frees its alias. Returns false if it was not present. Error semantics as
// DeleteEndpoint.
func (s *Store) DeleteGroup(tenant, id string) (bool, error) {
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
	if err := s.persistLocked(); err != nil {
		return true, fmt.Errorf("group %s deleted in memory but not persisted (would resurrect on restart): %w", id, err)
	}
	return true, nil
}

// DeleteService removes a service and frees its alias. Returns false if it was not present. Error semantics
// as DeleteEndpoint.
func (s *Store) DeleteService(tenant, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.services[tenant][id]; !ok {
		return false, nil
	}
	delete(s.services[tenant], id)
	s.releaseAliasLocked(tenant, id)
	s.generation++
	if err := s.persistLocked(); err != nil {
		return true, fmt.Errorf("service %s deleted in memory but not persisted (would resurrect on restart): %w", id, err)
	}
	return true, nil
}

// GetEndpoint returns the endpoint by id for the tenant (or a built-in catalog endpoint).
func (s *Store) GetEndpoint(tenant, id string) (Endpoint, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.endpoints[tenant][id]; ok {
		return e, true
	}
	e, ok := s.builtInEndpoints[id]
	return e, ok
}

// ListEndpoints returns an alias-sorted snapshot for the tenant, including the built-in catalog endpoints.
func (s *Store) ListEndpoints(tenant string) []Endpoint {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Endpoint, 0, len(s.endpoints[tenant])+len(s.builtInEndpoints))
	for _, e := range s.endpoints[tenant] {
		out = append(out, e)
	}
	for _, e := range s.builtInEndpoints {
		out = append(out, e)
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
		out = append(out, g)
	}
	for _, g := range s.builtInGroups {
		out = append(out, g)
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
		out = append(out, svc)
		seen[strings.ToLower(svc.Alias)] = true
	}
	for _, svc := range s.builtInServices {
		if !seen[strings.ToLower(svc.Alias)] {
			out = append(out, svc)
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
