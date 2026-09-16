package assetcatalog

import (
	"errors"
	"fmt"
)

// ErrPersistence means storage did not confirm the candidate. The previous
// live catalog is retained; an ambiguous external commit still needs a reload.
var ErrPersistence = errors.New("asset catalog persistence was not confirmed")

func copyEndpoint(e Endpoint) Endpoint {
	e.Tags = append([]string(nil), e.Tags...)
	return e
}

func copyGroup(g Group) Group {
	g.StaticMembers = append([]string(nil), g.StaticMembers...)
	if g.Dynamic != nil {
		r := *g.Dynamic
		if r.Platform != nil {
			p := *r.Platform
			r.Platform = &p
		}
		if r.Steered != nil {
			p := *r.Steered
			r.Steered = &p
		}
		g.Dynamic = &r
	}
	return g
}

func copyService(s Service) Service {
	s.Ports = append([]PortProto(nil), s.Ports...)
	return s
}

// The caller holds the live store lock. Built-ins are immutable for the entire
// transaction; mutable authored maps and slices belong only to this candidate.
func (s *Store) candidateLocked() *Store {
	n := NewStore()
	n.seq, n.generation = s.seq, s.generation
	n.builtInEndpoints, n.builtInGroups, n.builtInServices = s.builtInEndpoints, s.builtInGroups, s.builtInServices
	for tenant, entries := range s.endpoints {
		n.endpoints[tenant] = map[string]Endpoint{}
		for id, e := range entries {
			n.endpoints[tenant][id] = copyEndpoint(e)
		}
	}
	for tenant, entries := range s.groups {
		n.groups[tenant] = map[string]Group{}
		for id, g := range entries {
			n.groups[tenant][id] = copyGroup(g)
		}
	}
	for tenant, entries := range s.services {
		n.services[tenant] = map[string]Service{}
		for id, svc := range entries {
			n.services[tenant][id] = copyService(svc)
		}
	}
	for tenant, entries := range s.aliases {
		n.aliases[tenant] = map[string]string{}
		for alias, owner := range entries {
			n.aliases[tenant][alias] = owner
		}
	}
	return n
}

func (s *Store) adoptLocked(n *Store) {
	s.seq, s.generation = n.seq, n.generation
	s.endpoints, s.groups, s.services, s.aliases = n.endpoints, n.groups, n.services, n.aliases
}

func mutateCatalog[T any](s *Store, apply func(*Store) (T, error)) (T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.candidateLocked()
	result, err := apply(n)
	if err != nil {
		var zero T
		return zero, err
	}
	if n.generation == s.generation {
		return result, nil
	} // absent delete
	n.persister = s.persister
	if err := n.persistLocked(); err != nil {
		var zero T
		return zero, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	s.adoptLocked(n)
	return result, nil
}

func (s *Store) UpsertEndpoint(e Endpoint) (Endpoint, error) {
	e = copyEndpoint(e)
	if e.Source == SourceEnrolled {
		return s.upsertEndpoint(e)
	}
	return mutateCatalog(s, func(n *Store) (Endpoint, error) { return n.upsertEndpoint(e) })
}

func (s *Store) UpsertGroup(g Group) (Group, error) {
	g = copyGroup(g)
	return mutateCatalog(s, func(n *Store) (Group, error) { return n.upsertGroup(g) })
}

func (s *Store) UpsertService(svc Service) (Service, error) {
	svc = copyService(svc)
	return mutateCatalog(s, func(n *Store) (Service, error) { return n.upsertService(svc) })
}

func (s *Store) DeleteEndpoint(tenant, id string) (bool, error) {
	return mutateCatalog(s, func(n *Store) (bool, error) { return n.deleteEndpoint(tenant, id) })
}

func (s *Store) DeleteGroup(tenant, id string) (bool, error) {
	return mutateCatalog(s, func(n *Store) (bool, error) { return n.deleteGroup(tenant, id) })
}

func (s *Store) DeleteService(tenant, id string) (bool, error) {
	return mutateCatalog(s, func(n *Store) (bool, error) { return n.deleteService(tenant, id) })
}

func (s *Store) ReplaceAuthored(endpoints []Endpoint, groups []Group, services []Service) ([]string, error) {
	return mutateCatalog(s, func(n *Store) ([]string, error) {
		removed, err := n.replaceAuthored(endpoints, groups, services)
		if err == nil {
			n.generation++
		} // includes enrolled-only changes or empty reconciliation
		return removed, err
	})
}
