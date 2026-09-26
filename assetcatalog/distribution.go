package assetcatalog

// distribution.go — the catalog's half of making authored policy fleet-wide.
//
// ★ Rules are useless without this, and the way they fail is the dangerous way. An authored rule names
// destinations by ENDPOINT ID, so a rule distributed to an Edge whose catalog lacks those ids resolves to no
// addresses at all. On the egress plane that is inert (a bypass that bypasses nothing). On east-west it is
// worse: an empty selector is treated as a wildcard, so a rule that should have matched one hop matches every
// hop. Distributing rules without the catalog they reference would therefore have converted a silent
// no-op into a silent widening. See docs/authored_policy_reaches_one_edge_not_the_serving_one.md.
//
// Authored entries reconcile as one saved candidate; enrolled-derived and built-in
// entries retain their separate ownership.

import "sort"

// ConfigGeneration returns the monotonic authored-catalog version, bumped on every authored mutation. Folded
// into the config bundle's aggregate generation so adding an endpoint a rule needs triggers a fleet re-pull.
func (s *Store) ConfigGeneration() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

// AuthoredSnapshot returns the AUTHORED entries across all tenants — never the built-ins, which every Edge
// seeds for itself from the same code and which would otherwise be shipped over the wire on every pull only to
// overwrite themselves.
//
// Enrolled-derived endpoints are not filtered out: they are indistinguishable from authored ones in the store,
// they are cheap, and an Edge receiving one it would have derived anyway converges to the same value.
func (s *Store) AuthoredSnapshot() (endpoints []Endpoint, groups []Group, services []Service) {
	s.mu.Lock()
	defer s.mu.Unlock()
	endpoints, groups, services = []Endpoint{}, []Group{}, []Service{}
	for _, byID := range s.endpoints {
		for _, e := range byID {
			endpoints = append(endpoints, copyEndpoint(e))
		}
	}
	for _, byID := range s.groups {
		for _, g := range byID {
			groups = append(groups, copyGroup(g))
		}
	}
	for _, byID := range s.services {
		for _, svc := range byID {
			services = append(services, copyService(svc))
		}
	}
	// Deterministic order so an unchanged catalog serialises identically and does not churn the bundle.
	sort.Slice(endpoints, func(i, j int) bool {
		if endpoints[i].TenantID != endpoints[j].TenantID {
			return endpoints[i].TenantID < endpoints[j].TenantID
		}
		return endpoints[i].ID < endpoints[j].ID
	})
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].TenantID != groups[j].TenantID {
			return groups[i].TenantID < groups[j].TenantID
		}
		return groups[i].ID < groups[j].ID
	})
	sort.Slice(services, func(i, j int) bool {
		if services[i].TenantID != services[j].TenantID {
			return services[i].TenantID < services[j].TenantID
		}
		return services[i].ID < services[j].ID
	})
	return endpoints, groups, services
}

// ReplaceAuthored makes this store's authored catalog equal the control plane's, and is the mirror of
// AuthoredSnapshot: whatever that method exports is exactly what this method takes back.
//
// ★ WHY IT EXISTS (2026-08-11). The config-bundle apply UPSERTED the endpoints, groups and services a bundle
// carried and had no way to remove one. So an authored asset deleted on the control plane — the control plane
// answering `{"status":"deleted"}`, HTTP 200 — stayed on every Edge indefinitely. Verified live: an endpoint
// deleted on the CP was still present on both edges two minutes later, while the CP's own view showed it gone.
//
// That is the shape this tree keeps finding: a write reported as successful, correct in the record, and absent
// where it has to take effect. It is the same defect as rules reaching one Edge, one layer down, and it went
// unnoticed for the ordinary reason — adding an asset works, and nobody deletes one very often.
//
// ENROLLED-DERIVED ENDPOINTS ARE KEPT. Each Edge derives them from the enrolled ledger the bundle also carries,
// so an Edge that removed them for being absent from the incoming set would be deleting its own correct
// derivation and re-adding it on the next ledger pass. Built-ins are untouched for the same reason one layer
// over: they live in their own maps and every Edge seeds them from the same code.
//
// Returns the ids removed, so the caller can NAME them. Authority that erases quietly is how a cutover loses
// policy nobody migrated.
func (s *Store) replaceAuthored(endpoints []Endpoint, groups []Group, services []Service) (removed []string, err error) {
	for _, e := range endpoints {
		if _, uerr := s.upsertEndpoint(e); uerr != nil {
			return nil, uerr
		}
	}
	for _, g := range groups {
		if _, uerr := s.upsertGroup(g); uerr != nil {
			return nil, uerr
		}
	}
	for _, svc := range services {
		if _, uerr := s.upsertService(svc); uerr != nil {
			return nil, uerr
		}
	}

	keepEndpoint := map[string]bool{}
	for _, e := range endpoints {
		keepEndpoint[e.TenantID+"\x00"+e.ID] = true
	}
	keepGroup := map[string]bool{}
	for _, g := range groups {
		keepGroup[g.TenantID+"\x00"+g.ID] = true
	}
	keepService := map[string]bool{}
	for _, svc := range services {
		keepService[svc.TenantID+"\x00"+svc.ID] = true
	}

	type ref struct{ tenant, id string }
	var dropEndpoints, dropGroups, dropServices []ref

	s.mu.Lock()
	for tenant, byID := range s.endpoints {
		for id, e := range byID {
			if e.Source == SourceEnrolled || keepEndpoint[tenant+"\x00"+id] {
				continue
			}
			dropEndpoints = append(dropEndpoints, ref{tenant, id})
		}
	}
	for tenant, byID := range s.groups {
		for id := range byID {
			if !keepGroup[tenant+"\x00"+id] {
				dropGroups = append(dropGroups, ref{tenant, id})
			}
		}
	}
	for tenant, byID := range s.services {
		for id := range byID {
			if !keepService[tenant+"\x00"+id] {
				dropServices = append(dropServices, ref{tenant, id})
			}
		}
	}
	s.mu.Unlock()

	// Candidate deletes share alias release and generation updates with admin mutations.
	// The public transaction wrapper saves the complete reconciliation once.
	for _, r := range dropEndpoints {
		if ok, derr := s.deleteEndpoint(r.tenant, r.id); derr != nil {
			return removed, derr
		} else if ok {
			removed = append(removed, "endpoint:"+r.id)
		}
	}
	for _, r := range dropGroups {
		if ok, derr := s.deleteGroup(r.tenant, r.id); derr != nil {
			return removed, derr
		} else if ok {
			removed = append(removed, "group:"+r.id)
		}
	}
	for _, r := range dropServices {
		if ok, derr := s.deleteService(r.tenant, r.id); derr != nil {
			return removed, derr
		} else if ok {
			removed = append(removed, "service:"+r.id)
		}
	}
	sort.Strings(removed)
	return removed, nil
}
