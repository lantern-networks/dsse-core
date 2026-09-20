package assetcatalog

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
)

type contextUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

func (s *Store) sharedCandidateLocked(raw []byte) (*Store, error) {
	n := NewStore()
	n.generation = s.generation
	n.builtInEndpoints, n.builtInGroups, n.builtInServices = s.builtInEndpoints, s.builtInGroups, s.builtInServices
	if raw == nil {
		old := s.authoredStateLocked()
		if len(old.Endpoints)+len(old.Groups)+len(old.Services) > 0 {
			return nil, ErrPersistence
		}
	} else {
		var snap persistedCatalog
		if err := json.Unmarshal(raw, &snap); err != nil || snap.Endpoints == nil || snap.Groups == nil || snap.Services == nil || snap.Aliases == nil || snap.Seq < 0 {
			return nil, ErrPersistence
		}
		for tenant, rows := range snap.Endpoints {
			for id, e := range rows {
				if tenant == "" || id == "" || e.TenantID != tenant || e.ID != id || e.Source == SourceEnrolled {
					return nil, ErrPersistence
				}
			}
		}
		for tenant, rows := range snap.Groups {
			for id, g := range rows {
				if tenant == "" || id == "" || g.TenantID != tenant || g.ID != id {
					return nil, ErrPersistence
				}
			}
		}
		for tenant, rows := range snap.Services {
			for id, v := range rows {
				if tenant == "" || id == "" || v.TenantID != tenant || v.ID != id {
					return nil, ErrPersistence
				}
				norm, err := normalizeServiceTransports(v)
				if err != nil {
					return nil, ErrPersistence
				}
				rows[id] = norm
			}
		}
		n.seq, n.endpoints, n.groups, n.services, n.aliases = snap.Seq, snap.Endpoints, snap.Groups, snap.Services, snap.Aliases
	}
	// Enrolled endpoints and their aliases belong to local inventory, not this blob.
	for tenant, rows := range s.endpoints {
		for id, e := range rows {
			if e.Source == SourceEnrolled {
				if n.endpoints[tenant] == nil {
					n.endpoints[tenant] = map[string]Endpoint{}
				}
				if _, exists := n.endpoints[tenant][id]; exists {
					return nil, ErrPersistence
				}
				n.endpoints[tenant][id] = copyEndpoint(e)
			}
		}
	}
	for tenant, rows := range s.aliases {
		for alias, id := range rows {
			if strings.HasPrefix(id, enrolledOwnerPrefix) {
				if n.aliases[tenant] == nil {
					n.aliases[tenant] = map[string]string{}
				}
				if owner, exists := n.aliases[tenant][alias]; exists && owner != id {
					return nil, ErrPersistence
				}
				n.aliases[tenant][alias] = id
			}
		}
	}
	if !reflect.DeepEqual(s.authoredStateLocked(), n.authoredStateLocked()) {
		n.generation++
	}
	return n, nil
}

// RefreshShared refuses unavailable shared authority without replacing the last
// confirmed live catalog. Built-ins and locally enrolled devices are preserved.
func (s *Store) RefreshShared() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.persister.(contextUpdater); !ok {
		return nil
	}
	raw, err := s.persister.Load()
	if err != nil {
		return ErrPersistence
	}
	n, err := s.sharedCandidateLocked(raw)
	if err != nil {
		return ErrPersistence
	}
	s.adoptLocked(n)
	return nil
}
