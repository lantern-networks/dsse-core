package assetcatalog

import (
	"context"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/blobstore"
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
		if len(old.Endpoints)+len(old.Groups)+len(old.Services)+len(old.EnrolledAliases) > 0 {
			return nil, ErrPersistence
		}
	} else {
		var snap persistedCatalog
		if err := json.Unmarshal(raw, &snap); err != nil || snap.Endpoints == nil || snap.Groups == nil || snap.Services == nil || snap.Aliases == nil || snap.Seq < 0 {
			return nil, ErrPersistence
		}
		if snap.Generation > n.generation {
			n.generation = snap.Generation
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
				rows[id] = loadServiceTransports(v)
			}
		}
		for tenant, rows := range snap.EnrolledAliases {
			for id, alias := range rows {
				if tenant == "" || !strings.HasPrefix(id, enrolledOwnerPrefix) || strings.TrimSpace(alias) == "" || snap.Aliases[tenant][alias] != id {
					return nil, ErrPersistence
				}
			}
		}
		if snap.EnrolledAliases != nil {
			n.enrolledAliases = snap.EnrolledAliases
		}
		n.seq, n.endpoints, n.groups, n.services, n.aliases = snap.Seq, snap.Endpoints, snap.Groups, snap.Services, snap.Aliases
	}
	// Identity remains inventory-owned. Overlay confirmed operator aliases while
	// rebuilding the local inventory view; default names do not reserve shared state.
	for tenant, rows := range s.endpoints {
		for id, e := range rows {
			if e.Source == SourceEnrolled {
				if n.endpoints[tenant] == nil {
					n.endpoints[tenant] = map[string]Endpoint{}
				}
				if _, exists := n.endpoints[tenant][id]; exists {
					return nil, ErrPersistence
				}
				if alias, ok := n.enrolledAliases[tenant][id]; ok {
					e.Alias = alias
				}
				e.Alias = n.claimAliasLocked(tenant, e.Alias, id)
				n.endpoints[tenant][id] = copyEndpoint(e)
			}
		}
	}
	before, after := s.authoredStateLocked(), n.authoredStateLocked()
	before.Seq, after.Seq = 0, 0
	before.Generation, after.Generation = 0, 0
	if n.generation <= s.generation && !reflect.DeepEqual(before, after) {
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
	if _, ok := catalogUpdater(s.persister); !ok {
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

// Older adapters expose the same atomic transaction without a context argument.
type legacyCatalogUpdater interface {
	Update(func([]byte) ([]byte, error)) error
}
type catalogUpdaterAdapter struct{ legacyCatalogUpdater }

func (a catalogUpdaterAdapter) UpdateContext(ctx context.Context, f func([]byte) ([]byte, error)) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return a.Update(f)
}
func catalogUpdater(p blobstore.Persister) (contextUpdater, bool) {
	if v, ok := p.(contextUpdater); ok {
		return v, true
	}
	if v, ok := p.(legacyCatalogUpdater); ok {
		return catalogUpdaterAdapter{v}, true
	}
	return nil, false
}
