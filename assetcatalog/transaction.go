package assetcatalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/lantern-networks/dsse-core/blobstore"
	"net/netip"
	"regexp"
)

// ErrPersistence means storage did not confirm the candidate. The previous
// live catalog is retained unless a file replacement is known to have completed.
// An ambiguous external commit still needs a reload.
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
	for tenant, rows := range s.enrolledAliases {
		n.enrolledAliases[tenant] = map[string]string{}
		for id, alias := range rows {
			n.enrolledAliases[tenant][id] = alias
		}
	}
	return n
}

func (s *Store) adoptLocked(n *Store) {
	s.seq, s.generation = n.seq, n.generation
	s.endpoints, s.groups, s.services, s.aliases = n.endpoints, n.groups, n.services, n.aliases
	s.enrolledAliases = n.enrolledAliases
}

func mutateCatalog[T any](s *Store, apply func(*Store) (T, error)) (T, error) {
	return mutateCatalogContext(context.Background(), s, apply)
}
func mutateCatalogContext[T any](ctx context.Context, s *Store, apply func(*Store) (T, error)) (T, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := catalogUpdater(s.persister); ok {
		var n *Store
		var result T
		var validation error
		err := p.UpdateContext(ctx, func(raw []byte) ([]byte, error) {
			var err error
			n, err = s.sharedCandidateLocked(raw)
			if err != nil {
				return nil, err
			}
			result, validation = apply(n)
			if validation != nil {
				return nil, validation
			}
			return json.Marshal(n.authoredStateLocked())
		})
		if validation != nil {
			return result, validation
		}
		if err != nil {
			var zero T
			return zero, ErrPersistence
		}
		s.adoptLocked(n)
		return result, nil
	}
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
		if errors.Is(err, blobstore.ErrDurabilityUnconfirmed) {
			s.adoptLocked(n)
		}
		var zero T
		return zero, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	s.adoptLocked(n)
	return result, nil
}

func (s *Store) UpsertEndpoint(e Endpoint) (Endpoint, error) {
	if e.Source == SourceEnrolled {
		return s.upsertEndpoint(copyEndpoint(e))
	} // trusted inventory/legacy callers
	return s.UpsertEndpointContext(context.Background(), e)
}
func (s *Store) UpsertEndpointContext(ctx context.Context, e Endpoint) (Endpoint, error) {
	e = copyEndpoint(e)
	return mutateCatalogContext(ctx, s, func(n *Store) (Endpoint, error) {
		current, found := n.GetEndpoint(e.TenantID, e.ID)
		if certPinEndpoint(e) || found && certPinEndpoint(current) {
			return Endpoint{}, ErrCertPinEndpointOwnership
		}
		if e.Source == SourceApplication || found && current.Source == SourceApplication {
			return Endpoint{}, ErrApplicationEndpointOwnership
		}
		if e.Source == SourceEnrolled || strings.HasPrefix(e.ID, enrolledOwnerPrefix) || found && current.Source == SourceEnrolled {
			if !found || current.Source != SourceEnrolled || current.ID != enrolledEndpointID(current.Identity) {
				return Endpoint{}, fmt.Errorf("enrolled endpoint must come from inventory")
			}
			desired := e.Alias
			e.Alias = current.Alias
			if !reflect.DeepEqual(e, current) {
				return Endpoint{}, fmt.Errorf("only the enrolled endpoint name may be changed")
			}
			e.Alias = desired
			saved, err := n.upsertEndpoint(e)
			if err != nil {
				return Endpoint{}, err
			}
			if n.enrolledAliases[e.TenantID] == nil {
				n.enrolledAliases[e.TenantID] = map[string]string{}
			}
			n.enrolledAliases[e.TenantID][e.ID] = saved.Alias
			n.generation++
			return saved, nil
		}
		// An address an administrator types is checked when it is new or changed. A record that already holds
		// something else can still be renamed.
		if e.Kind == KindNetwork && strings.TrimSpace(e.Address) != "" && (!found || current.Address != e.Address) {
			if err := ValidateNetworkAddress(e.Address); err != nil {
				return Endpoint{}, err
			}
		}
		return n.upsertEndpoint(e)
	})
}

// networkNamePattern is a host name, optionally a wildcard for the names beneath it.
var networkNamePattern = regexp.MustCompile(`^(\*\.)?([A-Za-z0-9_]([A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)*[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$`)

// ValidateNetworkAddress accepts what a rule can match a destination by: an IP address, a network range, a
// host name, or a wildcard for the names beneath one. Anything else — a sentence, a URL, a name with a port
// — used to be stored as it was typed and produced a destination no flow could ever be.
func ValidateNetworkAddress(address string) error {
	a := strings.TrimSpace(address)
	if a != address || a == "" {
		return fmt.Errorf("the address %q has spaces around it or is empty", address)
	}
	if _, err := netip.ParseAddr(a); err == nil {
		return nil
	}
	if _, err := netip.ParsePrefix(a); err == nil {
		return nil
	}
	if len(a) <= 253 && networkNamePattern.MatchString(a) {
		return nil
	}
	return fmt.Errorf("%q is not an address a rule can match: give an IP address (10.0.0.10), a network range (10.0.0.0/24), a host name (db.example.com) or a wildcard for the names beneath one (*.example.com)", address)
}

func (s *Store) UpsertGroup(g Group) (Group, error) {
	return s.UpsertGroupContext(context.Background(), g)
}
func (s *Store) UpsertGroupContext(ctx context.Context, g Group) (Group, error) {
	g = copyGroup(g)
	return mutateCatalogContext(ctx, s, func(n *Store) (Group, error) { return n.upsertGroup(g) })
}

func (s *Store) UpsertService(svc Service) (Service, error) {
	return s.UpsertServiceContext(context.Background(), svc)
}
func (s *Store) UpsertServiceContext(ctx context.Context, svc Service) (Service, error) {
	svc = copyService(svc)
	return mutateCatalogContext(ctx, s, func(n *Store) (Service, error) { return n.upsertService(svc) })
}

func (s *Store) DeleteEndpoint(tenant, id string) (bool, error) {
	return s.DeleteEndpointContext(context.Background(), tenant, id)
}
func (s *Store) DeleteEndpointContext(ctx context.Context, tenant, id string) (bool, error) {
	return mutateCatalogContext(ctx, s, func(n *Store) (bool, error) {
		// Only an existing destination is refused by ownership; an absent ID is
		// absent (404), not "managed through bypass review" (403).
		if e, ok := n.GetEndpoint(tenant, id); ok && (strings.HasPrefix(id, certPinEndpointPrefix) || certPinEndpoint(e)) {
			return false, ErrCertPinEndpointOwnership
		}
		if e, ok := n.GetEndpoint(tenant, id); ok && e.Source == SourceApplication {
			return false, ErrApplicationEndpointOwnership
		}
		if e, ok := n.GetEndpoint(tenant, id); ok && e.Source == SourceEnrolled {
			return false, fmt.Errorf("enrolled endpoints are managed by inventory")
		}
		return n.deleteEndpoint(tenant, id)
	})
}

func (s *Store) DeleteGroup(tenant, id string) (bool, error) {
	return s.DeleteGroupContext(context.Background(), tenant, id)
}
func (s *Store) DeleteGroupContext(ctx context.Context, tenant, id string) (bool, error) {
	return mutateCatalogContext(ctx, s, func(n *Store) (bool, error) { return n.deleteGroup(tenant, id) })
}

func (s *Store) DeleteService(tenant, id string) (bool, error) {
	return s.DeleteServiceContext(context.Background(), tenant, id)
}
func (s *Store) DeleteServiceContext(ctx context.Context, tenant, id string) (bool, error) {
	return mutateCatalogContext(ctx, s, func(n *Store) (bool, error) { return n.deleteService(tenant, id) })
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
