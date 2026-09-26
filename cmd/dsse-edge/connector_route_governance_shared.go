package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"
)

type routeGovernanceUpdater interface {
	UpdateContext(context.Context, func([]byte) ([]byte, error)) error
}

func (g *connectorRouteGovernance) isShared() bool {
	if g == nil {
		return false
	}
	_, ok := g.persister.(routeGovernanceUpdater)
	return ok
}
func routeGovernanceWriteContext(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return ctx
}
func routeState(g *connectorRouteGovernance) governancePersistState {
	return governancePersistState{Held: g.held, Approved: g.approved, Seen: g.seen, Authored: g.authored}
}

// In CP-configured mode, first-sight discovery does not change routing decisions.
func routeDecisionState(g *connectorRouteGovernance) governancePersistState {
	st := routeState(g)
	if g.cpConfigured {
		st.Seen = nil
	}
	return st
}

// Candidates have no persistence backend, so their mutations cannot publish a
// decision until the authoritative transaction commits.
func decodeRouteCandidate(raw []byte, known, cpConfigured bool) (*connectorRouteGovernance, error) {
	c := newConnectorRouteGovernanceWithOptions("", cpConfigured)
	if len(raw) == 0 {
		if known {
			return nil, fmt.Errorf("known route governance row is missing")
		}
		return c, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	for _, key := range []string{"held", "approved", "seen", "authored"} {
		if _, ok := fields[key]; !ok {
			return nil, fmt.Errorf("route governance field %s is missing", key)
		}
	}
	var st governancePersistState
	if err := json.Unmarshal(raw, &st); err != nil {
		return nil, err
	}
	// Historical empty maps may be encoded as null; missing fields are not a
	// complete persisted snapshot. Normalize null maps before any local mutation.
	if st.Held != nil {
		c.held = st.Held
	}
	if st.Approved != nil {
		c.approved = st.Approved
	}
	if st.Seen != nil {
		c.seen = st.Seen
	}
	if st.Authored != nil {
		c.authored = st.Authored
	}
	return c, nil
}
func (g *connectorRouteGovernance) mutateRoutes(ctx context.Context, edit func(*connectorRouteGovernance) error) error {
	ctx = routeGovernanceWriteContext(ctx)
	g.writeMu.Lock()
	defer g.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	var candidate *connectorRouteGovernance
	apply := func(raw []byte) ([]byte, error) {
		c, err := decodeRouteCandidate(raw, g.sharedKnown, g.cpConfigured)
		if err != nil {
			return nil, err
		}
		if err = edit(c); err != nil {
			return nil, err
		}
		next, err := json.Marshal(routeState(c))
		if err == nil {
			candidate = c
		}
		return next, err
	}
	if p, ok := g.persister.(routeGovernanceUpdater); ok {
		if err := p.UpdateContext(ctx, apply); err != nil {
			return err
		}
		g.sharedKnown = true
	} else {
		g.mu.RLock()
		raw, err := json.Marshal(routeState(g))
		g.mu.RUnlock()
		if err != nil {
			return err
		}
		if _, err = apply(raw); err != nil {
			return err
		}
		if err = g.persistStateLocked(routeState(candidate)); err != nil {
			return err
		}
	}
	g.sharedKnown = true
	g.mu.Lock()
	// A discovery/no-op mutation can adopt a peer's decision change without
	// incrementing the detached candidate's counter. Publication must still see it.
	before, _ := json.Marshal(routeDecisionState(g))
	after, _ := json.Marshal(routeDecisionState(candidate))
	if candidate.gen == 0 && !bytes.Equal(before, after) {
		candidate.gen++
	}
	g.held, g.approved, g.seen, g.authored = candidate.held, candidate.approved, candidate.seen, candidate.authored
	g.gen += candidate.gen
	g.mu.Unlock()
	return nil
}

// RefreshShared is checked by administrative reads and bundle publication.
// Routing still uses the local applied snapshot; it does not query SQL per packet.
func (g *connectorRouteGovernance) RefreshShared() error {
	if !g.isShared() {
		return nil
	}
	g.writeMu.Lock()
	defer g.writeMu.Unlock()
	raw, err := g.persister.Load()
	if err != nil {
		return err
	}
	c, err := decodeRouteCandidate(raw, g.sharedKnown, g.cpConfigured)
	if err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	before, _ := json.Marshal(routeDecisionState(g))
	after, _ := json.Marshal(routeDecisionState(c))
	if !bytes.Equal(before, after) {
		g.gen++
	}
	g.held, g.approved, g.seen, g.authored = c.held, c.approved, c.seen, c.authored
	if len(raw) > 0 {
		g.sharedKnown = true
	}
	return nil
}
func (g *connectorRouteGovernance) AddAuthored(tenant, id string, r authoredRoute) error {
	return g.AddAuthoredContext(context.Background(), tenant, id, r)
}
func (g *connectorRouteGovernance) AddAuthoredContext(ctx context.Context, tenant, id string, r authoredRoute) error {
	return g.mutateRoutes(ctx, func(c *connectorRouteGovernance) error { return c.addAuthoredLocal(tenant, id, r) })
}
func (g *connectorRouteGovernance) RemoveAuthored(tenant, id, key string) error {
	return g.RemoveAuthoredContext(context.Background(), tenant, id, key)
}
func (g *connectorRouteGovernance) RemoveAuthoredContext(ctx context.Context, tenant, id, key string) error {
	return g.mutateRoutes(ctx, func(c *connectorRouteGovernance) error { return c.removeAuthoredLocal(tenant, id, key) })
}
func (g *connectorRouteGovernance) SetHeld(tenant, id, cidr string, held bool) {
	if err := g.mutateRoutes(context.Background(), func(c *connectorRouteGovernance) error { c.setHeldLocal(tenant, id, cidr, held); return nil }); err != nil {
		log.Printf("route hold not saved: %v", err)
	}
}
func (g *connectorRouteGovernance) SetApproved(tenant, id, cidr string, approved bool) {
	if err := g.mutateRoutes(context.Background(), func(c *connectorRouteGovernance) error { c.setApprovedLocal(tenant, id, cidr, approved); return nil }); err != nil {
		log.Printf("route approval not saved: %v", err)
	}
}
func (g *connectorRouteGovernance) SeeRoutes(tenant, id string, cidrs []string, now time.Time) {
	if err := g.SeeRoutesContext(context.Background(), tenant, id, cidrs, now); err != nil {
		log.Printf("route discovery not saved: %v", err)
	}
}
func (g *connectorRouteGovernance) SeeRoutesContext(ctx context.Context, tenant, id string, cidrs []string, now time.Time) error {
	err := g.mutateRoutes(ctx, func(c *connectorRouteGovernance) error { c.seeRoutesLocal(tenant, id, cidrs, now); return nil })
	if err != nil {
		return err
	}
	tenant, id = strings.TrimSpace(tenant), strings.TrimSpace(id)
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.lastAdvertised[tenant] == nil {
		g.lastAdvertised[tenant] = map[string]time.Time{}
	}
	g.lastAdvertised[tenant][id] = now
	return nil
}
func (g *connectorRouteGovernance) ImportShared(st *governancePersistState) {
	if err := g.ImportReceived(context.Background(), st); err != nil {
		log.Printf("route bundle not saved: %v", err)
	}
}
func (g *connectorRouteGovernance) ImportReceived(ctx context.Context, st *governancePersistState) error {
	if g == nil || st == nil {
		return nil
	}
	if g.isShared() {
		return fmt.Errorf("received route decisions require a node-local store")
	}
	if !st.Complete && len(st.Held)+len(st.Approved)+len(st.Seen)+len(st.Authored) == 0 {
		return nil
	}
	// Copy the caller's maps; a subsequent mutation must not alter the received DTO.
	raw, err := json.Marshal(st)
	if err != nil {
		return err
	}
	var snapshot governancePersistState
	if err = json.Unmarshal(raw, &snapshot); err != nil {
		return err
	}
	return g.mutateRoutes(ctx, func(c *connectorRouteGovernance) error {
		if snapshot.Complete {
			raw, err := json.Marshal(snapshot)
			if err != nil {
				return err
			}
			received, err := decodeRouteCandidate(raw, false, g.cpConfigured)
			if err != nil {
				return err
			}
			c.held, c.approved, c.seen, c.authored = received.held, received.approved, received.seen, received.authored
			c.gen++
		} else {
			c.importSharedLocal(&snapshot)
		}
		return nil
	})
}

// ExportForBundle includes a complete empty set after a committed deletion. The
// legacy Export accessor retains its nil-for-empty contract.
func (g *connectorRouteGovernance) ExportForBundle() *governancePersistState {
	if g == nil {
		return nil
	}
	g.writeMu.Lock()
	defer g.writeMu.Unlock()
	g.mu.RLock()
	defer g.mu.RUnlock()
	st := routeState(g)
	if !g.sharedKnown && len(st.Held)+len(st.Approved)+len(st.Seen)+len(st.Authored) == 0 {
		return nil
	}
	st.Complete = true
	return &st
}
