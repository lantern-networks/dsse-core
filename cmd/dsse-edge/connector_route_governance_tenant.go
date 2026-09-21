package main

import (
	"context"
	"maps"
)

// connector_route_governance_tenant.go — an organization's routes are its own, and an erasure has to say so.
//
// ★ THE GATE ASKED FOR THIS THE MOMENT THE STORE BECAME DURABLE (2026-08-25). While the decisions lived only
// in memory, nothing survived an erasure because nothing survived anything. Making them durable made them a
// thing a customer can ask to have deleted, and a store nobody counts contributes nothing to "what is left" —
// so an erasure over it answers complete=true whatever it still holds.
func (g *connectorRouteGovernance) CountForTenant(tenantID string) int {
	if g == nil {
		return 0
	}
	g.mu.RLock()
	defer g.mu.RUnlock()
	var n int
	for _, bySite := range g.authored[tenantID] {
		n += (len(bySite))
	}
	for _, bySite := range g.held[tenantID] {
		n += (len(bySite))
	}
	for _, bySite := range g.approved[tenantID] {
		n += (len(bySite))
	}
	n += (len(g.seen[tenantID]))
	return n
}

// RemoveTenant drops every route decision this organization owns and reports how many went.
func (g *connectorRouteGovernance) RemoveTenant(tenantID string) int {
	n, _ := g.RemoveTenantChecked(tenantID)
	return n
}

func (g *connectorRouteGovernance) removeTenantLocal(tenantID string) (int, error) {
	if g == nil {
		return 0, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	n := len(g.seen[tenantID])
	for _, v := range g.authored[tenantID] {
		n += len(v)
	}
	for _, v := range g.held[tenantID] {
		n += len(v)
	}
	for _, v := range g.approved[tenantID] {
		n += len(v)
	}
	if n == 0 {
		return 0, nil
	}
	candidate := governancePersistState{Held: maps.Clone(g.held), Approved: maps.Clone(g.approved), Seen: maps.Clone(g.seen), Authored: maps.Clone(g.authored)}
	delete(candidate.Held, tenantID)
	delete(candidate.Approved, tenantID)
	delete(candidate.Seen, tenantID)
	delete(candidate.Authored, tenantID)
	if err := g.persistStateLocked(candidate); err != nil {
		return 0, err
	}
	g.held, g.approved, g.seen, g.authored = candidate.Held, candidate.Approved, candidate.Seen, candidate.Authored
	delete(g.lastAdvertised, tenantID)
	return n, nil
}

func (g *connectorRouteGovernance) RemoveTenantChecked(tenantID string) (int, error) {
	return g.RemoveTenantContext(context.Background(), tenantID)
}
func (g *connectorRouteGovernance) RemoveTenantContext(ctx context.Context, tenantID string) (int, error) {
	if g == nil {
		return 0, nil
	}
	n := 0
	err := g.mutateRoutes(ctx, func(c *connectorRouteGovernance) error {
		var err error
		n, err = c.removeTenantLocal(tenantID)
		if n > 0 {
			c.gen++
		}
		return err
	})
	if err != nil {
		return 0, err
	}
	g.mu.Lock()
	delete(g.lastAdvertised, tenantID)
	g.mu.Unlock()
	return n, nil
}
