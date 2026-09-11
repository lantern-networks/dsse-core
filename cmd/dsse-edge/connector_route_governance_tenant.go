package main

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
	if g == nil {
		return 0
	}
	removed := g.CountForTenant(tenantID)
	if removed == 0 {
		return 0
	}
	g.mu.Lock()
	delete(g.authored, tenantID)
	delete(g.held, tenantID)
	delete(g.approved, tenantID)
	delete(g.seen, tenantID)
	delete(g.lastAdvertised, tenantID)
	g.saveLocked()
	g.mu.Unlock()
	return removed
}
