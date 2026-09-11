package main

import "strings"

// ★★★ THE SAME TWO MACHINES WERE HEALTHY CONNECTORS AND SILENT DEVICES ON ONE SCREEN (2026-09-06, read off a
// live deployment with two connectors in a separate VPC and one Mac).
//
// A connector enrols like a device — it needs admission, an identity and a certificate, and the licence counts
// it because the licence counts AGENTS — so it is in the enrolled ledger, correctly. What was wrong is that
// every surface that says "devices" read that ledger whole. The Console then showed, side by side:
//
//	CONNECTORS  2 / 2 up · all connectors online
//	DEVICES     3 · 1 steering · 2 not reporting     Platform: Unknown 2, macOS 1
//
// and the device list carried two rows that will never have a user, an OS, a posture or a steering state,
// each offering a Block button — which on a connector cuts off everything behind it, from a screen whose
// words describe cutting off a laptop.
//
// The ledger entry itself already knows ("enrolled as a connector for site hq"), but that is a sentence, and
// deciding what something IS by matching a sentence is the shape this repository keeps removing. The
// connector registry is authoritative for connectors; ask it.
//
// ★ WITHHELD, NOT DROPPED. The count travels with the answer, because a list that quietly omits rows is how a
// fleet loses machines nobody can see. Seats and licence keep counting them: they are agents.
func connectorIdentitiesFor(registry connectorRegistryStore, tenant string) map[string]bool {
	out := map[string]bool{}
	if registry == nil {
		return out
	}
	want := strings.ToLower(strings.TrimSpace(tenant))
	for _, c := range registry.List() {
		id := strings.ToLower(strings.TrimSpace(c.ID))
		if id == "" {
			continue
		}
		// An operator answering for the whole deployment passes no tenant and gets every connector; inside an
		// organization, only its own — the same scoping rule the device list itself follows.
		if want != "" && strings.ToLower(strings.TrimSpace(c.TenantID)) != want {
			continue
		}
		out[id] = true
	}
	return out
}

// isConnectorIdentity reports whether this enrolled identity is a connector rather than an endpoint.
func isConnectorIdentity(connectors map[string]bool, identity string) bool {
	return connectors[strings.ToLower(strings.TrimSpace(identity))]
}
