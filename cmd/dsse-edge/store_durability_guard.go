package main

import (
	"log"
	"os"
	"path/filepath"
	"strings"
)

// sharedStateDSNConfigured records whether this deployment was given a shared database. Read from the flag at
// start-up, before any store is resolved.
var sharedStateDSNConfigured bool

// storeUnderstandsSharedState names the stores whose backend is resolved by cpStateBlobPersister, and which
// therefore accept the value "postgres". The rest are handed their value as a plain file path.
//
// ★ THIS LIST IS NOT DECORATION (2026-08-21). The first attempt at the fleet default rewrote the value for
// ALL thirty-one stores. The ones on this list fataled loudly and were easy to see; the ones NOT on it took
// "postgres" as a FILE NAME and came up empty in silence — /admin/endpoints answered 0 on both Edges and the
// posture check found both real devices gone from the inventory. A gate test regenerates this list from the
// call sites so it cannot drift away from them.
func storeUnderstandsSharedState(name string) bool {
	switch sharedStoreKey(name) {
	// audit_chain joined on 2026-08-24: it was already resolved by cpStateBlobPersister, and giving it a
	// -state-dir default is what made it reachable through this path at all.
	// agent_updates joined on 2026-08-28: the published set was a file on whichever control plane served the
	// publish, so in an HA pair one node held the catalogue and the other answered "nothing published" — and an
	// Edge polling the front door read them alternately.
	case "admin_runtime_state", "admission_revocations", "high_risk_overlay", "agent_rollout", "agent_updates", "asset_catalog",
		"audit_chain", "break_glass", "delegated_grants",
		"dlp_allowlist", "dlp_classifiers", "dlp_fingerprints", "dlp_policy_objects",
		"enrolled_inventory", "enrolment_tokens", "grants", "human_approvals", "idp_connections",
		// inspection_posture UNDERSTANDS shared state but is never resolved to it automatically — see
		// storeStaysNodeLocal below. The two lists answer different questions: this one is "would =postgres
		// work if an operator asked for it", and a control plane running leader+standby needs exactly that so
		// the standby holds the posture the leader authored. What must not happen is an EDGE drifting onto it
		// by default, which is how every enforcement node came to hold a database connection.
		"tenant_trust_distributions", "inspection_posture", "tenant_ca_registry", "transport_anchor_acks", "transport_trust",
		"policy_rules", "revocation_mesh_outbox", "seat_allocations", "vendor_license", "vlan_objects":
		return true
	}
	return false
}

// The risk store's historical filename and its Postgres row key differ. Keep
// both stable while resolving the backend by the key its persister understands.
func sharedStoreKey(name string) string {
	if strings.TrimSpace(name) == "high_risk_devices" {
		return "high_risk_overlay"
	}
	return strings.TrimSpace(name)
}

func durableStoreFlag(name string) string {
	switch name {
	case "high_risk_devices":
		return "high-risk"
	case "admission_revocations":
		return "admission-revocation"
	}
	return strings.ReplaceAll(name, "_", "-")
}

// storeStaysNodeLocal names the stores an Edge must NOT be defaulted onto shared state for.
//
// It is not the opposite of storeUnderstandsSharedState — a store can be on both, meaning "=postgres works if
// an operator asks for it, but no node drifts onto it by itself". An explicit backend always wins, so a control
// plane that needs the standby to see what the leader authored just says so.
//
// The first entry's reason is written down in cp_state_blob_persister.go: every Edge holding the
// enrolled inventory WRITES it, as a whole snapshot, after each config-bundle apply. Three Edges on one copy
// meant an enrolment recorded by one node was erased by another saving an older snapshot, and the identity
// could be enrolled a second time. A shared blob has exactly the same last-writer-wins shape as the shared
// bind mount that caused it, so this one stays per node until its writes are incremental.
func storeStaysNodeLocal(name string) bool {
	switch strings.TrimSpace(name) {
	case "enrolled_inventory":
		return true
	case "tenant_ca_registry":
		// ★★★ SAME MOVE AS THE POSTURE, AND FOR A BIGGER REASON (2026-08-23). Two Edges shared one blob row
		// for this and wrote whole snapshots into it; an anchor flapped between them. It travels in the config
		// bundle now, so what a node keeps is a CACHE of what it was given. A cache is per node by definition,
		// and pointing it back at shared state would put two writers on one row again.
		//
		// A control plane, which AUTHORS rather than receives, is given an explicit backend — and =postgres
		// still works for it, which is what storeUnderstandsSharedState says.
		return true
	case "inspection_posture":
		// ★★★ IT STOPPED BEING SHARED STATE (2026-08-23). The posture used to be a store two Edges were meant
		// to agree on by sharing a database row — which is how every enforcement Edge came to hold a Postgres
		// connection, and which did not work anyway: measured, one of the two Edges had no posture store at all.
		//
		// It travels in the signed config bundle now, so what is left on a node is a CACHE of the last posture
		// the control plane gave it — kept only so a restart resumes where it was instead of enforcing the
		// default for one poll interval. A cache is per node by definition; pointing it at shared state would
		// put two writers back on one row and re-create what was just removed.
		return true
	default:
		return false
	}
}

// durableStorePath resolves a CONFIG store's backend to a durable default, per design/ It is the one
// place that makes the safe path the default path: with -state-dir set, a store whose own flag is unset or
// "memory" persists to ‹state-dir›/‹name›.json, so a store needs NO per-store wiring to be durable and a NEW
// store inherits durability instead of being born volatile.
//
// Precedence: an explicit backend (a real path, or "postgres") always wins — the operator overrode it on purpose.
// Only "" and "memory" (the volatile defaults) are redirected. With no -state-dir this returns the value
// unchanged, preserving the legacy per-store behaviour for deployments that have not opted in.
func durableStorePath(stateDir, explicit, name string) string {
	e := strings.TrimSpace(explicit)
	if e != "" && e != "memory" {
		return explicit // an explicit path or "postgres" — the operator's choice wins
	}
	// ★★★ A NODE THAT HOLDS NO COPY FOLLOWS THE FLEET (2026-08-21).
	//
	// An Edge that was never given a store flag used to resolve to a per-node file — or, with no state dir, to
	// memory — so two Edges built from the same source and running the same binary answered differently.
	// Measured as one customer administrator reading the same 121 admin routes from two Edges seconds apart:
	// 82 identical, 18 different — this organization's enrolment tokens on one and [] on the other, licence
	// allocated=30 versus 0, the decrypt allowlist present versus empty. In a fleet that grows and shrinks
	// under load, that means what a customer sees depends on which node a load balancer picked.
	//
	// The rule is narrow on purpose, because the wide version broke this lab within a minute:
	//
	//   - only stores whose consumer understands "postgres" (storeUnderstandsSharedState). The first attempt
	//     rewrote every store's value and the ones that take a plain path silently came up EMPTY.
	//   - only when this node has NO copy of its own. A node holding a file keeps it: choosing between two
	//     populated copies is a migration, not a default, and doing it automatically is how the endpoint
	//     inventory was lost. Such a node says so at start-up and names the one-line migration.
	//   - never for a store that must stay per node (storeStaysNodeLocal).
	//
	// What it fixes is exactly the case that matters for autoscaling: a NEW Edge, with nothing of its own,
	// joins and answers what the fleet answers instead of answering from an empty map.
	if sharedStateDSNConfigured && storeUnderstandsSharedState(name) && !storeStaysNodeLocal(name) {
		own := ""
		if sd := strings.TrimSpace(stateDir); sd != "" {
			candidate := filepath.Join(sd, name+".json")
			// An empty file, directory, dangling link or inaccessible path is
			// not first boot. Keep it local for checked loading/recovery instead
			// of hiding it by silently selecting a different, empty backend.
			if _, err := os.Lstat(candidate); err == nil || !os.IsNotExist(err) {
				own = candidate
			}
		}
		if own == "" {
			return "postgres"
		}
		log.Printf("state store %q: this node has its own copy at %q and the deployment has a shared database, "+
			"so it stays per node — two Edges can answer differently. Migrate with -%s-store=postgres+import:%s",
			name, own, durableStoreFlag(name), own)
	}
	if strings.TrimSpace(stateDir) == "" {
		return explicit // no state dir configured: leave as-is (legacy; may be volatile)
	}
	return filepath.Join(strings.TrimSpace(stateDir), name+".json")
}

// store_durability_guard.go addresses a production foot-gun: ~30 `-*-store` flags default to an in-memory /
// volatile backend, and a forgotten flag silently loses data on restart. See docs/edge_state_durability_design.md
// for the full design; this file is its "turn the advisory warning into an invariant" surface.
//
// The key move, per that design, is that not all volatile state is equal. State is CONFIG (operator-authored —
// losing it is the recurring "it was wiped again" bug) or RUNTIME (recoverable — losing it costs a re-login or a
// re-count). Both are reported, but they are reported as DIFFERENT things, and only CONFIG is a candidate for
// fail-closed: an admin re-authenticating is a nuisance; the product forgetting the Named Networks an operator
// defined is the bug we keep having.

// storeStateClass is CONFIG (operator-authored, must survive) or RUNTIME (recoverable, volatile tolerable).
type storeStateClass int

const (
	storeClassConfig storeStateClass = iota
	storeClassRuntime
)

// storeDurabilityCheck is one durability-critical store and whether its configured value is the volatile mode.
type storeDurabilityCheck struct {
	flag     string          // the -flag name (without the leading dash) for the message
	value    string          // the configured value
	jsonMode bool            // true: empty value = in-memory (a path/"postgres" = durable). false: "memory" = volatile.
	class    storeStateClass // CONFIG or RUNTIME — decides whether volatile is a bug or merely a nuisance
	impact   string          // short note on what is lost on restart
}

func (c storeDurabilityCheck) volatile() bool {
	v := strings.TrimSpace(c.value)
	if c.jsonMode {
		return v == ""
	}
	return v == "memory"
}

// volatileStoreReport is the split view: CONFIG stores left volatile (the recurring-bug class) vs RUNTIME stores
// left volatile (tolerable). Kept separate so the enforcement and the message can treat them differently.
type volatileStoreReport struct {
	config  []string // flag names of volatile CONFIG stores
	runtime []string // flag names of volatile RUNTIME stores
}

// warnVolatileDurableStores logs the volatile durability-critical stores, CONFIG and RUNTIME reported distinctly.
// No-op in lab. Returns the split report (for the enforcement check + tests).
func warnVolatileDurableStores(devMode bool, checks []storeDurabilityCheck) volatileStoreReport {
	if devMode {
		return volatileStoreReport{}
	}
	var report volatileStoreReport
	var configLines, runtimeLines []string
	for _, c := range checks {
		if !c.volatile() {
			continue
		}
		if c.class == storeClassConfig {
			report.config = append(report.config, c.flag)
			configLines = append(configLines, "-"+c.flag+" ("+c.impact+")")
		} else {
			report.runtime = append(report.runtime, c.flag)
			runtimeLines = append(runtimeLines, "-"+c.flag+" ("+c.impact+")")
		}
	}
	if len(configLines) > 0 {
		// CONFIG volatile is the recurring bug: operator-authored config that will be gone on the next restart.
		// This is the line that must not be wallpaper.
		log.Printf("WARNING: %d OPERATOR-CONFIG store(s) are IN-MEMORY in production — config set through the Console "+
			"is LOST on the next restart (this is the recurring \"it was wiped again\" bug). "+
			"Give each a durable backend (a JSON path on the shared state "+
			"mount, or =postgres): %s", len(configLines), strings.Join(configLines, "; "))
	}
	if len(runtimeLines) > 0 {
		// RUNTIME volatile is tolerable — reported so it is a known choice, not a hidden one.
		log.Printf("NOTE: %d runtime store(s) are in-memory (recoverable — a re-login or a re-count, not lost config): %s",
			len(runtimeLines), strings.Join(runtimeLines, "; "))
	}
	return report
}

// requireDurableStoresViolation reports the volatile stores that must FAIL startup. Per the design, the
// fail-closed candidate is the CONFIG class ONLY: a volatile RUNTIME store (sessions, metering) is a legitimate
// choice even in production, but a volatile CONFIG store means the node will forget what an operator told it.
//
// Still gated on -require-durable-stores (opt-in) so the current reference Edge — which has CONFIG stores not yet
// converted to durable-by-default (design, a follow-up) — is not bricked. Once every CONFIG store defaults
// durable, this becomes the default and the flag becomes -allow-volatile-config (the escape hatch). Pure/testable.
func requireDurableStoresViolation(devMode, requireDurable bool, report volatileStoreReport) []string {
	if devMode || !requireDurable {
		return nil
	}
	return report.config
}

// A bundle receiver owns a node-local cache; the publishing CP owns authority.
// A shared DSN used for other services must not make the receiver an author.
func configBundleStorePath(stateDir, sourceURL, explicit, name string) string {
	if strings.TrimSpace(sourceURL) == "" {
		return durableStorePath(stateDir, explicit, name)
	}
	if v := strings.TrimSpace(explicit); v != "" && v != "memory" {
		return explicit
	}
	if sd := strings.TrimSpace(stateDir); sd != "" {
		return filepath.Join(sd, name+".json")
	}
	return ""
}
