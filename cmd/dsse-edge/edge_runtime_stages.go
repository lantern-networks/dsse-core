package main

// Phase 2 of the main.go decomposition :
// newServerWithConfig's construction prefix, decomposed into named stages. Each stage body was
// moved VERBATIM from newServerWithConfig and runs at the same point in construction where its
// block previously sat; ordering inside a stage is unchanged. Stages take the normalized
// serverConfig (config.withDefaults has already run) plus any prior-stage outputs they need,
// and return their stores explicitly — no stage reaches into another's outputs behind the
// caller's back.

import (
	"log"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/dns"
	dnsresolver "github.com/lantern-networks/dsse-core/dnsresolver"
	"github.com/lantern-networks/dsse-core/tunnel"
	"github.com/lantern-networks/dsse-core/vlan"
)

// buildVLANBoundaryStore constructs the Named Networks (VLAN objects) + boundary-policy store,
// durable when -vlan-object-store is configured.
func buildVLANBoundaryStore(config serverConfig) *vlan.Store {
	vlanBoundary := vlan.NewStore() //: VLAN/Subnet objects + boundary policies + export
	// Durability (optional, -vlan-object-store). Without it this is a plain in-memory map and EVERY restart
	// erases every Network object the operator defined — the reason the Console's Networks page read permanently
	// empty, since the lab rebuilds the Edge on every change. Every mutation confirms its candidate snapshot before publication.
	if storeShouldBeWired(config.VLANObjectStorePath) {
		p, e := cpStateBlobPersister(config.VLANObjectStorePath, cpStateBlobDB, "vlan_objects")
		if e != nil {
			log.Fatalf("resolve vlan object store %q: %v", config.VLANObjectStorePath, e)
		}
		if p != nil {
			// FAIL CLOSED. A load error means a store exists but could not be read — starting "fresh" would
			// silently discard the operator's Named Networks AND their boundary policies, leaving an
			// empty Networks page and inter-VLAN enforcement quietly gone. That is the very bug this store
			// fixes, so refuse to start instead of recreating it while looking healthy.
			if lerr := vlanBoundary.SetPersister(p); lerr != nil {
				log.Fatalf("vlan object store %q: %v (refusing to start empty — fix or move the file)", config.VLANObjectStorePath, lerr)
			}
		}
		vlan.OnPersistError = func(err error) {
			logErrorf("vlan_object_store_save_failed: %v — network change was not confirmed; prior live state retained", err)
		}
	}
	return vlanBoundary
}

// edgeDNSRuntime is the output of buildEdgeDNSRuntime: the shared DNS conntrack, the Edge DNS
// resolver (DNS-over-tunnel + env-gated legacy UDP), and the durable operator DNS-policy store.
type edgeDNSRuntime struct {
	conntrack   *dns.ConntrackStore
	resolver    *dnsresolver.Resolver
	policyStore *dnsPolicyStore
}

// buildEdgeDNSRuntime constructs the Edge DNS runtime. registry/tunnelManager are the
// connector plumbing the conditional-forwarding upstream resolves through.
func buildEdgeDNSRuntime(config serverConfig, registry connectorRegistryStore, tunnelManager *tunnel.Manager) edgeDNSRuntime {
	dnsConntrack := config.DNSConntrack // DNS resolution conntrack -> IP->FQDN recovery
	if dnsConntrack == nil {
		dnsConntrack = dns.NewConntrackStore()
	}
	// D2/D3/D4 + W3 (M-series): one Edge DNS resolver shared by the DNS-over-tunnel HTTP
	// endpoint (preferred — DNS rides the encrypted (T) tunnel) and the legacy plaintext UDP listener
	// (deprecated, env-gated). Sharing the conntrack so a resolved FQDN is recoverable for connect-by-IP.
	edgeDNSResolver := newEdgeDNSResolverFromEnv(strings.TrimSpace(config.Evaluator.PolicyBundle.TenantID), dnsConntrack)
	// An operator's DNS policy outlives the process. Applied over the boot environment on purpose: a restart
	// that reverts an admin's change is the bug, not the safety net.
	edgeDNSPolicyStore := newDNSPolicyStore(config.DNSPolicyStorePath)
	if line := restoreDNSPolicy(edgeDNSPolicyStore, edgeDNSResolver); line != "" {
		log.Print(line)
	}
	maybeStartEdgeDNSResolverUDPFromEnv(edgeDNSResolver) // the DNS-over-tunnel route is registered on mux later
	// Conditional DNS forwarding: internal (e.g. AD) zones resolve THROUGH the connector that reaches the
	// internal DNS server — the Edge cannot reach internal DNS directly. See docs/dns_conditional_forwarding_design.md.
	edgeDNSResolver.SetConnectorDNS(&connectorDNSUpstream{registry: registry, tunnelManager: tunnelManager, tenantID: strings.TrimSpace(config.Evaluator.PolicyBundle.TenantID)})
	return edgeDNSRuntime{conntrack: dnsConntrack, resolver: edgeDNSResolver, policyStore: edgeDNSPolicyStore}
}

// dlpRuntime is the output of buildDLPRuntime: the live DLP rule/allowlist/policy-object/
// EDM-fingerprint/classifier stores (durable where configured), the per-device risk
// aggregator, and the license/entitlement gate.
type dlpRuntime struct {
	rules         *dlpRuleRuntimeStore
	allowlist     *dlpAllowlistRuntimeStore
	deviceRisk    *dlpDeviceRiskAggregator
	entitlements  *entitlementStore
	policyObjects *dlpPolicyObjectStore
	fingerprints  *dlpFingerprintRuntimeStore
	classifiers   *dlpClassifierRuntimeStore
}

func buildDLPRuntime(config serverConfig) dlpRuntime {
	// DLP: live per-tenant rules. dlpRuleStore holds model.DLPRules (/admin/dlp-rules) overlaid onto the
	// bundle so DLP is an egress-rule option (per-destination, surfaced as a dlp_inspect directive) — the ONLY
	// scan trigger; there is deliberately no tenant-wide fallback. In-memory hot-swap (cross-restart
	// persistence deferred, like the other runtime toggles).
	dlpRuleStore := newDLPRuleRuntimeStore()
	dlpAllowlistStore := newDLPAllowlistRuntimeStore("dsse-dlp-allowlist-v1")
	// Durable allowlist (optional): rehydrate + recompile on boot + flush periodically so operator-declared
	// known-safe values (false-positive tuning) survive an Edge restart.
	if storeShouldBeWired(config.DLPAllowlistStorePath) {
		if p, e := cpStateBlobPersister(config.DLPAllowlistStorePath, cpStateBlobDB, "dlp_allowlist"); e != nil {
			log.Fatalf("resolve dlp allowlist store %q: %v", config.DLPAllowlistStorePath, e)
		} else if p != nil {
			if lerr := dlpAllowlistStore.SetPersister(p); lerr != nil {
				log.Fatalf("load dlp allowlist store: %v", lerr)
			}
			go func() {
				for range time.Tick(30 * time.Second) {
					if err := dlpAllowlistStore.PersistIfDirty(); err != nil {
						log.Printf("dlp allowlist store: persist failed: %v", err)
					}
				}
			}()
		}
	}
	// DLP → device risk (S4): aggregate DLP detections per device and raise device risk (via the high-risk
	// overlay) when a DLP Policy's device-risk COMPOSITE conditions are satisfied, so risk-based policy acts. The
	// conditions live on each DLP Policy object (S4), evaluated per detection — there is no global threshold.
	var dlpRiskMarker deviceRiskMarker
	if config.HighRiskOverlay != nil {
		dlpRiskMarker = config.HighRiskOverlay // avoid a typed-nil interface
	}
	dlpDeviceRisk := newDLPDeviceRiskAggregator(dlpRiskMarker)
	// License/entitlement gate for optional paid features (DLP). Default = the -dlp-entitled-by-default flag, so a
	// tenant with no explicit license entry falls back to it; an admin/license can override per tenant. Durable.
	entitlementStore := newEntitlementStore(map[string]bool{featureDLP: !config.DLPRequiresLicense})
	if storeShouldBeWired(config.EntitlementStorePath) {
		if p, e := cpStateBlobPersister(config.EntitlementStorePath, cpStateBlobDB, "entitlements"); e != nil {
			log.Fatalf("resolve entitlement store %q: %v", config.EntitlementStorePath, e)
		} else if p != nil {
			if lerr := entitlementStore.SetPersister(p); lerr != nil {
				log.Fatalf("load entitlement store: %v", lerr)
			}
			go func() {
				for range time.Tick(30 * time.Second) {
					if err := entitlementStore.PersistIfDirty(); err != nil {
						log.Printf("entitlement store: persist failed: %v", err)
					}
				}
			}()
		}
	}
	// Reusable named DLP Policy objects (S5): egress rules reference one by id. Durable.
	dlpPolicyObjects := newDLPPolicyObjectStore()
	if storeShouldBeWired(config.DLPPolicyObjectStorePath) {
		if p, e := cpStateBlobPersister(config.DLPPolicyObjectStorePath, cpStateBlobDB, "dlp_policy_objects"); e != nil {
			log.Fatalf("resolve dlp policy object store %q: %v", config.DLPPolicyObjectStorePath, e)
		} else if p != nil {
			if lerr := dlpPolicyObjects.SetPersister(p); lerr != nil {
				log.Fatalf("load dlp policy object store: %v", lerr)
			}
			go func() {
				for range time.Tick(30 * time.Second) {
					if err := dlpPolicyObjects.PersistIfDirty(); err != nil {
						log.Printf("dlp policy object store: persist failed: %v", err)
					}
				}
			}()
		}
	}
	dlpFingerprintStore := newDLPFingerprintRuntimeStore("dsse-dlp-edm-v1")
	// Durable EDM datasets (optional): rehydrate + recompile on boot + flush periodically so operator fingerprints
	// (hashes only) survive an Edge restart.
	if storeShouldBeWired(config.DLPFingerprintStorePath) {
		if p, e := cpStateBlobPersister(config.DLPFingerprintStorePath, cpStateBlobDB, "dlp_fingerprints"); e != nil {
			log.Fatalf("resolve dlp fingerprint store %q: %v", config.DLPFingerprintStorePath, e)
		} else if p != nil {
			if lerr := dlpFingerprintStore.SetPersister(p); lerr != nil {
				log.Fatalf("load dlp fingerprint store: %v", lerr)
			}
			go func() {
				for range time.Tick(30 * time.Second) {
					if err := dlpFingerprintStore.PersistIfDirty(); err != nil {
						log.Printf("dlp fingerprint store: persist failed: %v", err)
					}
				}
			}()
		}
	}
	dlpClassifierStore := newDLPClassifierRuntimeStore()
	// Durable custom classifiers (optional): rehydrate + recompile on boot + flush periodically so operator-defined
	// identifiers survive an Edge restart. Admin writes save synchronously; the ticker flushes staged updates.
	if storeShouldBeWired(config.DLPClassifierStorePath) {
		if p, e := cpStateBlobPersister(config.DLPClassifierStorePath, cpStateBlobDB, "dlp_classifiers"); e != nil {
			log.Fatalf("resolve dlp classifier store %q: %v", config.DLPClassifierStorePath, e)
		} else if p != nil {
			if lerr := dlpClassifierStore.SetPersister(p); lerr != nil {
				log.Fatalf("load dlp classifier store: %v", lerr)
			}
			go func() {
				for range time.Tick(30 * time.Second) {
					if err := dlpClassifierStore.PersistIfDirty(); err != nil {
						log.Printf("dlp classifier store: persist failed: %v", err)
					}
				}
			}()
		}
	}
	return dlpRuntime{
		rules:         dlpRuleStore,
		allowlist:     dlpAllowlistStore,
		deviceRisk:    dlpDeviceRisk,
		entitlements:  entitlementStore,
		policyObjects: dlpPolicyObjects,
		fingerprints:  dlpFingerprintStore,
		classifiers:   dlpClassifierStore,
	}
}
