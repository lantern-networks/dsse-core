package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/lantern-networks/dsse-core/idpregistry"
)

// config_bundle_idp_connections.go — carrying, from the control plane to the Edges, WHICH IDENTITY PROVIDER
// may sign a user in for each organization.
//
// ★★★ THE STEP-UP CEREMONY STOPPED AT A REGISTRY THAT ONLY THE CONTROL PLANE HAD (2026-09-02, measured on the
// live deployment with a real device).
//
// An egress rule with access=authenticate held a flow, the Edge redirected the browser to the clientless
// broker, and the broker answered
//
//	{"error":"no usable IdP for the tenant (required \"\" is not registered)"}
//
// about an organization whose administrator had registered one minutes earlier, through the Console, with a
// 200. Asked directly, the Edge's own /admin/idp-connections returned an empty list: the registration lived
// on the control plane and nothing carried it. This is the same family as the internal CAs beside it — an
// object authored in one place and enforced in another, travelling on no channel that exists here.
//
// ★★ AND IT CARRIES THE CLIENT SECRET, DELIBERATELY. The Edge is the OIDC relying party: it performs the
// token exchange, so it must hold what the IdP issued to this deployment. The bundle is pulled over TLS
// against the deployment's own anchor and is signature-verified, which is the same protection the fleet
// credential and the connector secrets already travel under. An Edge that cannot be trusted with the secret
// cannot be trusted to enforce with it either.
type idpConnectionBundle struct {
	// Connections is every organization's registry. An Edge carries every organization's flows, so this is
	// fleet-wide rather than scoped to the puller's organization.
	Connections []idpregistry.Connection `json:"connections"`
	// Defaults is each organization's chosen provider, by organization id. It is a separate map because a
	// default is a property of the organization, not of any one connection.
	Defaults map[string]string `json:"defaults,omitempty"`
	// Complete says the control plane could read its whole registry. False must never be read as "there are
	// none": an Edge that emptied its registry on a failed read would refuse to sign anybody in anywhere.
	Complete bool `json:"complete"`
}

// idpConnectionBundleSection builds what the control plane publishes, or nil when this node holds no registry
// and is therefore not the authority for this object.
func idpConnectionBundleSection(store *idpregistry.Store) *idpConnectionBundle {
	if store == nil {
		return nil
	}
	return &idpConnectionBundle{Connections: store.ListAll(), Defaults: store.DefaultsAll(), Complete: true}
}

// applyIdPConnectionBundleSection makes this Edge's registry match the control plane's. Returns how many
// connections this Edge now holds, and whether it changed anything.
func applyIdPConnectionBundleSection(store *idpregistry.Store, section *idpConnectionBundle, logf func(string, ...interface{})) (count int, applied bool) {
	if store == nil || section == nil {
		return 0, false
	}
	if !section.Complete {
		if logf != nil {
			logf("config_bundle_idp_connections: the control plane could not read its whole registry — " +
				"keeping the %d connection(s) this Edge already holds. An incomplete read is not an absence")
		}
		return len(store.ListAll()), false
	}
	// ★ COMPARED BY WHAT IT SERIALISES TO. A Connection carries slices, so it is not comparable with ==,
	// and a hand-written field comparison is a list somebody forgets to extend the day a field is added —
	// which shows up as an Edge that quietly never applies a change to that field.
	before := connectionsFingerprint(store)
	store.ReplaceAll(section.Connections, section.Defaults)
	after := connectionsFingerprint(store)
	return len(store.ListAll()), before != after
}

// connectionsFingerprint is the registry's whole content as one string, so "did this change anything" is
// asked of everything rather than of the fields somebody remembered.
func connectionsFingerprint(store *idpregistry.Store) string {
	if store == nil {
		return ""
	}
	body, err := json.Marshal(struct {
		C []idpregistry.Connection `json:"c"`
		D map[string]string        `json:"d"`
	}{store.ListAll(), store.DefaultsAll()})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}
