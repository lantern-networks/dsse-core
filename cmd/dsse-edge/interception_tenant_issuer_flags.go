package main

import "flag"

// Per-tenant interception-issuer configuration, in a sibling file because main.go's decomposition ratchet
// holds its flag count frozen — new configuration belongs beside the thing it configures.

// interceptionTenantIssuerFlags decides whether each organization's intercepted traffic is signed under ITS
// OWN certificate authority, or whether one node-wide intermediate signs for everybody.
type interceptionTenantIssuerFlags struct {
	// dir holds one offline-issued bundle per organization: <tenant>.root.pem, <tenant>.intermediate.pem and
	// <tenant>.key.pem (the key sealed with -interception-root-kek-file when that is configured). The Edge
	// never holds any root key — each intermediate was issued out of band by that organization's own offline
	// root, which is the whole point.
	//
	// ★ PER-TENANT INTERCEPTION WAS PROVISIONABLE AND UNREACHABLE BEFORE THIS (measured 2026-08-16). A
	// per-tenant ROOT could be created, listed, persisted and distributed to a customer's devices while every
	// leaf on the node was minted by one shared intermediate: the offline issuer was returned before the
	// per-tenant root was ever consulted. Two organizations on the reference lab each held a durable root that
	// signed nothing.
	//
	// Populating this directory puts the node into per-tenant signing, which is FAIL-CLOSED for organizations
	// without a bundle: their traffic is not intercepted, rather than being intercepted under somebody else's
	// CA. That direction is deliberate. Signing under the wrong CA SUCCEEDS — the device trusts it, the
	// operator sees traffic, and one customer's Edge is minting certificates in another customer's name until
	// somebody happens to read one. No interception is a visible outage; the alternative is an invisible one.
	dir *string
}

func registerInterceptionTenantIssuerFlags() interceptionTenantIssuerFlags {
	return interceptionTenantIssuerFlags{
		dir: flag.String("interception-offline-tenant-intermediate-dir", "",
			"directory of PER-TENANT offline interception issuers (<tenant>.root.pem + <tenant>.intermediate.pem + "+
				"<tenant>.key.pem, the key sealed with -interception-root-kek-file when set). Restored at boot and "+
				"written by POST /admin/interception-intermediate/{tenant}. Non-empty AND populated => per-tenant "+
				"signing is IN FORCE and any organization without an issuer here is NOT intercepted. Empty = one "+
				"node-wide intermediate signs for everybody (current default)"),
	}
}
