// Package knownbypass provides a curated default catalog of host patterns for well-known services that pin
// their TLS certificate or otherwise cannot be intercepted. A decrypt-all edge raw-forwards these by
// default instead of breaking them on first contact — and instead of every endpoint generating
// cert-pinning detection noise for the same well-known services. Operators can extend the list, and a tenant
// admin can override an individual catalog entry (force-inspect it despite the pin, or disable the bypass).
//
// Scope is deliberately conservative: mostly services that genuinely cannot be inspected (certificate
// pinning, OS trust/update, certificate-validation endpoints), plus the GitHub developer platform as a
// curated compatibility bypass (its asset CDN is a genuinely pinned apex; the rest is bypassed alongside so
// the platform works end to end — the entry is overridable per tenant for anyone who needs to inspect it).
// It intentionally does NOT include Google Workspace or Microsoft 365, which an edge typically intercepts
// for tenant restriction; bypassing those would defeat that control. Region-specific pinned apps (e.g.
// banking) are left to per-deployment configuration or to the cert-pinning detection workflow.
//
// This is the predefined-catalog OBJECT: a versioned set of entries carrying vendor/category/risk metadata,
// plus a per-tenant override layer (see overrides.go). A signed, automatically-updated catalog feed that
// replaces the built-in default is a separate, later piece — this package is the in-process default it ships.
package knownbypass

import "strings"

// CatalogVersion is the monotonic version of the built-in default catalog. It bumps when the default entry set
// changes so a tenant can tell which curated baseline is in effect (a signed feed will carry its own version).
const CatalogVersion = 6

// Override modes for a predefined catalog entry. The default (no override) is no-decrypt keep-steer.
const (
	// OverrideForceInspect decrypts/inspects the entry's traffic despite the pin (it may break the app — the
	// UI warns). Removes the entry from the effective bypass set.
	OverrideForceInspect = "force_inspect"
	// OverrideDisabled stops applying this predefined bypass without asserting "inspect". Also removes the
	// entry from the effective bypass set; kept distinct from force_inspect for audit/intent clarity.
	OverrideDisabled = "disabled"
)

// Group is a named catalog entry: a vendor/category-scoped set of bypass patterns with risk metadata, so the
// catalog is auditable and individually overridable. (Named "Group" for backward compatibility with existing
// consumers; conceptually it is a predefined-catalog Entry.)
type Group struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Vendor      string   `json:"vendor"`
	Category    string   `json:"category"`
	Risk        string   `json:"risk"` // low|medium|high — risk of bypassing (not inspecting) this entry
	Description string   `json:"description"`
	Patterns    []string `json:"patterns"` // interception engine syntax: "*.suffix" matches the suffix and any subdomain
}

// Groups is the curated default catalog, one entry per vendor/category.
var Groups = []Group{
	{
		ID:          "apple_push",
		Name:        "apple_push",
		Vendor:      "Apple",
		Category:    "push",
		Risk:        "low",
		Description: "Apple Push (APNs)",
		Patterns: []string{
			"*.push.apple.com",
		},
	},
	{
		ID:          "apple_software_update",
		Name:        "apple_software_update",
		Vendor:      "Apple",
		Category:    "software_update",
		Risk:        "low",
		Description: "Apple software update / iTunes media",
		Patterns: []string{
			"*.aaplimg.com",
			"*.itunes.apple.com",
			"*.mzstatic.com",
			"appldnld.apple.com",
			"audiocontentdownload.apple.com",
			"cls-ingest.itunes.apple.com",
			"cls-iosclient.itunes.apple.com",
			"devimages-cdn.apple.com",
			"diagassets.apple.com",
			"download.developer.apple.com",
			"gdmf-ados.apple.com",
			"gdmf.apple.com",
			"itunes.apple.com",
			"mesu.apple.com",
			"ns.itunes.apple.com",
			"oscdn.apple.com",
			"osrecovery.apple.com",
			"pg-bootstrap.itunes.apple.com",
			"play.itunes.apple.com",
			"s.mzstatic.com",
			"smp-device-content.apple.com",
			"suconfig.apple.com",
			"swcdn.apple.com",
			"swdist.apple.com",
			"swdownload.apple.com",
			"swscan.apple.com",
			"updates-http.cdn-apple.com",
			"updates.cdn-apple.com",
			"vpp.itunes.apple.com",
			"xp-cdn.apple.com",
			"xp.apple.com",
		},
	},
	{
		ID:          "apple_app_store",
		Name:        "apple_app_store",
		Vendor:      "Apple",
		Category:    "app_store",
		Risk:        "low",
		Description: "Apple App Store / Game Center / iWork",
		Patterns: []string{
			"*.apps-marketplace.apple.com",
			"*.apps.apple.com",
			"*.gc.apple.com",
			"*.iwork.apple.com",
			"playgrounds-assets-cdn.apple.com",
			"playgrounds-cdn.apple.com",
		},
	},
	{
		ID:          "apple_certificate_validation",
		Name:        "apple_certificate_validation",
		Vendor:      "Apple",
		Category:    "certificate_validation",
		Risk:        "high",
		Description: "Apple certificate validation (OCSP/CRL)",
		Patterns: []string{
			"certs.apple.com",
			"crl.apple.com",
			"cssubmissions.apple.com",
			"fcs-keys-pub-prod.cdn-apple.com",
			"ocsp.apple.com",
			"ocsp2.apple.com",
			"ppq.apple.com",
			"skl.apple.com",
			"sylvan.apple.com",
			"tbsc.apple.com",
			"valid.apple.com",
			"wkms-public.apple.com",
		},
	},
	{
		// ★★★ FOUND THE SAME WAY AS THE ONE BELOW, ONE STEP EARLIER (2026-09-04). That entry exists because
		// NOTARIZING this product's own package from a Mac steered by this product failed at the last step.
		// This one exists because SIGNING it fails at the first:
		//
		//	codesign: The timestamp service is not available.
		//
		// `codesign --timestamp` asks an RFC 3161 authority to countersign, over a connection it will not have
		// re-signed. Without it a Developer ID signature cannot be produced at all, so a steered Mac cannot
		// build software — not the product, not anything. The failure names a "service", not a proxy, and a
		// developer meeting it has no reason to look at their network.
		//
		// ★ IT IS IN THE DEFAULT SET, LIKE EVERY ENTRY HERE, and an administrator who wants this inspected
		// says so with an override. That is the right way round: the deployment that has not thought about
		// code signing does not break it, and the one that has can still take it back.
		ID:       "apple_code_signing_timestamp",
		Name:     "apple_code_signing_timestamp",
		Vendor:   "Apple",
		Category: "certificate_validation",
		Risk:     "high",
		Description: "Apple's code-signing timestamp authority. Required by `codesign --timestamp`; without it " +
			"no Developer ID signature can be produced on this machine.",
		Patterns: []string{
			"timestamp.apple.com",
		},
	},
	{
		ID:       "apple_notarization_gatekeeper",
		Name:     "apple_notarization_gatekeeper",
		Vendor:   "Apple",
		Category: "certificate_validation",
		Risk:     "high",
		Description: "Apple Gatekeeper notarization ticket delivery (CloudKit). Required by `stapler` and by " +
			"first-launch ticket lookup.",
		// Found by being the victim of it, 2026-08-10. Notarizing this product's own .pkg from a Mac steered by
		// this product failed at the last step:
		//
		//   Certificate trust evaluation for api.apple-cloudkit.com did not return expected result.
		//   Certificate authority pinning mismatch.
		//   issuer=O=Lantern DSSE, CN=Lantern DSSE Interception Issuing CA
		//
		// ★ THIS IS A SEPARATE DOMAIN FROM apple.com and was matched by nothing. The catalog already carries
		// nine Apple entries and the reference Edge additionally bypasses "*.apple.com" as an operator flag;
		// "apple-cloudkit.com" is caught by neither, so the one Apple host a developer machine cannot do
		// without was the one being decrypted.
		//
		// ★ AND THE FAILURE MODE IS THE BAD ONE. Notarization SUCCEEDS — submission and result use ordinary
		// pinned-free hosts — and only the staple fails. An engineer who does not check gets a package that
		// installs on their own machine (where Gatekeeper can fetch the ticket online) and is refused on the
		// offline customer machine that most needs it. A customer whose developers build Mac software behind
		// this product hits it as "our releases are broken and we cannot see why".
		Patterns: []string{
			"*.apple-cloudkit.com",
		},
	},
	{
		ID:          "apple_account_id",
		Name:        "apple_account_id",
		Vendor:      "Apple",
		Category:    "identity",
		Risk:        "medium",
		Description: "Apple Account / Apple ID auth",
		Patterns: []string{
			"account.apple.com",
			"albert.apple.com",
			"appleid.cdn-apple.com",
			"gs.apple.com",
			"gsa.apple.com",
			"gsra.apple.com",
			"identity.apple.com",
			"idmsa.apple.com",
			"idv-prod1.apple.com",
			"idv.cdn-apple.com",
		},
	},
	{
		ID:          "apple_icloud",
		Name:        "apple_icloud",
		Vendor:      "Apple",
		Category:    "push_and_storage",
		Risk:        "low",
		Description: "iCloud (incl. Private Relay)",
		Patterns: []string{
			"*.icloud-content.com",
			"*.icloud.apple.com",
			"*.icloud.com",
			"gateway.icloud.com",
			"mask-api.icloud.com",
			"mask-h2.icloud.com",
			"mask.icloud.com",
			"metrics.icloud.com",
			"pong.icloud.com",
			"probe.icloud.com",
			"setup.icloud.com",
			"statici.icloud.com",
			"ws-ee-maidsvc.icloud.com",
		},
	},
	{
		ID:          "apple_device_management",
		Name:        "apple_device_management",
		Vendor:      "Apple",
		Category:    "device_management",
		Risk:        "low",
		Description: "Apple device management / ABM/ASM (DEP/MDM/VPP)",
		Patterns: []string{
			"*.business.apple.com",
			"*.school.apple.com",
			"api-business.apple.com",
			"api-school.apple.com",
			"api.edu.apple.com",
			"api.ent.apple.com",
			"axm-adm-enroll.apple.com",
			"axm-adm-mdm.apple.com",
			"axm-adm-scep.apple.com",
			"axm-app.apple.com",
			"axm-servicediscovery.apple.com",
			"bpapi.apple.com",
			"configuration.apple.com",
			"deviceenrollment.apple.com",
			"deviceservices-external.apple.com",
			"fba.apple.com",
			"humb.apple.com",
			"iprofiles.apple.com",
			"lcdn-locator.apple.com",
			"lcdn-registration.apple.com",
			"mdmenrollment.apple.com",
			"pos-device.apple.com",
			"serverstatus.apple.com",
			"sq-device.apple.com",
			"ws.school.apple.com",
		},
	},
	{
		ID:          "apple_time",
		Name:        "apple_time",
		Vendor:      "Apple",
		Category:    "time",
		Risk:        "low",
		Description: "Apple time sync",
		Patterns: []string{
			"time-ios.apple.com",
			"time-macos.apple.com",
			"time.apple.com",
		},
	},
	{
		ID:          "apple_captive_dns",
		Name:        "apple_captive_dns",
		Vendor:      "Apple",
		Category:    "connectivity",
		Risk:        "medium",
		Description: "Apple captive portal / DNS",
		Patterns: []string{
			"captive.apple.com",
			"doh.dns.apple.com",
			"static.ips.apple.com",
		},
	},
	{
		ID:          "apple_other_services",
		Name:        "apple_other_services",
		Vendor:      "Apple",
		Category:    "other",
		Risk:        "low",
		Description: "Other Apple services Apple lists for enterprise networks",
		Patterns: []string{
			"*.appattest.apple.com",
			"*.smoot.apple.com",
			"app-site-association.cdn-apple.com",
			"apple-native-relay.apple.com",
			"apple-relay.apple.com",
			"gg.apple.com",
			"guzzoni.apple.com",
			"ig.apple.com",
			"iphonesubmissions.apple.com",
			"support.apple.com",
			"supportmetrics.apple.com",
			"www.apple.com",
		},
	},
	{
		ID:          "windows_update",
		Name:        "windows_update",
		Vendor:      "Microsoft",
		Category:    "software_update",
		Risk:        "low",
		Description: "Windows Update / delivery optimization use pinned, large downloads (NOT M365 auth).",
		Patterns: []string{
			"*.delivery.mp.microsoft.com",
			"*.dl.delivery.mp.microsoft.com",
			"*.update.microsoft.com",
			"*.windowsupdate.com",
		},
	},
	{
		ID:          "github_asset_cdn",
		Name:        "github_asset_cdn",
		Vendor:      "GitHub",
		Category:    "developer_platform",
		Risk:        "low",
		Description: "ONLY GitHub's HSTS-preloaded asset CDN (githubassets.com) is bypassed — it genuinely cannot be intercepted (decrypting it fails the TLS handshake and the React SPA never mounts). Everything else GitHub — github.com, githubusercontent.com, codeload — is INTERCEPTED (default posture: bypass only what truly cannot be decrypted). The git CLI must trust the interception CA rather than relying on a bypass.",
		Patterns: []string{
			"*.githubassets.com",
			"github.githubassets.com",
		},
	},
	{
		ID:          "ca_certificate_validation",
		Name:        "ca_certificate_validation",
		Vendor:      "Public CAs",
		Category:    "certificate_validation",
		Risk:        "high",
		Description: "Non-Apple CA OCSP/CRL endpoints must not be intercepted, or interception-cert validation deadlocks.",
		Patterns: []string{
			"ocsp.digicert.com",
			"ocsp.pki.goog",
			"ocsp.sectigo.com",
		},
	},
	{
		ID:          "fido2_passkey_hybrid_cable",
		Name:        "fido2_passkey_hybrid_cable",
		Vendor:      "FIDO Alliance / Google / Apple",
		Category:    "authentication",
		Risk:        "low",
		Description: "Cross-device passkey (FIDO2 hybrid transport / caBLE) tunnel servers. The QR + phone ceremony is relayed browser<->phone end-to-end encrypted through these, so intercepting the TLS breaks the ceremony and reveals only ciphertext. Bypass is required for QR cross-device passkeys. Domains are FIDO-spec assigned (ids 0/1 = Chrome/Android and Apple), not an open-ended list.",
		Patterns: []string{
			"cable.ua5v.com",
			"cable.auth.com",
		},
	},
}

// ★★ REMOVED: A DEVELOPMENT SCAFFOLD THAT SHIPPED (2026-08-14, on the operator's instruction). An entry here
// bypassed one AI desktop client's WebSocket bridge. This product is built using that tool, and the exclusion
// existed so the author's own client kept working under decrypt-all — but this catalog is applied by default,
// so the exception went to every deployment rather than to the machine it was for.
//
// A selective steering exception is a ZTNA violation whichever host it names, and this codebase has recorded
// that rule before: an earlier bypass of the same vendor was removed on 2026-07-04 for the same reason, with
// the note that the answer is to make interception faithful rather than to carve a hole.
//
// Its stated justification had also stopped being true. "A long-lived WebSocket cannot survive decrypt-all
// proxying" was the symptom that produced it, and both legs were fixed: the edge→origin leg routes WebSocket
// upgrades over an http/1.1 transport carrying the browser hello, and the client→edge leg handles RFC 8441
// Extended CONNECT over h2.
//
// Nothing else about this catalog is changed by this commit. Whether the catalog should apply by default at all
// is a separate question, deliberately left open.

// CatalogDocument is the versioned predefined catalog returned to admins for review.
type CatalogDocument struct {
	Version int     `json:"version"`
	Entries []Group `json:"entries"`
}

// Catalog returns the versioned built-in default catalog.
func Catalog() CatalogDocument {
	return CatalogDocument{Version: CatalogVersion, Entries: Groups}
}

// EntryByID returns the catalog entry with the given id.
func EntryByID(id string) (Group, bool) {
	id = strings.TrimSpace(id)
	for _, g := range Groups {
		if g.ID == id {
			return g, true
		}
	}
	return Group{}, false
}

// EffectiveBypassHostsFrom returns the flattened bypass patterns of the given catalog entries after applying
// per-tenant overrides: an entry overridden to force_inspect or disabled is dropped (its traffic is inspected
// again), everything else stays a no-decrypt bypass. The entries are the EFFECTIVE catalog — the built-in
// default Groups, or a feed-supplied catalog when one is applied (the feed is a proprietary layer).
func EffectiveBypassHostsFrom(entries []Group, overrides []Override) []string {
	dropped := map[string]bool{}
	for _, o := range overrides {
		switch strings.TrimSpace(o.Mode) {
		case OverrideForceInspect, OverrideDisabled:
			dropped[strings.TrimSpace(o.EntryID)] = true
		}
	}
	hosts := []string{}
	for _, g := range entries {
		if dropped[g.ID] {
			continue
		}
		hosts = append(hosts, g.Patterns...)
	}
	return hosts
}

// EffectiveBypassHosts applies overrides to the built-in default catalog. Pass nil for the unoverridden default.
func EffectiveBypassHosts(overrides []Override) []string {
	return EffectiveBypassHostsFrom(Groups, overrides)
}

// DefaultBypassHosts returns the flattened curated default bypass patterns (no tenant overrides applied).
func DefaultBypassHosts() []string {
	return EffectiveBypassHosts(nil)
}
