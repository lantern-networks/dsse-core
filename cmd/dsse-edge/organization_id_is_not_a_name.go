package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"flag"
	"fmt"
	"strings"
	"sync/atomic"
)

// organization_id_is_not_a_name.go — where an organization's id comes from.
//
// ★★★ WHY (decided 2026-08-21, after the oracle below was measured). The id used to be the display name with
// the spaces taken out: the Console wizard filled it in as slug(display_name), and POST /admin/tenants took
// whatever the caller sent. "Northwind Traders" became tenant_northwind, its transport name became
// northwind.dsse.invalid, and that name is offered on the transport port by SNI. Measured on the lab, with no
// credential of any kind:
//
//	openssl s_client -servername northwind.dsse.invalid   -> subject=CN=northwind.dsse.invalid   ← it exists
//	openssl s_client -servername guessed-org.dsse.invalid -> the deployment's own certificate     ← it does not
//
// A dictionary of plausible company names, run against the port every agent must reach, enumerates the
// customer list of a multi-tenant deployment. Nothing else leaks — no CA, no key, no data — but WHO ELSE IS
// HERE is the one thing such a deployment must never answer to a stranger.
//
// So the id is minted, not chosen. There is nothing to guess, and the guarantee does not depend on whoever
// creates an organization picking a good name — which is the part that will not hold.
//
// ★ THE DISPLAY NAME IS UNAFFECTED, and it is what everybody reads. "Northwind Traders" stays on every screen;
// the id is machinery, and machinery is exactly what should not be memorable.
//
// ★ AND EXISTING ORGANIZATIONS KEEP THEIR IDS. An id is written into certificates, log paths, object
// references and every store keyed by it; renaming one is a migration, not an edit, and doing it silently
// would strand the devices holding certificates that name it. What this changes is every organization created
// from now on. See docs/pki_who_owns_which_certificate.ja.md for what retiring a guessable one would take.

// organizationIDBytes is 128 bits. Long enough that guessing is not a strategy, short enough to read back over
// a phone line when somebody has to.
const organizationIDBytes = 16

var organizationIDEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// newOrganizationID mints an id no one can guess. It keeps the tenant_ prefix that every gate, probe and log
// query in this tree matches on — the change is which characters follow it, not the shape.
func newOrganizationID() (string, error) {
	var raw [organizationIDBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// ★ NEVER A FALLBACK TO SOMETHING PREDICTABLE. Elsewhere in this file's neighbourhood an id that
		// cannot be randomised falls back to a timestamp and a pid, which is fine for a log line and exactly
		// wrong here: the whole property being bought is unguessability. No entropy, no organization.
		return "", fmt.Errorf("this deployment cannot generate an unguessable organization id right now (%w), "+
			"and it will not fall back to a predictable one — the id is what stops a stranger enumerating "+
			"the organizations on this deployment", err)
	}
	return "tenant_" + strings.ToLower(organizationIDEncoding.EncodeToString(raw[:])), nil
}

// organizationTransportServerName is the name this organization's agents send, derived from its id.
//
// ★ DERIVED SO THE GOOD DEFAULT IS THE EASY ONE. A minted id protects nothing if the transport name is still
// chosen by hand as "northwind.dsse.invalid" — the SNI oracle reads the NAME, not the id. A caller may still
// give a name explicitly (an organization that wants its own domain on its own certificate), and then it is
// their decision, made deliberately, rather than one made for them by a form that helpfully filled it in.
// ★★★ AND IT IS ONLY SAFE IF THE ID IS (2026-08-22, measured while giving a third organization its first
// transport authority). Deriving the name from the id protects the customer list exactly as far as the id
// does — and the organizations that predate the minting keep guessable ids by design, three lines up. So this
// function, written to stop a name naming a customer, would have produced:
//
//	tenant_acme -> acme.dsse.invalid
//
// for the very next organization to be given an authority, silently, from the default path. The oracle would
// have come straight back on a name minted today.
//
// A legacy id is therefore folded through SHA-256 instead of being used verbatim: opaque, stable, needing no
// human to invent anything, and reversible by nobody. Refusing was the other option and it is worse — it puts
// a hand-typed name back in the loop, which is the habit this whole file exists to remove.
func organizationTransportServerName(tenantID, suffix string) string {
	id := strings.ToLower(strings.TrimSpace(tenantID))
	id = strings.TrimPrefix(id, "tenant_")
	suffix = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(suffix)), ".")
	if id == "" || suffix == "" {
		return ""
	}
	if !organizationIDIsMinted(tenantID) {
		sum := sha256.Sum256([]byte("dsse-organization-transport-name\x1f" + id))
		id = strings.ToLower(organizationIDEncoding.EncodeToString(sum[:organizationIDBytes]))
	}
	return id + "." + suffix
}

// organizationIDIsMinted says whether an id came from newOrganizationID — 128 bits of base32 — rather than
// from the era when it was the display name with the spaces taken out.
//
// Shape, not a registry: the ids that predate the minting are in stores this function cannot reach, and a
// check that needed a lookup would answer differently on a node that had not loaded one.
//
// ★ AND IT ERRS TOWARDS "LEGACY", which is the harmless direction. The first version accepted any 26
// characters of a–z2–7 — and a company slug of exactly 26 letters passes that, which the test beside this
// caught. So a base32 digit is required as well: a random 128-bit id contains one about 99.6% of the time,
// and the 0.4% that do not are simply FOLDED, giving a name that is opaque and stable exactly like every
// other. Nothing already created moves either way, because the name is stored when the authority is created
// and only derived when one is omitted. Being wrong towards folding costs a readable correspondence between
// an id and its name; being wrong the other way puts a customer's name back on the wire.
func organizationIDIsMinted(tenantID string) bool {
	id := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(tenantID)), "tenant_")
	if len(id) != organizationIDEncoding.EncodedLen(organizationIDBytes) {
		return false
	}
	digit := false
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '2' && r <= '7':
			digit = true
		default:
			return false
		}
	}
	return digit
}

// deploymentNameSuffix is the DNS suffix this deployment's per-organization names sit under.
//
// It has its OWN flag rather than being read off the recovery name, because the two are set on different
// nodes: the recovery name is announced by an EDGE, and the organization whose name is being minted is created
// on the CONTROL PLANE. Measured 2026-08-21: deriving it from -renewal-recovery-sni left the control plane
// with an empty suffix, so creating an organization's authority still demanded a name typed in by hand — the
// exact thing the minted id exists to stop.
//
// The recovery name is still accepted as a fallback for a single-node deployment where one process is both.
var deploymentNameSuffixValue atomic.Value // string

func declareDeploymentNameSuffix(configured, recoverySNI string) {
	base := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(configured), ".")))
	if base == "" {
		base = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(recoverySNI)), recoveryNamePrefix)
	}
	deploymentNameSuffixValue.Store(base)
}

func deploymentNameSuffix() string {
	s, _ := deploymentNameSuffixValue.Load().(string)
	return s
}

// deploymentNameSuffixFlag is registered here rather than in main.go: new flags belong beside the thing they
// configure (docs/dev_advisory_2026-08-03_edge_main_split_plan.md).
var deploymentNameSuffixFlag = flag.String("deployment-name-suffix", "",
	"the DNS suffix this deployment's per-organization names sit under (e.g. \"dsse.invalid\"). An organization "+
		"created here is given an unguessable id, and the name its agents send is that id under this suffix — so "+
		"nobody has to invent one, and nothing derived from the customer's real name is offered on the transport "+
		"port. Falls back to the base of -renewal-recovery-sni when empty")
