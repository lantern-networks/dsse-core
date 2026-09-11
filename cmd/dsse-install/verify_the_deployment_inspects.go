package main

// verify_the_deployment_inspects.go — every Edge signs intercepted traffic, under ONE authority, and that
// authority is this deployment's.
//
// ★★★ THE THIRD TIER WAS MISSING AND NOTHING SAID SO (2026-08-26, reported from real hardware as letter 105).
// The architecture names three tiers — transport, device-identity, interception — the installer minted two,
// and the generated start script did not contain the word interception. The organization checklist answered
// "done 4/13, blocking []" on a deployment where no traffic had ever been decrypted, because a step nobody
// can see reads exactly like a step that is finished.
//
// Three things have to be true and each fails differently:
//
//	an authority exists          -> without it the Edge inspects nothing at all
//	every Edge reports the SAME  -> the engine mints its own when it finds none, so a node that missed the
//	                                material signs under a root no device has heard of and no sibling shares
//	it chains to this deployment -> otherwise it is a second authority beside the first, and a device that
//	                                trusts this deployment's anchor is refused by its own Edge
//
// The middle one is the reason this asks every Edge rather than one: a fleet where each node invented its own
// root looks perfectly healthy from any single node.

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// verifyTheDeploymentInspects asks every Edge for the authority it signs intercepted traffic with.
func verifyTheDeploymentInspects(client *http.Client, dir string, edgeAdmins []string, adminToken string) []verifyResult {
	if len(edgeAdmins) == 0 {
		return nil
	}
	anchor, err := deploymentAnchorPool(dir)
	if err != nil {
		return []verifyResult{{name: "the deployment inspects", ok: false,
			note: fmt.Sprintf("could not read this deployment's anchor: %v", err)}}
	}

	seen := map[string][]string{} // fingerprint-ish key (the PEM) -> the Edges reporting it
	missing := []string{}
	for _, admin := range edgeAdmins {
		admin = strings.TrimRight(strings.TrimSpace(admin), "/")
		if admin == "" {
			continue
		}
		status, body, err := get(client, admin+"/admin/interception-roots", adminToken)
		if err != nil || status != http.StatusOK {
			missing = append(missing, fmt.Sprintf("%s (HTTP %d %v)", admin, status, err))
			continue
		}
		var answer struct {
			DefaultRootPEM string `json:"default_root_pem"`
		}
		if jerr := json.Unmarshal(body, &answer); jerr != nil || strings.TrimSpace(answer.DefaultRootPEM) == "" {
			missing = append(missing, admin+" (reports no interception authority — it inspects NOTHING)")
			continue
		}
		seen[answer.DefaultRootPEM] = append(seen[answer.DefaultRootPEM], admin)
	}

	out := []verifyResult{}
	switch {
	case len(seen) == 0:
		out = append(out, verifyResult{name: "the deployment inspects", ok: false,
			note: "no Edge reports an interception authority, so nothing is being decrypted anywhere in this " +
				"deployment: " + strings.Join(missing, "; ")})
		return out
	case len(missing) > 0:
		out = append(out, verifyResult{name: "the deployment inspects", ok: false,
			note: "some Edges have no interception authority and inspect NOTHING, while others do — a device " +
				"is decrypted or not depending on which node its flows land on: " + strings.Join(missing, "; ")})
	case len(seen) > 1:
		out = append(out, verifyResult{name: "every Edge signs under the same DEFAULT authority", ok: false,
			note: fmt.Sprintf("this deployment has %d different interception authorities. The engine mints its "+
				"own when it finds no material, so a node that was missed signs under a root no device has "+
				"heard of: %s", len(seen), describeAuthoritiesByEdge(seen))})
	default:
		// ★★★ SAYING WHAT THIS IS NOT (2026-08-27). Read as a headline, "under ONE authority — ok" endorses
		// the thing an organization must never have: every customer decrypted by the same key. It is about
		// the FLEET — an Edge that was missed mints its own root and signs under one no device has heard of —
		// and it is silent about whether an organization can be given its own. That is asked separately.
		out = append(out, verifyResult{name: "every Edge signs under the same DEFAULT authority", ok: true,
			note: fmt.Sprintf("all %d Edge(s) agree, so no node was missed and left minting its own. This says "+
				"nothing about whether an ORGANIZATION can have its own authority — that is the next check",
				len(edgeAdmins))})
	}

	// Whatever they reported, it has to be THIS deployment's — a device trusts the anchor and nothing else.
	for rootPEM, admins := range seen {
		cert, perr := certificateFromPEM(rootPEM)
		if perr != nil {
			out = append(out, verifyResult{name: "the interception authority is this deployment's", ok: false,
				note: fmt.Sprintf("%s reports something that is not a certificate: %v", strings.Join(admins, ", "), perr)})
			continue
		}
		if _, verr := cert.Verify(x509.VerifyOptions{Roots: anchor, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); verr != nil {
			out = append(out, verifyResult{name: "the interception authority is this deployment's", ok: false,
				note: fmt.Sprintf("%q does not chain to this deployment's anchor (%v) — every device that trusts "+
					"this deployment would be refused by its own Edge", cert.Subject.CommonName, verr)})
			continue
		}
		out = append(out, verifyResult{name: "the interception authority is this deployment's", ok: true,
			note: fmt.Sprintf("%q chains to this deployment's anchor, so a device that already trusts this "+
				"deployment needs to be told nothing new", cert.Subject.CommonName)})
	}
	return out
}

func certificateFromPEM(raw string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(raw))
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// describeAuthoritiesByEdge names which Edges share which authority, so a split fleet says where the split is.
func describeAuthoritiesByEdge(seen map[string][]string) string {
	groups := []string{}
	for rootPEM, admins := range seen {
		name := "unparseable"
		if cert, err := certificateFromPEM(rootPEM); err == nil {
			name = cert.Subject.CommonName + " " + cert.SerialNumber.String()
		}
		sort.Strings(admins)
		groups = append(groups, name+" on "+strings.Join(admins, ", "))
	}
	sort.Strings(groups)
	return strings.Join(groups, " | ")
}
