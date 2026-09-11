package main

// interception_root.go — install the organization's interception root at INSTALL TIME, from the artifact.
//
// ★ WHY THE INSTALLER AND NOT A RUNBOOK (docs/pki_trust_model.md section 8.2). The trust an agent starts from cannot
// arrive over the network: it would have to be trusted before it arrives. Embedding it in the package removes
// that circle for the FIRST trust decision, and it makes a device's organization a property of the artifact it
// was installed from rather than of a runtime lookup — so an endpoint built for one organization cannot be
// talked onto another's authorities. The Edge half has been live since 2026-08-16
// (GET /admin/tenant-install-bundle/{tenant} answers with the transport anchors, that organization's
// interception root, and the signed bundle it starts from, in ONE answer). The packaging lane was the
// remaining half, and on Windows it was a person following
// docs/handoff_windows_interception_root_changed_to_hsm.ja.md by hand.
//
// The DECISION lives here, with no Windows in it, so the rule that decides whether a machine's trust store is
// modified is exercised by tests on any host rather than only where it runs. The store I/O is in
// interception_root_windows.go.

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

// parsedRoot is one certificate, identified the two ways that matter: by KEY (the fingerprint, which is what
// makes two certificates actually different) and by NAME (the subject, which is all a trust store shows).
type parsedRoot struct {
	DER        []byte
	SHA256     string
	Subject    string
	RawSubject []byte
}

func parseRoot(der []byte) (parsedRoot, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return parsedRoot{}, err
	}
	sum := sha256.Sum256(der)
	return parsedRoot{
		DER:        der,
		SHA256:     hex.EncodeToString(sum[:]),
		Subject:    c.Subject.String(),
		RawSubject: c.RawSubject,
	}, nil
}

// readInterceptionRoots parses every CERTIFICATE block in the file.
//
// More than one is accepted deliberately: a rotation's normal state is an OVERLAP carrying the old and the new
// authority together (section 8.2), so an installer produced during one has to be able to lay down both.
func readInterceptionRoots(path string) ([]parsedRoot, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var out []parsedRoot
	rest := raw
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		r, perr := parseRoot(block.Bytes)
		if perr != nil {
			return nil, fmt.Errorf("%s: a PEM CERTIFICATE block does not parse as a certificate: %w", path, perr)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		// A file with no certificate in it is a packaging mistake, and the failure it would otherwise produce
		// is "TLS is broken on this machine", hours later and somewhere else.
		return nil, fmt.Errorf("%s contains no PEM CERTIFICATE block", path)
	}
	return out, nil
}

// rootPlan is what installing WOULD do, decided before anything is written.
type rootPlan struct {
	Add            []parsedRoot
	AlreadyPresent []parsedRoot
}

// planRootInstall decides which incoming roots to add, and REFUSES the one state that has taken this product
// down twice.
//
// ★★ TWO AUTHORITIES UNDER ONE NAME IS THE OUTAGE, NOT AN UNTIDINESS. It happened on 2026-08-02 with two
// same-subject intermediates side by side, and again as the collision win-dev-1 found on 2026-08-16, where
// per_tenant held two roots both named "Lantern DSSE Interception Root" differing only by key. A trust store
// shows an operator the NAME. Two authorities carrying one name are indistinguishable there, so the operator
// cleaning up picks by coin flip and the wrong pick breaks every HTTPS site on the machine. The generator now
// names the organization, which prevents the NEXT collision and can do nothing about a store that already
// holds one — and nothing at all about a root a CUSTOMER supplied.
//
// So: adding the same certificate again is a no-op (that is a re-install). Adding a DIFFERENT certificate
// under a subject already present is refused, naming both fingerprints, because the resolution is a
// deliberate removal by fingerprint and an installer must not make that decision on an operator's behalf.
func planRootInstall(existing, incoming []parsedRoot) (rootPlan, error) {
	byFingerprint := map[string]bool{}
	bySubject := map[string][]string{}
	for _, e := range existing {
		byFingerprint[e.SHA256] = true
		key := string(e.RawSubject)
		bySubject[key] = append(bySubject[key], e.SHA256)
	}

	var plan rootPlan
	for _, in := range incoming {
		if byFingerprint[in.SHA256] {
			plan.AlreadyPresent = append(plan.AlreadyPresent, in)
			continue
		}
		if held := bySubject[string(in.RawSubject)]; len(held) > 0 {
			return rootPlan{}, fmt.Errorf("REFUSING to add a second certificate named %q: this machine already "+
				"trusts %d certificate(s) with that exact subject and a different key (%s), and the incoming one "+
				"is %s. A trust store shows an operator the NAME, so two authorities under one name are "+
				"indistinguishable there, and removing the wrong one breaks every HTTPS site on this machine — "+
				"this product has had that outage. Remove the superseded certificate deliberately, BY FINGERPRINT, "+
				"then install this one", in.Subject, len(held), strings.Join(held, " "), in.SHA256)
		}
		// A second incoming root under a subject an earlier incoming root just claimed is the same collision,
		// arriving in one file. Caught here so a malformed bundle cannot walk past the rule.
		bySubject[string(in.RawSubject)] = []string{in.SHA256}
		byFingerprint[in.SHA256] = true
		plan.Add = append(plan.Add, in)
	}
	return plan, nil
}
