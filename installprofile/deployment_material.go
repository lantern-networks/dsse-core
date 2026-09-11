package installprofile

// deployment_material.go — turning the signed profile's `deployment` block into the files this device verifies
// against. The Windows half of what the macOS pkg's postinstall does in derive_config_from_profile.
//
// ★★★ WHY THIS EXISTS (2026-08-29, measured on win-dev-1 against the hikari.lab two-site deployment).
//
// A customer receives three things: an installer, a signed profile, and a one-time token. Until the profile
// grew a `deployment` block, that was not enough on Windows — the anchor the device verifies every Edge
// against, its organization's interception root, its device-CA pin and the update pins all had to arrive some
// other way, and nothing in the product produced them. The lab put them there by hand. A customer has no hand
// in this lab.
//
// ★★ AND THE ANCHOR IS TWO AUTHORITIES, NOT ONE. An organization with its own address is served a certificate
// from its OWN transport CA — `CN=<name> Transport CA` — which the deployment root does not sign. The profile
// tells the device to present that name; handing it only the deployment root makes every dial fail with
// "certificate signed by unknown authority", and on this box that turned into something worse than a failure:
// the device fell back to an unnamed trust-bundle fetch, was answered with the DEPLOYMENT's own organization,
// and adopted anchors naming the deployment's root as its interception authority. It reported ADOPTED. Every
// screen was green, and the organization's own inspection authority was not the one in force.
//
// So the bundle is `anchor_pem` + `transport_anchors_pem`, concatenated, and both doors verify against it.
//
// This file is deliberately platform-neutral: the derivation is a value computation over the profile, testable
// on any host, and only the writing of the files is a Windows act. A platform-specific implementation that
// bypasses the shared seam is how this package has previously turned a defect into "green on Linux CI, red on
// the one box that runs it".

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
)

// DeploymentMaterial is what a device can be provisioned with from the profile alone. Every field is a
// public fact — certificates, fingerprints and public keys. The one-time enrolment token is deliberately NOT
// here: it is the only secret, it says this device is this device, and it travels separately.
type DeploymentMaterial struct {
	// TransportAnchorsPEM verifies the Edge, whichever door this device is told to knock on: the deployment's
	// root followed by the authorities that sign this organization's own name. Empty when the profile carries
	// no deployment block at all.
	TransportAnchorsPEM []byte
	// InterceptionRootPEM is the organization's own inspection root. Writing it to a file is not the same as
	// trusting it — putting it where the operating system looks is a separate act, and this only carries it.
	InterceptionRootPEM []byte
	// AgentPolicyPin, DeviceCAPin, UpdateSigningKeys and UpdatePublisherTeamID are the values the operator
	// would otherwise have had to pass on a command line that no installed service has.
	// StepUpPortalCertificateIsOperators carries DeploymentSpec's field of the same name to the code that
	// provisions a device: when it is true the device adds NOTHING to its trust store for the step-up portal.
	StepUpPortalCertificateIsOperators bool
	// StepUpPortalAnchorPEM is the authority the step-up portal is actually served under, for the case where
	// the operator has not supplied their own certificate for it.
	//
	// ★★★ MEASURED, AFTER SHIPPING THE OPPOSITE (2026-09-03, on the Windows box, from the real portal). This
	// used to be chosen on the device by NAME — the organization's own transport CA — because the design says
	// the portal is served on the organization's certificate. It is not. The portal's URL defaults to the
	// deployment's agent-plane name (DSSE_CLIENTLESS_BASE_URL), so the Edge's SNI selection never reaches the
	// organization's certificate and serves the deployment's:
	//
	//   portal chain      CN=keyaki.lab <- Keyaki Networks Transport CA <- Keyaki Networks Root CA
	//   organization CA   verify -> 20 (unable to get local issuer certificate)
	//   deployment root   verify -> 0  (ok)
	//
	// The device was trusting an authority the portal never presents, and not trusting the one it does. So the
	// profile now NAMES the anchor rather than leaving a device to infer it: whoever serves the portal decides
	// what verifies it, and that is knowable where the portal is configured, not on the device.
	StepUpPortalAnchorPEM []byte
	AgentPolicyPin        string
	DeviceCAPin           string
	UpdateSigningKeys     []string
	UpdatePublisherTeamID string
	// SteerExclusions and PassthroughDomains are the authored policy. This product ships zero built-in
	// exclusions on purpose, so an empty list here is the whole list — and a caller that arms steering on an
	// empty list should say so rather than discover it later.
	SteerExclusions    []string
	PassthroughDomains []string
	// AnchorSubjects names, in order, what went into TransportAnchorsPEM. It exists so the startup line can say
	// WHICH authorities are in force rather than how many, because a count cannot be reconciled with anything.
	AnchorSubjects []string
	// AnchorFingerprints are the SHA-256 of the DER of each anchor, same order as AnchorSubjects. A name is not
	// evidence; this is what an operator compares against what the deployment announced.
	AnchorFingerprints []string
}

// Present reports whether the profile carried anything at all. A profile without a deployment block is not an
// error — every profile issued before 2026-08-29 lacks one, and those devices were provisioned by hand — so the
// caller keeps whatever it already has rather than blanking it.
func (m DeploymentMaterial) Present() bool {
	return len(m.TransportAnchorsPEM) > 0 || len(m.InterceptionRootPEM) > 0 ||
		strings.TrimSpace(m.AgentPolicyPin) != "" || strings.TrimSpace(m.DeviceCAPin) != ""
}

// DeriveDeployment turns the profile's deployment block into the material above.
//
// It fails LOUDLY and BY NAME. A PEM field that carries no certificate is a configuration error the operator
// must see: the alternative measured on this product is a device that starts, verifies nothing, and reports the
// same silence as a device that was never given anything. Which field was wrong is part of the error, because
// "invalid certificate" in a document with three certificate fields is a message that costs a round trip.
func DeriveDeployment(d DeploymentSpec) (DeploymentMaterial, error) {
	var m DeploymentMaterial

	inputs := append([]namedPEM{{"deployment.anchor_pem", d.AnchorPEM}},
		namedPEMs("deployment.transport_anchors_pem", d.TransportAnchorsPEM)...)
	anchors, subjects, fps, err := concatCertPEMs(inputs...)
	if err != nil {
		return DeploymentMaterial{}, err
	}
	m.TransportAnchorsPEM, m.AnchorSubjects, m.AnchorFingerprints = anchors, subjects, fps
	m.StepUpPortalCertificateIsOperators = d.StepUpPortalCertificateIsOperators
	if !d.StepUpPortalCertificateIsOperators {
		// The profile names it now; AnchorPEM is the fallback for a profile issued before it did.
		if named := strings.TrimSpace(d.StepUpPortalAnchorPEM); named != "" {
			m.StepUpPortalAnchorPEM = []byte(named)
		} else {
			m.StepUpPortalAnchorPEM = []byte(strings.TrimSpace(d.AnchorPEM))
		}
	}

	// ★ THE ORGANIZATION'S OWN NAME NEEDS ITS OWN AUTHORITY. A profile that tells the device to present a name
	// and names only the deployment root describes a dial that cannot succeed. Saying so here — where the
	// document is read — beats discovering it as an unexplained handshake failure at every start.
	if strings.TrimSpace(d.AnchorPEM) != "" && len(d.TransportAnchorsPEM) == 0 {
		m.AnchorSubjects = append(m.AnchorSubjects,
			"(no deployment.transport_anchors_pem — this device can verify only the deployment's shared certificate)")
	}

	if strings.TrimSpace(d.InterceptionRootPEM) != "" {
		root, _, _, err := concatCertPEMs(namedPEM{"deployment.interception_root_pem", d.InterceptionRootPEM})
		if err != nil {
			return DeploymentMaterial{}, err
		}
		m.InterceptionRootPEM = root
	}

	m.AgentPolicyPin = strings.TrimSpace(d.AgentPolicySigningPublicKey)
	m.DeviceCAPin = strings.TrimSpace(d.DeviceCAPinSHA256)
	m.UpdatePublisherTeamID = strings.TrimSpace(d.UpdatePublisherTeamID)
	m.UpdateSigningKeys = trimmedNonEmpty(d.UpdateSigningKeys)
	m.SteerExclusions = trimmedNonEmpty(d.SteerExclusions)
	m.PassthroughDomains = trimmedNonEmpty(d.PassthroughDomains)
	return m, nil
}

// namedPEM pairs a PEM blob with the profile field it came from, so an error can name the field.
type namedPEM struct {
	field string
	pem   string
}

func namedPEMs(field string, blobs []string) []namedPEM {
	out := make([]namedPEM, 0, len(blobs))
	for i, b := range blobs {
		out = append(out, namedPEM{fmt.Sprintf("%s[%d]", field, i), b})
	}
	return out
}

// concatCertPEMs parses each blob, drops exact duplicates, and re-encodes the survivors in order. It
// re-encodes rather than concatenating the input text because the profile is JSON and its PEM arrives with
// whatever line endings the issuer's platform used; a trailing newline that is missing on one blob and present
// on the next is enough to make the join unparseable, and that failure looks like a bad certificate.
func concatCertPEMs(blobs ...namedPEM) (out []byte, subjects []string, fingerprints []string, err error) {
	var buf bytes.Buffer
	seen := map[string]bool{}
	for _, b := range blobs {
		text := strings.TrimSpace(b.pem)
		if text == "" {
			continue
		}
		certs, perr := ParseCertificates([]byte(text))
		if perr != nil {
			return nil, nil, nil, fmt.Errorf("%s: %w", b.field, perr)
		}
		for _, c := range certs {
			sum := sha256.Sum256(c.Raw)
			fp := hex.EncodeToString(sum[:])
			if seen[fp] {
				continue
			}
			seen[fp] = true
			if werr := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); werr != nil {
				return nil, nil, nil, fmt.Errorf("%s: re-encode: %w", b.field, werr)
			}
			subjects = append(subjects, c.Subject.String())
			fingerprints = append(fingerprints, fp)
		}
	}
	return buf.Bytes(), subjects, fingerprints, nil
}

// ParseCertificates returns every certificate in a PEM blob, and an error naming what it found instead when
// there is none. "no certificates" and "a private key where a certificate should be" are different mistakes and
// an operator fixes them differently.
func ParseCertificates(blob []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	var otherTypes []string
	rest := blob
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			otherTypes = append(otherTypes, block.Type)
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("a PEM CERTIFICATE block that does not parse: %w", err)
		}
		certs = append(certs, c)
	}
	if len(certs) == 0 {
		if len(otherTypes) > 0 {
			sort.Strings(otherTypes)
			return nil, fmt.Errorf("no CERTIFICATE block — this field holds %s", strings.Join(dedupeStrings(otherTypes), ", "))
		}
		return nil, fmt.Errorf("no PEM certificate found")
	}
	return certs, nil
}

func dedupeStrings(in []string) []string {
	out := in[:0:0]
	seen := map[string]bool{}
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func trimmedNonEmpty(in []string) []string {
	var out []string
	for _, s := range in {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// MissingAnchors reports whether every fingerprint the profile names is present in have. It is how the
// startup path decides whether an ADOPTED anchor set still covers the doors this profile tells the device to
// knock on — the condition that, when it silently did not hold, left this box carrying another organization's
// authority while reporting that it had adopted a distribution.
func MissingAnchors(have []string, want []string) (missing []string) {
	present := map[string]bool{}
	for _, h := range have {
		present[strings.ToLower(strings.TrimSpace(h))] = true
	}
	for _, w := range want {
		k := strings.ToLower(strings.TrimSpace(w))
		if k == "" || present[k] {
			continue
		}
		missing = append(missing, k)
	}
	return missing
}

// Fingerprints is the same measurement applied to parsed certificates, so both sides of the comparison above
// are computed the same way rather than by two functions that agree until one is edited.
func Fingerprints(certs []*x509.Certificate) []string {
	out := make([]string, 0, len(certs))
	for _, c := range certs {
		sum := sha256.Sum256(c.Raw)
		out = append(out, hex.EncodeToString(sum[:]))
	}
	return out
}
