package installprofile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// selfSigned mints a throwaway CA so the tests measure the derivation rather than a fixture's spelling.
func selfSigned(t *testing.T, cn string) (pemText string, fingerprint string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	sum := sha256.Sum256(der)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), hex.EncodeToString(sum[:])
}

// THE ANCHOR IS BOTH AUTHORITIES. This is the defect the hikari.lab walk was stopped by: the profile told the
// device to present its organization's own name, and the anchor it was handed could not verify the certificate
// served for that name. A derivation that returns only the deployment root reproduces it exactly.
func TestTheAnchorCarriesTheDeploymentRootAndTheOrganizationsOwnTransportCA(t *testing.T) {
	root, rootFP := selfSigned(t, "Deployment Root CA")
	orgCA, orgFP := selfSigned(t, "acme.example Transport CA")

	m, err := DeriveDeployment(DeploymentSpec{
		AnchorPEM:           root,
		TransportAnchorsPEM: []string{orgCA},
	})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(m.TransportAnchorsPEM) {
		t.Fatal("the derived anchor bundle has no usable certificate")
	}
	if got := m.AnchorFingerprints; len(got) != 2 || got[0] != rootFP || got[1] != orgFP {
		t.Fatalf("anchor fingerprints = %v, want [%s %s] — the deployment root FIRST, then the organization's own",
			got, rootFP, orgFP)
	}
	if !strings.Contains(strings.Join(m.AnchorSubjects, "|"), "acme.example Transport CA") {
		t.Fatalf("subjects = %v — the startup line must be able to name what is in force, not count it", m.AnchorSubjects)
	}
}

// A blob that arrives without a trailing newline must not silently swallow the next one. The profile is JSON
// and its PEM carries whatever the issuer's platform wrote; re-encoding is what makes the join total.
func TestAnchorsJoinEvenWhenTheProfilesPEMHasNoTrailingNewline(t *testing.T) {
	root, _ := selfSigned(t, "Deployment Root CA")
	orgCA, _ := selfSigned(t, "acme.example Transport CA")

	m, err := DeriveDeployment(DeploymentSpec{
		AnchorPEM:           strings.TrimRight(root, "\n"),
		TransportAnchorsPEM: []string{strings.TrimRight(orgCA, "\n")},
	})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(m.AnchorFingerprints) != 2 {
		t.Fatalf("anchors = %d, want 2 — a missing newline joined two certificates into an unparseable one",
			len(m.AnchorFingerprints))
	}
}

// The same authority named twice is one anchor. A rotation that lists the outgoing CA in both fields is
// ordinary, and a duplicate in the pool is a second thing to reconcile for no gain.
func TestARepeatedAuthorityIsCarriedOnce(t *testing.T) {
	root, rootFP := selfSigned(t, "Deployment Root CA")
	m, err := DeriveDeployment(DeploymentSpec{
		AnchorPEM:           root,
		TransportAnchorsPEM: []string{root},
	})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if len(m.AnchorFingerprints) != 1 || m.AnchorFingerprints[0] != rootFP {
		t.Fatalf("fingerprints = %v, want exactly [%s]", m.AnchorFingerprints, rootFP)
	}
}

// A PEM field that holds no certificate is a configuration error, and the error must name the FIELD. A profile
// has three certificate-bearing fields; "invalid certificate" costs a round trip to localise.
func TestAFieldThatHoldsNoCertificateIsRefusedByName(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	root, _ := selfSigned(t, "Deployment Root CA")

	for _, tc := range []struct {
		name  string
		spec  DeploymentSpec
		wants string
	}{
		{"the anchor", DeploymentSpec{AnchorPEM: keyPEM}, "deployment.anchor_pem"},
		{"a transport anchor", DeploymentSpec{
			AnchorPEM: root, TransportAnchorsPEM: []string{root, keyPEM},
		}, "deployment.transport_anchors_pem[1]"},
		{"the interception root", DeploymentSpec{
			AnchorPEM: root, InterceptionRootPEM: keyPEM,
		}, "deployment.interception_root_pem"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DeriveDeployment(tc.spec)
			if err == nil {
				t.Fatal("a field holding a private key was accepted as an anchor")
			}
			if !strings.Contains(err.Error(), tc.wants) {
				t.Fatalf("error %q does not name the field %q", err, tc.wants)
			}
			if !strings.Contains(err.Error(), "PRIVATE KEY") {
				t.Fatalf("error %q does not say what it found instead", err)
			}
		})
	}
}

// Every profile issued before the deployment block existed lacks one, and those devices were provisioned by
// hand. An absent block must leave what they already have alone rather than blanking it.
func TestAProfileWithNoDeploymentBlockIsNotAnError(t *testing.T) {
	m, err := DeriveDeployment(DeploymentSpec{})
	if err != nil {
		t.Fatalf("an absent deployment block must not be an error: %v", err)
	}
	if m.Present() {
		t.Fatal("an absent deployment block reported material to install")
	}
}

// A profile that names a door and no authority for it describes a dial that cannot succeed. Say so where the
// document is read, not as an unexplained handshake failure at every start.
func TestAnAnchorWithNoOrganizationAuthoritySaysWhatItCannotVerify(t *testing.T) {
	root, _ := selfSigned(t, "Deployment Root CA")
	m, err := DeriveDeployment(DeploymentSpec{AnchorPEM: root})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	joined := strings.Join(m.AnchorSubjects, "|")
	if !strings.Contains(joined, "transport_anchors_pem") {
		t.Fatalf("subjects = %v — nothing said this device can only verify the shared certificate", m.AnchorSubjects)
	}
}

// THE CONDITION THAT WAS SILENT. An adopted distribution that does not cover the doors the profile names is the
// exact state this box reached while reporting ADOPTED. The comparison has to exist for anything to report it.
func TestAnAdoptedSetMissingTheProfilesAnchorsIsDetectable(t *testing.T) {
	_, rootFP := selfSigned(t, "Deployment Root CA")
	_, orgFP := selfSigned(t, "acme.example Transport CA")
	_, strangerFP := selfSigned(t, "Some Other Tenant Transport CA")

	if missing := MissingAnchors([]string{rootFP, orgFP}, []string{rootFP, orgFP}); len(missing) != 0 {
		t.Fatalf("a covering set reported %v missing", missing)
	}
	missing := MissingAnchors([]string{rootFP, strangerFP}, []string{rootFP, orgFP})
	if len(missing) != 1 || missing[0] != orgFP {
		t.Fatalf("missing = %v, want exactly [%s] — the organization's own authority is the one absent", missing, orgFP)
	}
}

// Case must not decide the answer: fingerprints are compared, and they are hex either way.
func TestTheAnchorComparisonIsNotCaseSensitive(t *testing.T) {
	_, fp := selfSigned(t, "Deployment Root CA")
	if missing := MissingAnchors([]string{strings.ToUpper(fp)}, []string{strings.ToLower(fp)}); len(missing) != 0 {
		t.Fatalf("the same anchor spelled in two cases reported %v missing", missing)
	}
}

// The two sides of that comparison must be computed the same way, or they agree until one is edited.
func TestFingerprintsOfAgreesWithTheDerivation(t *testing.T) {
	root, rootFP := selfSigned(t, "Deployment Root CA")
	m, err := DeriveDeployment(DeploymentSpec{AnchorPEM: root})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	certs, err := ParseCertificates(m.TransportAnchorsPEM)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got := Fingerprints(certs); len(got) != 1 || got[0] != rootFP || m.AnchorFingerprints[0] != rootFP {
		t.Fatalf("Fingerprints=%v derivation=%v want [%s]", got, m.AnchorFingerprints, rootFP)
	}
}

// The pins and the authored policy come across, because the alternative is a command line no installed service
// has. An empty exclusion list is the whole list and must stay distinguishable from "not carried".
func TestThePinsAndTheAuthoredPolicyComeAcross(t *testing.T) {
	root, _ := selfSigned(t, "Deployment Root CA")
	m, err := DeriveDeployment(DeploymentSpec{
		AnchorPEM:                   root,
		DeviceCAPinSHA256:           " 4c129d79 ",
		AgentPolicySigningPublicKey: " 0ae740bd ",
		UpdateSigningKeys:           []string{"f95090bb", "  ", ""},
		UpdatePublisherTeamID:       " M4U8GSBL6C ",
		SteerExclusions:             []string{"subject:Contoso", ""},
		PassthroughDomains:          []string{"bank.example"},
	})
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	if m.DeviceCAPin != "4c129d79" || m.AgentPolicyPin != "0ae740bd" || m.UpdatePublisherTeamID != "M4U8GSBL6C" {
		t.Fatalf("pins not trimmed: %+v", m)
	}
	if len(m.UpdateSigningKeys) != 1 || m.UpdateSigningKeys[0] != "f95090bb" {
		t.Fatalf("update keys = %v — blank entries must not become pins", m.UpdateSigningKeys)
	}
	if len(m.SteerExclusions) != 1 || m.SteerExclusions[0] != "subject:Contoso" {
		t.Fatalf("exclusions = %v", m.SteerExclusions)
	}
	if len(m.PassthroughDomains) != 1 {
		t.Fatalf("passthrough = %v", m.PassthroughDomains)
	}
	if !m.Present() {
		t.Fatal("material carrying an anchor and two pins reported nothing to install")
	}
}
