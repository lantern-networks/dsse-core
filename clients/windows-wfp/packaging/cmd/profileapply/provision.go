package main

// provision.go — turning the two things a customer receives into the configuration a device runs on.
//
// ★★★ WHAT THE CUSTOMER ACTUALLY HAS (2026-08-29, measured by walking it on win-dev-1). The stated shape is
// three things: an installer, a signed profile downloaded from the Console, and a one-time token shown once.
// On Windows that was not true. The profile, the deployment anchor, the organization's interception root, the
// device-CA pin and the update pins were all BUILD-TIME inputs to build-msi.ps1 — so a customer needed a
// package built for their organization, which means the vendor builds one package per customer and re-signs it,
// and the "deployment-independent installer" in the description does not exist.
//
// Worse, nothing at all produced enrolment.json. The agent has a self-enrolment gate that reads it and enrols
// on first start; on Windows the file could only be written by hand. Every walk of this lane had been done by a
// person with a shell, which is why the gap survived.
//
// So this is the derivation, and its inputs are exactly the two artefacts the Console hands over:
//
//	profileapply --provision --config install_profile.json [--token enrolment_token.txt]
//
// Everything else comes out of the profile's `deployment` block, which is public by construction — an anchor,
// two fingerprints, a public root and two public keys. The token stays separate because it is the only secret
// and the only thing that says this device is this device.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lantern-networks/dsse-core/installprofile"
)

// enrolmentSeed is the file the agent's enrolment gate reads on first start. The field names are the agent's,
// not ours: this is the same document the macOS agent config carries, and a second spelling of it would be a
// second thing to keep true.
type enrolmentSeed struct {
	EnrolURL          string `json:"enrol_url"`
	DeviceID          string `json:"device_id,omitempty"`
	Token             string `json:"enrolment_token"`
	Tenant            string `json:"tenant,omitempty"`
	EnrolCAPEM        string `json:"enrol_ca_pem,omitempty"`
	DeviceCAPinSHA256 string `json:"device_ca_pin_sha256,omitempty"`
}

// provisionPlan is what a provision would write, computed before anything is written.
//
// Separated from the writing so the decision is testable on any host and so a partially-applied provision is
// not a thing that can happen from a bad profile: everything is derived and validated first, and only then does
// the disk change.
type provisionPlan struct {
	AnchorsPEM []byte
	// OrganizationTransportServerName is the name this organization's own transport authority is issued for.
	// It is how the anchor that belongs to THIS organization is told from anything else in the bundle — see
	// organization_anchor.go, and the rule that replaced a shape-based guess with it.
	OrganizationTransportServerName string
	// StepUpPortalCertificateIsOperators says the deployment's step-up portal is served on a certificate the
	// operator provided. When it is, this machine trusts NOTHING extra to complete a step-up — see
	// organization_anchor.go and the field's note in installprofile.
	StepUpPortalCertificateIsOperators bool
	// StepUpPortalAnchorPEM is the authority that portal is served under, named by the profile rather than
	// guessed here — see DeploymentMaterial for what guessing it cost.
	StepUpPortalAnchorPEM []byte
	InterceptionRootPEM   []byte
	Seed                  *enrolmentSeed
	AgentPolicyPin        string
	UpdateSigningKeys     []string
	UpdatePublisherID     string
	Notes                 []string
}

// planProvision derives everything from the verified profile and the token.
//
// ★ IT REFUSES BY NAME, AND IT REFUSES EARLY. A profile that cannot produce a working device is an authoring
// mistake somebody has to fix, and the shape this product keeps paying for is the one where that mistake
// installs cleanly and fails later as a TLS error with no author in it.
func planProvision(p installprofile.InstallProfile, token string) (provisionPlan, error) {
	var plan provisionPlan

	m, err := installprofile.DeriveDeployment(p.Deployment)
	if err != nil {
		return provisionPlan{}, err
	}
	if !m.Present() {
		return provisionPlan{}, fmt.Errorf(
			"this profile carries no deployment block, so it cannot provision a device on its own — it was " +
				"issued before the Console put the deployment's own facts in the profile. Download a new one, " +
				"or install a package built for this organization (build-msi.ps1 -Profile/-TransportCA/-InterceptionRoot)")
	}
	if len(m.TransportAnchorsPEM) == 0 {
		return provisionPlan{}, fmt.Errorf(
			"deployment.anchor_pem is empty, so this device would have nothing to verify its Edge with and " +
				"every dial would fail closed")
	}
	plan.AnchorsPEM = m.TransportAnchorsPEM
	plan.InterceptionRootPEM = m.InterceptionRootPEM
	plan.StepUpPortalCertificateIsOperators = m.StepUpPortalCertificateIsOperators
	plan.StepUpPortalAnchorPEM = m.StepUpPortalAnchorPEM
	plan.OrganizationTransportServerName = strings.TrimSpace(p.Organization.TransportServerName)
	plan.AgentPolicyPin = m.AgentPolicyPin
	plan.UpdateSigningKeys = m.UpdateSigningKeys
	plan.UpdatePublisherID = m.UpdatePublisherTeamID
	plan.Notes = append(plan.Notes, fmt.Sprintf("transport anchors: %d", len(m.AnchorFingerprints)))
	for i, s := range m.AnchorSubjects {
		fp := ""
		if i < len(m.AnchorFingerprints) {
			fp = " sha256=" + m.AnchorFingerprints[i]
		}
		plan.Notes = append(plan.Notes, "  "+s+fp)
	}
	if len(m.InterceptionRootPEM) == 0 {
		plan.Notes = append(plan.Notes,
			"no deployment.interception_root_pem — this organization's Edges do not inspect, or the profile predates the field")
	}

	// The token is optional: a fleet enrolled by MDM, or a device being re-provisioned with an identity it
	// already holds, has no token to spend and must not be refused for it.
	if strings.TrimSpace(token) == "" {
		plan.Notes = append(plan.Notes, "no enrolment token supplied — this device will not enrol itself; "+
			"it must already hold an identity, or one must be delivered another way")
		return plan, nil
	}

	transport := strings.TrimSpace(p.TransportURL)
	if transport == "" {
		return provisionPlan{}, fmt.Errorf(
			"a token was supplied but the profile names no transport_url, so there is no address to enrol against")
	}
	seed := &enrolmentSeed{
		EnrolURL:          strings.TrimRight(transport, "/") + "/enroll",
		Token:             strings.TrimSpace(token),
		Tenant:            strings.TrimSpace(p.TenantID),
		EnrolCAPEM:        string(m.TransportAnchorsPEM),
		DeviceCAPinSHA256: m.DeviceCAPin,
	}
	// The device_id is deliberately absent: a machine already has a name, and the agent reads its own rather
	// than having one invented for it here (see defaultDeviceIdentity). Writing one would make the installer a
	// second place that decides what this machine is called.

	// ★ THE BOOTSTRAP MUST BE PINNED, AND THIS IS WHERE THAT IS KNOWABLE. Enrolment is the trust bootstrap; the
	// agent refuses to run it over an unpinned channel. Both pins come from the same profile, so a profile that
	// carries neither produces a device that will refuse to enrol — said here, at install, rather than as a
	// refusal on a machine nobody is watching.
	if seed.EnrolCAPEM == "" && seed.DeviceCAPinSHA256 == "" {
		return provisionPlan{}, fmt.Errorf(
			"this profile pins neither the enrol endpoint's CA (deployment.anchor_pem) nor the device CA " +
				"(deployment.device_ca_pin_sha256), and the agent refuses to enrol over an unpinned channel")
	}
	plan.Seed = seed
	plan.Notes = append(plan.Notes, "enrolment seed: "+seed.EnrolURL+" (organization "+seed.Tenant+")")
	return plan, nil
}

// readTokenFile reads the one-time token. It accepts either the raw secret or a file holding it, trims the
// whitespace an operator's copy-paste or a text editor's trailing newline adds, and refuses a file that holds
// something that cannot be a token — an empty file is the mistake this catches, and it is a common one.
func readTokenFile(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		return "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read enrolment token %q: %w", path, err)
	}
	t := strings.TrimSpace(string(raw))
	if t == "" {
		return "", fmt.Errorf("the enrolment token file %q is empty — a token is shown once and cannot be "+
			"retrieved later, so this device has nothing to enrol with", path)
	}
	if strings.ContainsAny(t, " \t\r\n") {
		return "", fmt.Errorf("the enrolment token file %q holds more than one value — it must contain the "+
			"single secret the Console displayed", path)
	}
	return t, nil
}

// writeSeed persists the enrolment seed beside the identity it will produce, with a DACL-free but
// admin-directory placement: %ProgramData%\DSSE\enroll is created by the installer and inherits the machine
// data directory's protection.
//
// ★ IT DOES NOT OVERWRITE AN EXISTING SEED OR IDENTITY. A device that has already enrolled holds a private key
// this file cannot reproduce; dropping a fresh token beside it would either spend a second approval for a
// machine that needs none, or — worse on a re-install — look like the machine is unenrolled and start a second
// identity for the same box. Re-provisioning an enrolled device is a deliberate act with its own path.
func writeSeed(enrollDir string, seed *enrolmentSeed) (string, error) {
	return writeSeedForOrganization(enrollDir, seed, "")
}

// writeSeedForOrganization is writeSeed told which organization this device is being installed for, so an
// identity belonging to a DIFFERENT one does not suppress the seed.
//
// ★★★ THE REFUSAL BELOW WAS RIGHT FOR A RE-INSTALL AND WRONG FOR A MOVE (2026-08-30). Declining to write a
// seed beside an existing identity stops a re-install spending an approval for a machine that needs none. A
// device moved to ANOTHER deployment also holds an identity — one issued by the old organization's device CA,
// which the new Edge has no reason to accept. Suppressing the seed there leaves a live approval unused beside a
// credential nobody will take, and the device stands aside for ever. The discriminator was already on disk.
func writeSeedForOrganization(enrollDir string, seed *enrolmentSeed, tenantID string) (string, error) {
	if seed == nil {
		return "", nil
	}
	if err := os.MkdirAll(enrollDir, 0o755); err != nil {
		return "", fmt.Errorf("create %s: %w", enrollDir, err)
	}
	if _, err := os.Stat(filepath.Join(enrollDir, "device.crt")); err == nil {
		held := enrolledTenant(enrollDir)
		if identityIsForAnotherOrganization(held, tenantID) {
			// Fall through and write the seed: the identity here cannot serve this deployment.
			// Said out loud, because spending an approval is not something to do quietly.
			fmt.Printf("profileapply: this device holds an identity issued by %q and is being installed for "+
				"%q — that credential cannot serve this deployment, so the enrolment seed IS written and the "+
				"approval will be spent\n", held, tenantID)
		} else {
			return "this device already holds an enrolled identity — the enrolment seed was NOT written, and no approval was spent", nil
		}
	}
	seedPath := filepath.Join(enrollDir, "enrolment.json")
	if held, err := os.ReadFile(seedPath); err == nil {
		// ★★★ A SEED FOR ANOTHER ORGANIZATION IS NOT "A TOKEN IN FLIGHT" (2026-08-30, measured while moving
		// this box between two labs). The guard below exists so a re-provision does not throw away an approval
		// that has been issued and not yet spent. It was doing that for a seed pointing at a DELETED
		// deployment — and the two guards then contradicted each other in consecutive lines:
		//
		//	this device holds an identity issued by "tenant_zkn2u…" and is being installed for
		//	  "tenant_jduwy…" — that credential cannot serve this deployment, so the enrolment seed IS written
		//	an enrolment seed is already present — left as it is
		//
		// The second line silently undid the first. The device kept a seed naming an organization it is not
		// being installed for, at an address that no longer resolves, and would never enrol.
		if other := seedTenant(held); identityIsForAnotherOrganization(other, tenantID) {
			fmt.Printf("profileapply: the enrolment seed on this device names organization %q and this "+
				"install is for %q — that seed cannot enrol here, so it is REPLACED\n", other, tenantID)
		} else {
			return "an enrolment seed is already present — left as it is, so a token already in flight is not replaced", nil
		}
	}
	raw, err := json.MarshalIndent(seed, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(seedPath, raw, 0o600); err != nil {
		return "", fmt.Errorf("write %s: %w", seedPath, err)
	}
	return "enrolment seed written -> " + seedPath + " (the agent enrols itself on first start)", nil
}

// seedTenant reads the organization an enrolment seed is addressed to. Empty when it cannot be read, which
// is treated as "cannot tell" and therefore left alone — proof, never absence, the same rule the identity
// check uses.
func seedTenant(raw []byte) string {
	var seed struct {
		Tenant string `json:"tenant"`
	}
	if json.Unmarshal(raw, &seed) != nil {
		return ""
	}
	return strings.TrimSpace(seed.Tenant)
}

// enrolledTenant reads the organization the identity on disk was issued by. Empty when there is no marker or it
// cannot be read — which is treated as "cannot tell", never as "different".
func enrolledTenant(enrollDir string) string {
	raw, err := os.ReadFile(filepath.Join(enrollDir, "enrolled.json"))
	if err != nil {
		return ""
	}
	var meta struct {
		Tenant string `json:"tenant"`
	}
	if json.Unmarshal(raw, &meta) != nil {
		return ""
	}
	return strings.TrimSpace(meta.Tenant)
}

// identityIsForAnotherOrganization is the same rule the agent's gate uses (identityServesThisOrganization),
// stated once per binary because they are separate programs. Proof, never absence: either side unknown means
// the identity is left alone.
func identityIsForAnotherOrganization(identityTenant, profileTenant string) bool {
	a, b := strings.TrimSpace(identityTenant), strings.TrimSpace(profileTenant)
	if a == "" || b == "" {
		return false
	}
	return !strings.EqualFold(a, b)
}
