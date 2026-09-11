package installprofile

import (
	"strings"
	"time"
)

// build.go — making a device's install profile, in one place, so the DEPLOYMENT can make one.
//
// ★★★ WHY THIS IS NOT ONLY IN A COMMAND (2026-08-25, reported from win-dev-1 and from the operator).
//
// The install profile is the ONE configuration object every endpoint needs, and the only way to produce it
// was: ssh to the machine holding the repository, find cmd/dsse-genprofile, hand it the deployment's raw
// Ed25519 signing seed as a FILE PATH, and copy the JSON back. An operator is not assumed to have a
// checkout, a Go toolchain, or shell access to the control plane — and the deployment's private signing key
// should never be somewhere a person handles it at all.
//
// Everything in a profile that is not a preference is something the deployment already knows: the tenant, the
// address its agent plane answers on, and the key to sign with. What an operator actually decides is the
// posture and what bypasses. So the building lives here, where the control plane can call it, and the
// command keeps working by calling the same function — development and the lab may hold the key in a file.
func splitCSV(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// genOptions is what the flags say, before any of it is turned into a profile. Separated from main only so
// buildProfile can be tested: the defect this file's IssuedAt comment describes — an anti-rollback guard
// comparing a field that never moves — survived for as long as it did because nothing could ask the ISSUER
// what it actually stamps.
type Options struct {
	Tenant       string
	Group        string
	TransportURL string
	// TransportEndpoints are the other starting addresses, "region=URL". See the field on InstallProfile.
	TransportEndpoints []string
	// RegionPriority is the operator's preference among those regions, region -> rank, lower preferred.
	//
	// ★★★ IT HAD NO WAY IN (2026-08-30). The field existed on the profile, both agents read it, and
	// regionfailover applied it — and Options could not carry it, so the one route that issues profiles could
	// not fill it however much it wanted to. Every fleet this product has ever configured ranked its regions
	// by measured latency alone, and an organization's home region decided nothing.
	RegionPriority map[string]int
	EnrollMode     string
	Posture        string
	AckFailOpen    bool
	// VMEgress / AckVMEgress: what happens to traffic from virtual machines on the device (WSL distros,
	// Hyper-V guests), which have their own network stack and are not steered. Two keys, like fail-open —
	// see the note on installprofile.VMEgressBlocked.
	VMEgress       string
	AckVMEgress    bool
	Backend        string
	BypassApps     string
	BypassDests    string
	DNSListen      string
	BlockQUIC      bool
	CaptiveTimeout int
	// Organization is the name this organization's devices present before they have been told anything. See
	// OrganizationSpec for why it is stated at install time and not learned.
	//
	// ★★★ NOTHING EVER FILLED IT (2026-08-28, found by asking why a Mac dials the shared name). The Edge
	// selects an organization's transport certificate by SNI — it must, because the client certificate arrives
	// after the server's — the control plane issues a per-organization name for exactly that, and the agents
	// on both platforms read this block. Every producer left it empty, so every device of every organization
	// dialled the shared name and was served the deployment's own certificate. Three layers implemented and
	// the middle one never connected.
	Organization OrganizationSpec
	// Deployment is what the device must be told about the deployment itself, so that a profile and a one-time
	// token are the whole of what a customer receives. See DeploymentSpec.
	Deployment DeploymentSpec
}

// buildProfile assembles the profile that will be signed. issued is both the payload's ordering stamp and the
// envelope's created_at, passed in rather than read from the clock so a test can order two issues.
func Build(o Options, issued time.Time) InstallProfile {
	bq := o.BlockQUIC
	return InstallProfile{
		Kind:    ProfileKind,
		Version: 3,
		// ★ NOT `Version+1`. version is the SCHEMA version — every profile this tool has ever emitted carries
		// the literal 3 — and the anti-rollback guard in configstore.Apply compared it, so it could never fire.
		// Ordering belongs to a value that actually moves per issue.
		IssuedAt:           issued.UTC().Format(time.RFC3339),
		TenantID:           strings.TrimSpace(o.Tenant),
		GroupID:            strings.TrimSpace(o.Group),
		TransportURL:       strings.TrimSpace(o.TransportURL),
		TransportEndpoints: o.TransportEndpoints,
		RegionPriority:     o.RegionPriority,
		Enroll:             EnrollSpec{Mode: strings.TrimSpace(o.EnrollMode)},
		Posture:            strings.TrimSpace(o.Posture),
		AckFailOpen:        o.AckFailOpen,
		VMEgress:           strings.TrimSpace(o.VMEgress),
		AckVMEgress:        o.AckVMEgress,
		Backend:            strings.TrimSpace(o.Backend),
		BypassApps:         splitCSV(o.BypassApps),
		BypassDests:        splitCSV(o.BypassDests),
		DNSListen:          strings.TrimSpace(o.DNSListen),
		BlockQUIC:          &bq,
		StartMode:          StartAuto,
		Captive:            CaptiveSpec{TimeoutSec: o.CaptiveTimeout},
		// Trimmed here rather than at each caller, and left entirely empty when nothing is named — which is a
		// supported, meaningful state: "the deployment's shared certificate".
		Organization: OrganizationSpec{
			TenantID:                  strings.TrimSpace(o.Organization.TenantID),
			TransportServerName:       strings.TrimSpace(o.Organization.TransportServerName),
			EnrolmentServerName:       strings.TrimSpace(o.Organization.EnrolmentServerName),
			RenewalRecoveryServerName: strings.TrimSpace(o.Organization.RenewalRecoveryServerName),
		},
		// Carried verbatim: these are the deployment's own facts, and trimming a PEM would break it. Empty
		// stays empty — a deployment that has not been given one of them says so by absence rather than by a
		// blank that reads as configured.
		Deployment: DeploymentSpec{
			AnchorPEM:                   o.Deployment.AnchorPEM,
			TransportAnchorsPEM:         o.Deployment.TransportAnchorsPEM,
			DeviceCAPinSHA256:           strings.TrimSpace(o.Deployment.DeviceCAPinSHA256),
			InterceptionRootPEM:         o.Deployment.InterceptionRootPEM,
			InterceptionRootIsOwn:       o.Deployment.InterceptionRootIsOwn,
			AgentPolicySigningPublicKey: strings.TrimSpace(o.Deployment.AgentPolicySigningPublicKey),
			UpdateSigningKeys:           o.Deployment.UpdateSigningKeys,
			UpdatePublisherTeamID:       strings.TrimSpace(o.Deployment.UpdatePublisherTeamID),
			SteerExclusions:             o.Deployment.SteerExclusions,
			PassthroughDomains:          o.Deployment.PassthroughDomains,
		},
	}
}
