package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// enrolment_gate.go — what the agent does when it starts and finds it has no device identity. The Windows
// analog of the macOS DsseEnrolmentGate, and deliberately the same rule table, because a device that behaves
// differently per platform at its trust bootstrap is a device with two trust stories.
//
// The distinction that decides everything is the one the Edge itself draws between an identity that is ABSENT
// and one an admin DISABLED:
//
//	never enrolled — the ordinary Day-0 state. Nothing has been lost, because nothing was ever gained. Taking
//	                 over the network path would only break a machine that was working. Enrol if there is a
//	                 token; otherwise stand aside and say so.
//	was enrolled   — a machine that HAS held an identity and no longer does. That is a different event, and it
//	                 is not this gate's to reinterpret: the existing fail-closed handling stands.
//
// Standing aside bypasses nothing: there is no policy to bypass on a machine nobody approved, and the
// alternative is not "more secure" but "no network" — an agent taking over the path and then failing every
// handshake with a credential it does not have.

type enrolmentGateDecision int

const (
	// gateProceed: a device identity is present. Nothing to do.
	gateProceed enrolmentGateDecision = iota
	// gateEnrolFirst: no identity, but the machine holds an admin-issued token. Enrol, then proceed.
	gateEnrolFirst
	// gateStandAside: no identity, no token, never enrolled. Do not take over the network path.
	gateStandAside
	// gateProceedPreviouslyEnrolled: no identity, but this machine HAS been enrolled before. The existing
	// handling (fail-closed, loud) stands — losing a credential must not demote enforcement to "new machine".
	gateProceedPreviouslyEnrolled
)

func (d enrolmentGateDecision) String() string {
	switch d {
	case gateProceed:
		return "proceed"
	case gateEnrolFirst:
		return "enrol_first"
	case gateStandAside:
		return "stand_aside_not_enrolled"
	case gateProceedPreviouslyEnrolled:
		return "proceed_previously_enrolled"
	}
	return "unknown"
}

// enrolmentGateDecide works from facts the caller has already established, so it stays testable without a
// registry, a filesystem, or an Edge.
//
// wasEnrolledBefore MUST come from durable state (the enrolled.json completion marker — even one whose material
// no longer loads — or a renewed-identity pointer), never from a working credential: a device whose key was
// wiped must not be mistaken for a new one, or losing a credential becomes losing enforcement on exactly the
// devices an operator cares most about.
func enrolmentGateDecide(hasIdentity, hasEnrolmentToken, wasEnrolledBefore bool) enrolmentGateDecision {
	if hasIdentity {
		return gateProceed
	}
	if hasEnrolmentToken {
		return gateEnrolFirst
	}
	if wasEnrolledBefore {
		return gateProceedPreviouslyEnrolled
	}
	return gateStandAside
}

// notEnrolledOperatorMessage is the line an operator reads when the agent stands aside. It says what is wrong
// AND what to do about it — "not enrolled" alone sends someone hunting through logs for a cause that is really
// a missing step.
const notEnrolledOperatorMessage = "this device is not enrolled and has no enrolment token — traffic is NOT " +
	"being steered or inspected. An administrator issues a one-time enrolment token in the Console (Enrolment " +
	"Tokens) and places it in enrolment.json next to the enrolled material (enrolment_token field); the agent " +
	"then enrols itself on the next service start."

// enrolmentConfig is the per-machine enrolment block, the same fields the macOS agent config carries. It lives
// OUTSIDE the signed install profile deliberately: the profile is tenant-authored and fleet-signed, while the
// token is per-machine, one-time, and must be erasable after it is spent — none of which a signed document can
// be. The enclosing directory's SYSTEM/Admin-only ACL is what protects it, exactly as for the key beside it.
//
// It carries a token, never a certificate: shipping a certificate would mean an admin generated the machine's
// private key, putting it outside the machine and foreclosing TPM binding.
type enrolmentConfig struct {
	EnrolURL string `json:"enrol_url"` // https://<edge>:<port>/enroll
	DeviceID string `json:"device_id"` // the name this machine will carry
	Token    string `json:"enrolment_token"`
	Tenant   string `json:"tenant,omitempty"` // advisory only — the Edge is authoritative
	// EnrolCAPEM is the CA to verify the enrol endpoint's TLS against (the bootstrap channel pin).
	EnrolCAPEM string `json:"enrol_ca_pem,omitempty"`
	// DeviceCAPinSHA256 is the SHA-256 the issued device CA must match.
	DeviceCAPinSHA256 string `json:"device_ca_pin_sha256,omitempty"`
	// TokenSpent records that the token here WAS spent — what an operator reading this file months later
	// actually wants to know. Set by markEnrolmentTokenSpent; a config with it set carries no live token.
	TokenSpent bool `json:"enrolment_token_spent,omitempty"`
}

// hasUnspentToken reports whether this config carries a live token to enrol with.
func (c enrolmentConfig) hasUnspentToken() bool {
	return strings.TrimSpace(c.Token) != "" && !c.TokenSpent
}

// hasPinnedBootstrap mirrors the invariant both platforms enforce: enrolment is the trust bootstrap and must
// not run over an unpinned channel. Either the endpoint's CA or the expected device-CA fingerprint pins it.
func (c enrolmentConfig) hasPinnedBootstrap() bool {
	return strings.TrimSpace(c.EnrolCAPEM) != "" || strings.TrimSpace(c.DeviceCAPinSHA256) != ""
}

// loadEnrolmentConfig reads the per-machine enrolment block. A missing file is the ordinary case (ok=false, no
// error); a present-but-unparseable one is reported, because "the installer wrote something here and the agent
// ignored it" must not be silent.
func loadEnrolmentConfig(path string) (enrolmentConfig, bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return enrolmentConfig{}, false, nil
	}
	var c enrolmentConfig
	if err := json.Unmarshal(raw, &c); err != nil {
		return enrolmentConfig{}, false, fmt.Errorf("enrolment config %q is present but unreadable: %w", path, err)
	}
	return c, true, nil
}

// markEnrolmentTokenSpent removes the token from the config once it has been spent and records that it was.
//
// The token is one-time on the server, so leaving it behind could not enrol a second machine — but it would be
// a live-looking credential sitting in a file with no remaining purpose, and the file would no longer say the
// one thing a reader wants to know: that enrolment happened here.
func markEnrolmentTokenSpent(path string) error {
	c, ok, err := loadEnrolmentConfig(path)
	if err != nil || !ok {
		return err
	}
	c.Token = ""
	c.TokenSpent = true
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// identityServesThisOrganization reports whether a device identity found on disk can be used HERE.
//
// ★★★ AN IDENTITY FOR ANOTHER ORGANIZATION IS NOT AN IDENTITY (2026-08-30, the macOS session hit it moving a
// device between deployments; this box was sitting in the same state when they said so).
//
// The gate asked "does this machine hold an identity", and a machine moved to a different deployment holds one:
// a certificate issued by YESTERDAY's organization's device CA. It answered proceed, never spent the unused
// approval that came with the new profile, and then presented a credential the new Edge has no reason to
// accept. Fail-closed, permanently, with a live token sitting beside it unused — and the log line said
// "loaded enrolled device identity" with the wrong tenant printed right there in it.
//
// An identity is a credential issued BY an organization. Carried to another one it is refused, so counting it
// as enrolment here means standing aside for ever while holding something nobody will take.
//
// ★ EITHER SIDE UNKNOWN MEANS USABLE. An identity written before enrolled.json carried a tenant, or a profile
// that names no organization, cannot be judged — and refusing on "cannot tell" would disenrol working devices
// to catch a case that has not happened to them. Same rule as the adopted-anchor discard: act on proof, never
// on absence.
func identityServesThisOrganization(identityTenant, profileTenant string) bool {
	a, b := strings.TrimSpace(identityTenant), strings.TrimSpace(profileTenant)
	if a == "" || b == "" {
		return true
	}
	return strings.EqualFold(a, b)
}
