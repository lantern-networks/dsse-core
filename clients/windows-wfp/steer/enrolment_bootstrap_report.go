package main

// enrolment_bootstrap_report.go — saying what pinned the enrolment channel, before it is used.
//
// ★★★ "A TLS ERROR" NAMES THREE DIFFERENT FAULTS (2026-08-29, the Mac session's recommendation after losing a
// round trip to it, adopted here so both clients say the same thing).
//
// Enrolment is the trust bootstrap: it runs before this device has any relationship with the deployment, so it
// cannot fall back on one. When it fails, the message the platform gives is about a handshake — and a handshake
// failure is the same sentence whether the device was handed the WRONG authority, handed NONE and fell through
// to the operating system's public trust store, or handed a PEM that did not parse. Those three have different
// fixes and different people to talk to, and none of them is discoverable from "a TLS error caused the secure
// connection to fail".
//
// So the pinning is reported at the moment it is decided, by name, on every path — including the paths that
// succeed. A line that only appears on failure cannot be compared against a machine that works.

import (
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/installprofile"
)

// bootstrapPinning describes what the enrolment channel is verified against. Purely descriptive: it decides
// nothing, so a bug here can only make the log wrong, never the connection.
type bootstrapPinning struct {
	// Authorities are the subjects of the certificates the enrolment client will accept, in order.
	Authorities []string
	// DeviceCAPin is the SHA-256 the issued device CA is cross-checked against, if any.
	DeviceCAPin string
	// ServerName is the name presented and verified, empty when the address is used.
	ServerName string
	// Unpinned, when non-empty, is why this channel is NOT pinned — the case that must never be silent.
	Unpinned string
}

// describeBootstrapPinning reads the material the enrolment client was built from.
//
// caPEM is what was supplied as the enrol CA; parseErr is the error from trying to use it, so a PEM that
// failed to parse is reported as that rather than as an absence — they look identical from the outside and
// they are not the same mistake.
func describeBootstrapPinning(caPEM, deviceCAPin, serverName string, parseErr error) bootstrapPinning {
	p := bootstrapPinning{
		DeviceCAPin: strings.TrimSpace(deviceCAPin),
		ServerName:  strings.TrimSpace(serverName),
	}
	switch {
	case parseErr != nil:
		p.Unpinned = "the supplied enrol CA could not be used: " + parseErr.Error()
	case strings.TrimSpace(caPEM) != "":
		certs, err := installprofile.ParseCertificates([]byte(caPEM))
		if err != nil {
			p.Unpinned = "the supplied enrol CA holds no usable certificate: " + err.Error()
			break
		}
		for _, c := range certs {
			p.Authorities = append(p.Authorities, c.Subject.String())
		}
	case p.DeviceCAPin != "":
		// Pinned, but on the ISSUED material rather than on the channel: the endpoint is verified by the
		// system store and the identity it hands back is refused unless its CA matches. Weaker and worth
		// distinguishing, because it is the configuration that survives a hostile enrol endpoint only by
		// refusing what it produced — after the one-time token has already been spent.
		p.Unpinned = "no enrol_ca_pem — the endpoint is verified by the operating system's trust store, and " +
			"only the ISSUED device CA is pinned (the one-time token is spent before that check can refuse anything)"
	default:
		p.Unpinned = "neither an enrol CA nor a device-CA fingerprint was supplied"
	}
	return p
}

// Line is the single sentence printed on every enrolment attempt.
func (p bootstrapPinning) Line() string {
	var b strings.Builder
	if p.Unpinned != "" {
		b.WriteString("steer: enrolment bootstrap UNPINNED — " + p.Unpinned)
	} else {
		b.WriteString(fmt.Sprintf("steer: enrolment bootstrap pinned to %d authority(ies): %s",
			len(p.Authorities), strings.Join(p.Authorities, "; ")))
	}
	if p.ServerName != "" {
		b.WriteString(" | name presented: " + p.ServerName)
	} else {
		b.WriteString(" | no name presented (the address is verified)")
	}
	if p.DeviceCAPin != "" {
		b.WriteString(" | issued device CA must be sha256=" + p.DeviceCAPin)
	} else {
		b.WriteString(" | the issued device CA is NOT pinned")
	}
	return b.String()
}
