package main

import (
	"crypto/x509"
	"fmt"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

// The nearest expiry across everything this deployment depends on.
//
// Three separate things can run out and take the deployment with them: the certificate a component serves, a
// trust anchor devices verify against, and the certificates devices themselves hold. Each was visible on its
// own screen and none of them fed the readiness assessment, so "ready for real traffic" could be true with
// something expiring the following week.
//
// One answer rather than three, and NAMED, because "something expires in six days" is not actionable until you
// know what. Whichever is nearest is the one with the deadline; the others are still on their own screens.
// kind is "trust_anchor" or "device_certificate"; who names the specific one. Returned separately from the
// English label so the Console can say it in the language being read — the label used to be rendered
// verbatim, which put an English clause in the middle of a Japanese table.
func soonestPKIExpiry(config serverConfig, now time.Time) (what string, in time.Duration, have bool) {
	w, i, h, _, _ := soonestPKIExpiryDetailed(config, now)
	return w, i, h
}

func soonestPKIExpiryDetailed(config serverConfig, now time.Time) (what string, in time.Duration, have bool,
	kind string, who string) {
	consider := func(label, k, subject string, notAfter time.Time) {
		if notAfter.IsZero() {
			return
		}
		d := notAfter.Sub(now)
		if !have || d < in {
			what, in, have, kind, who = label, d, true, k, subject
		}
	}

	// What devices verify the Edge against. Losing one of these is the failure with no way back.
	if trustPEMs, _ := currentTrustAnchors(config); strings.TrimSpace(trustPEMs) != "" {
		if anchors, err := (agentpolicy.TrustBundlePayload{TransportCAPEM: trustPEMs}).Anchors(); err == nil {
			for _, a := range anchors {
				consider("the transport trust anchor “"+certLabel(a)+"”", "trust_anchor", certLabel(a), a.NotAfter)
			}
		}
	}

	// What devices are actually presenting. Observed rather than issued, so a renewal that silently stopped
	// shows up here as the fleet ageing rather than as a record that says everything was fine.
	for _, fact := range deviceCertificates.snapshot() {
		if at, err := time.Parse(time.RFC3339, fact.NotAfter); err == nil {
			consider("the certificate held by "+fact.Identity, "device_certificate", fact.Identity, at)
		}
	}

	return what, in, have, kind, who
}

func certLabel(c *x509.Certificate) string {
	if c == nil {
		return "unknown"
	}
	if cn := strings.TrimSpace(c.Subject.CommonName); cn != "" {
		return cn
	}
	return fmt.Sprintf("serial %s", c.SerialNumber)
}
