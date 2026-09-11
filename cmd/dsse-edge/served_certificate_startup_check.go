package main

import (
	"fmt"
	"log"
	"os"
	"strings"
)

// Would the fleet accept what this node is about to start serving?
//
// The admission guard was described in its own comment as "the ONE place a change to served material is
// admitted", and for changes made through the Console that was true. It was never true of STARTUP: the
// listener reads whatever is on disk through certreload and presents it, unasked. So a node could boot
// serving a certificate every device refuses — which is exactly the shape of the 2026-07-31 outage, where a
// certificate with no basicConstraints was accepted and the fleet did not fail until it re-handshaked — and
// nothing anywhere said so. The operator who redeploys with the wrong file gets silence, then an outage.
//
// This runs the same guard at startup and SAYS what it found. It does not refuse to start by default, on
// purpose: a node that will not start cannot be fixed remotely, so a fleet-wide redeploy with a bad file
// would take the deployment down completely rather than partially, and the guard's inputs are weaker here
// than at runtime (adoption is measured from handshakes that have not happened yet). Deployments that would
// rather fail closed set -refuse-start-on-unusable-certificate. Either way the condition is no longer
// invisible: it is logged, and it is on the certificate in the Console.

// servedCertificateStartupFinding is what the check concluded, kept for the admin API so the Console can
// show it on the certificate itself. Empty Problem means the certificate was accepted.
type servedCertificateStartupFinding struct {
	Name    string `json:"name"`
	Problem string `json:"problem,omitempty"`
}

var servedCertificateStartupFindings []servedCertificateStartupFinding

// checkServedCertificatesAtStartup evaluates every certificate this node will present. Returns the findings;
// the caller decides whether a problem is fatal.
func checkServedCertificatesAtStartup(config serverConfig) []servedCertificateStartupFinding {
	out := []servedCertificateStartupFinding{}
	seen := map[string]bool{}
	// The transport certificate is the one devices verify, and the one whose replacement stranded the fleet.
	// Component certificates are presented to the Console and connectors, which report their own failures
	// loudly; a device that cannot verify the Edge reports nothing, because it cannot connect to report.
	for _, path := range []string{config.TransportCertFile} {
		path = strings.TrimSpace(path)
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		name := deriveCertName(path)
		pem, err := os.ReadFile(path)
		if err != nil {
			// Unreadable is not "fine": the listener is about to try the same file.
			out = append(out, servedCertificateStartupFinding{Name: name,
				Problem: fmt.Sprintf("the certificate file could not be read: %v", err)})
			continue
		}
		f := servedCertificateStartupFinding{Name: name}
		if verr := guardServedCertificateChange(config, name, string(pem)); verr != nil {
			f.Problem = verr.Error()
		}
		out = append(out, f)
	}
	return out
}

// reportServedCertificatesAtStartup runs the check, records it for the Console, and logs each outcome. The
// healthy case is logged too: a check whose silence is indistinguishable from it not running is not a check
// an operator can rely on.
func reportServedCertificatesAtStartup(config serverConfig, refuseToStart bool) {
	findings := checkServedCertificatesAtStartup(config)
	servedCertificateStartupFindings = findings
	bad := 0
	for _, f := range findings {
		if f.Problem == "" {
			log.Printf("served_certificate_check name=%s result=accepted", f.Name)
			continue
		}
		bad++
		log.Printf("served_certificate_check name=%s result=REFUSED detail=%s", f.Name, f.Problem)
	}
	if bad == 0 {
		return
	}
	if refuseToStart {
		log.Fatalf("refusing to start: %d served certificate(s) would be refused by the fleet "+
			"(-refuse-start-on-unusable-certificate is set)", bad)
	}
	log.Printf("served_certificate_check summary=%d_would_be_refused action=starting_anyway "+
		"note=set -refuse-start-on-unusable-certificate to fail closed instead", bad)
}
