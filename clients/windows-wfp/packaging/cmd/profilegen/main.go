// profilegen is a DEV/LAB tool that signs an L1 install profile into an agentpolicy.Envelope and prints the pin
// (public key hex) to anchor it against. In production the Control Plane signs profiles with the tenant key;
// this is only for local packaging/install testing (feeding the MSI CONFIG= + a --pin to profileapply).
//
//	profilegen --tenant acme --transport https://edge.acme:18543 --version 1 --out profile.json
//	# prints: PIN=<hex>   (pass to `profileapply --pin <hex>`)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/installprofile"
	"github.com/lantern-networks/dsse-core/regionfailover"
)

func main() {
	tenant := flag.String("tenant", "acme", "tenant id")
	group := flag.String("group", "", "device group id (optional)")
	transport := flag.String("transport", "https://edge.acme.example:18543", "transport_url")
	posture := flag.String("posture", "fail-closed", "posture: fail-closed | fail-open")
	ackFailOpen := flag.Bool("ack-failopen", false, "set ack_failopen (fail-open needs this AND posture=fail-open)")
	version := flag.Int("version", 1, "profile version")
	out := flag.String("out", "profile.json", "output envelope JSON path")
	keyPath := flag.String("key", "", "path to a persisted Ed25519 signing key (empty = fresh ephemeral key each run)")
	regionPriority := flag.String("region-priority", "", "this SITE's preference among the regions the Edge allows, 'region=N,region=N' (LOWER IS PREFERRED, 1 is highest). Outranks measured latency; RTT decides only within one rank. A region not named ranks last; a region the Edge does not serve is inert (this can never add a region).")
	flag.Parse()

	// Refused HERE, at authoring, because this is the last moment a human is looking at the value. Once signed
	// it is a document that verifies, and a rank of 0 — the ordinary zero-based instinct for "first" — means
	// UNSPECIFIED to the selector and ranks LAST, so it would deliver the exact inverse of the intent on every
	// device the profile reaches, with nothing anywhere reporting a problem.
	priority, err := regionfailover.ParsePriority(*regionPriority)
	if err != nil {
		fmt.Fprintf(os.Stderr, "profilegen: --region-priority: %v\n", err)
		os.Exit(2)
	}

	// Same clock for the payload stamp and the envelope's created_at. ★ THIS TOOL MUST STAMP TOO: it is the
	// SECOND issuer in the tree, and configstore.Apply refuses an unstamped profile over a stamped one — a
	// lab profile from here would be rejected on any box the CP had already reached, for a reason that would
	// look nothing like "the dev tool skipped a field".
	issued := time.Now().UTC().Truncate(time.Second)
	p := installprofile.InstallProfile{
		Kind:         installprofile.ProfileKind,
		Version:      *version,
		IssuedAt:     issued.Format(time.RFC3339),
		TenantID:     *tenant,
		GroupID:      *group,
		TransportURL: *transport,
		Posture:      *posture,
		AckFailOpen:  *ackFailOpen,
		Enroll:       installprofile.EnrollSpec{Mode: "interactive"},

		RegionPriority: priority,
	}

	signer, err := agentpolicy.LoadOrGenerateSigner(*keyPath, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "profilegen: signer: %v\n", err)
		os.Exit(1)
	}
	env, err := signer.Sign(p, issued)
	if err != nil {
		fmt.Fprintf(os.Stderr, "profilegen: sign: %v\n", err)
		os.Exit(1)
	}
	b, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "profilegen: marshal: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "profilegen: write %q: %v\n", *out, err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s\nPIN=%s\n", *out, signer.PublicKeyHex())
}
