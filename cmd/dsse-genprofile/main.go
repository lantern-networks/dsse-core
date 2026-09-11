// dsse-genprofile — sign an install profile (L1 seed) into an agentpolicy.Envelope for an endpoint agent to
// verify with --config-profile/--config-pin. Dev/CI tool; a management console performs the same signing
// server-side for a fleet. It NEVER prints the private key — only the PUBLIC pin the agent verifies against.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/installprofile"
)

func main() {
	out := flag.String("out", "", "path to write the signed envelope JSON (required)")
	keyPath := flag.String("key", "", "Ed25519 signing seed (32-byte hex) file; generated+persisted if absent (dev)")
	tenant := flag.String("tenant", "", "tenant_id (required)")
	group := flag.String("group", "", "group_id (optional; usually assigned at enrollment)")
	transportURL := flag.String("transport-url", "", "transport_url (the (T) Edge)")
	posture := flag.String("posture", "fail-closed", "fail-closed | fail-open")
	ackFailOpen := flag.Bool("ack-fail-open", false, "acknowledge fail-open (required for posture=fail-open to take effect)")
	backend := flag.String("backend", "wfp", "wfp | windivert")
	bypassApps := flag.String("bypass-apps", "", "comma-separated bypass app identifiers")
	bypassDests := flag.String("bypass-dests", "", "comma-separated bypass destinations")
	dnsListen := flag.String("dns-listen", "127.0.0.1:53", "local DNS proxy listen addr")
	blockQUIC := flag.Bool("block-quic", true, "block QUIC (UDP:443)")
	captiveTimeout := flag.Int("captive-timeout", 180, "captive window T_max (seconds)")
	enrollMode := flag.String("enroll-mode", "interactive", "mdm | token | interactive")
	flag.Parse()

	if strings.TrimSpace(*out) == "" || strings.TrimSpace(*tenant) == "" {
		fmt.Fprintln(os.Stderr, "dsse-genprofile: --out and --tenant are required")
		os.Exit(2)
	}
	signer, err := agentpolicy.LoadOrGenerateSigner(strings.TrimSpace(*keyPath), true)
	if err != nil || signer == nil {
		fmt.Fprintf(os.Stderr, "dsse-genprofile: signer: %v\n", err)
		os.Exit(1)
	}
	// One clock for both stamps. The envelope's created_at is unsigned metadata; IssuedAt is inside the signed
	// payload and is what configstore.Apply orders profiles by, so they must not be able to disagree.
	issued := time.Now().UTC().Truncate(time.Second)
	prof := installprofile.Build(installprofile.Options{
		Tenant:         *tenant,
		Group:          *group,
		TransportURL:   *transportURL,
		EnrollMode:     *enrollMode,
		Posture:        *posture,
		AckFailOpen:    *ackFailOpen,
		Backend:        *backend,
		BypassApps:     *bypassApps,
		BypassDests:    *bypassDests,
		DNSListen:      *dnsListen,
		BlockQUIC:      *blockQUIC,
		CaptiveTimeout: *captiveTimeout,
	}, issued)
	env, err := signer.Sign(prof, issued)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dsse-genprofile: sign: %v\n", err)
		os.Exit(1)
	}
	b, _ := json.MarshalIndent(env, "", "  ")
	if err := os.WriteFile(strings.TrimSpace(*out), b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "dsse-genprofile: write: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote signed profile -> %s\n", *out)
	fmt.Printf("PIN (verify with --config-pin): %s\n", signer.PublicKeyHex())
}
