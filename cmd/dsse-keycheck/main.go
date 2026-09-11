// Command dsse-keycheck answers one question: would a device ACCEPT this public key?
//
// ★ THE BUILD AND THE VERIFIER DISAGREED TWICE IN ONE DAY (2026-08-12, twenty-fourth review). First the MSI
// demanded 64 hex characters while the only agent-policy key the deployment had was a 130-character ECDSA
// point, so it could not be packaged at all. Then the fix — a length-only regular expression — accepted
// `04` followed by 128 zeros, which is not a point on P-256 and which the verifier refuses at runtime. The
// build's reasoning for staying loose was sound as far as it went ("a second implementation of the check is a
// second thing to disagree with") and the conclusion was the wrong one: do not implement it twice, CALL it.
//
// So this is not a check, it is a door to the one that already exists. agentpolicy.AcceptedPublicKeyHex is
// what the device uses; a packaging script that shells out to this cannot drift from it, because there is
// nothing here to drift.
//
//	dsse-keycheck --agent-policy-key <hex>   exit 0 = a device would accept it
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/lantern-networks/dsse-core/agentpolicy"
)

func main() {
	key := flag.String("agent-policy-key", "", "the public key hex to check, as an operator would paste it")
	flag.Parse()
	k := strings.ToLower(strings.TrimSpace(*key))
	if k == "" {
		fmt.Fprintln(os.Stderr, "dsse-keycheck: --agent-policy-key is required")
		os.Exit(2)
	}
	if !agentpolicy.AcceptedPublicKeyHex(k) {
		fmt.Fprintf(os.Stderr, "dsse-keycheck: REJECTED (%d hex chars). A device accepts either a 64-char "+
			"Ed25519 key or a 130-char uncompressed ECDSA-P256 point that is actually ON the curve — the "+
			"length being right is not enough, and this value would be refused at runtime after shipping.\n", len(k))
		os.Exit(1)
	}
	fmt.Printf("dsse-keycheck: accepted (%d hex chars)\n", len(k))
}
