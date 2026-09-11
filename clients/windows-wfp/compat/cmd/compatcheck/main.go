//go:build windows

// compatcheck — the install-time compatibility gate as a standalone exe (roadmap M8.2). The Burn bootstrapper
// (or an MSI launch-condition custom action) runs this as step 0: it detects the machine facts and exits
// non-zero with a human reason if the install cannot proceed, so the user gets a clear message instead of a
// silent "driver won't load" later.
//
//	compatcheck            # assume a production attestation-signed driver
//	compatcheck --test-signed   # assume the dev/test-signed driver (Secure Boot / HVCI become hard blocks)
//	compatcheck --json     # machine-readable output for the installer
//
// Exit codes: 0 = OK (may include warnings), 1 = blocked, 2 = usage error.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/compat"
)

func main() {
	testSigned := flag.Bool("test-signed", false, "evaluate for a self-signed TEST driver (Secure Boot / HVCI become blocks); default assumes a production attestation-signed driver")
	asJSON := flag.Bool("json", false, "emit the result as JSON")
	flag.Parse()

	f := compat.Detect()
	r := compat.Evaluate(f, !*testSigned)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
	} else {
		fmt.Println(r.Summary())
		fmt.Printf("facts: arch=%s sMode=%v secureBoot=%v hvci=%v build=%d (%s)\n",
			f.Arch, f.SMode, f.SecureBoot, f.HVCI, f.WindowsBuild, f.DisplayVersion)
		for _, b := range r.Blocks {
			fmt.Printf("  BLOCK: %s\n", b)
		}
		for _, w := range r.Warnings {
			fmt.Printf("  warn:  %s\n", w)
		}
	}

	if !r.OK {
		os.Exit(1)
	}
}
