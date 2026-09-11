package main

import "flag"

// stepUpBindingSecretFlag declares the deployment-wide secret the step-up start URL is signed with.
//
// ★★★ EVERY EDGE SIGNS WITH THE SAME KEY, OR THE BINDING IS NOT ONE (2026-09-02, measured on a three-region
// deployment). The step-up URL names the deployment's agent plane; the region's door hands that connection to
// whichever Edge it likes; and the Edge that RECEIVES the URL is usually not the one that issued it. With a
// per-process key the signature does not verify — and it does not fail loudly, because an unverifiable device
// is read as "no device identity", which mints an organization-wide grant instead of a device-bound one.
func stepUpBindingSecretFlag() *string {
	return flag.String("step-up-binding-secret", "",
		"deployment-wide secret the step-up start URL is signed with (it covers the device AND the "+
			"organization the held flow belonged to). MUST be the same on every Edge: the Edge that issues a "+
			"step-up URL is rarely the one the region's front door hands it to. Empty = a per-process key, "+
			"which loses the device binding the moment a ceremony crosses a node.")
}
