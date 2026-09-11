package main

import "flag"

// the_console_of_every_region.go — every address this deployment's Admin Console answers on.
//
// ★★★ WHY THERE IS MORE THAN ONE (2026-08-30, the operator: when a region fails over, the Console of the
// region that took over has to open too).
//
// Every device this product steers sends its traffic to an Edge, and an Edge is a forward proxy to the public
// internet: it refuses internal destinations, which is correct, and which means an administrator on a managed
// machine cannot open a Console that lives on the customer's own network. The device profile therefore names
// the Console as a destination the device must NOT steer.
//
// Naming one of them is a fix that lasts until the region holding it is the region that failed — which is the
// moment an administrator needs the Console most. -admin-console-origin stays single because CORS and the
// post-login redirect each need exactly one address; what a steered device must not steer is a different
// question, and its answer is a set.
//
// ★ THE FLAG LIVES HERE AND NOT IN main.go, which is the rule the decomposition ratchet enforces.
func registerAdminConsoleOriginsFlag() *string {
	return flag.String("admin-console-origins", "",
		"every address this deployment's Admin Console answers on, comma- or semicolon-separated "+
			"(e.g. https://console.a.example,https://console.b.example). Carried in the device profile as "+
			"destinations a steered device must NOT steer, so an administrator keeps the Console after a "+
			"region failover. -admin-console-origin is included automatically. Empty = just "+
			"-admin-console-origin, which covers one region and no more.")
}
