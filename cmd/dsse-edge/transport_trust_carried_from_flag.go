package main

import "flag"

// transportTrustCarriedFromFlag names where this node kept the trust distribution BEFORE it moved into the
// deployment's database.
//
// ★★★ A MOVE MUST NOT RESTART THE AUTHORITY BELOW WHAT THE FLEET IS SERVING (2026-09-07, measured the first
// time the shared store ran on a deployment that already had a distribution: every control plane read serial
// 2 while every Edge in every region served 4). The next certificate an operator added would have been
// numbered 3 and discarded by the whole fleet as a replay, with the Console reporting it added.
//
// Read once, and only ever upward — a node carrying a lower record cannot pull the shared one down.
func transportTrustCarriedFromFlag() *string {
	return flag.String("transport-trust-carried-from", "",
		"where this node kept the trust distribution before -transport-trust-store moved it into the "+
			"deployment's database. Read once, and only ever to RAISE the shared serial, so an upgrade "+
			"cannot restart the authority below what the fleet is already serving. Empty on a deployment "+
			"that never had one.")
}
