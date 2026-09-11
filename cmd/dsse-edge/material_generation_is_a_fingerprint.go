package main

import (
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"strings"
)

// material_generation_is_a_fingerprint.go — the number an Edge compares to decide whether to fetch.
//
// ★★★ IT WAS A COUNTER, AND A COUNTER CAN REVISIT A VALUE (2026-08-22, measured on the reference fleet).
//
// Each authority kept an in-memory `generation` that started at zero on every start-up and was incremented on
// every save; the answer handed to an Edge was their sum. An Edge stores the last number it was told and asks
// "is it still that". So:
//
//	control plane restarts   → the counters reset, and the sum walks back up from the bottom
//	an act bumps it          → the sum re-reaches a value some Edge is already holding
//	that Edge asks           → the numbers match, and it is told UNCHANGED — for ever
//
// Measured end to end. A transport name was changed on the control plane; region-b fetched it and served both
// names, region-a compared equal numbers and never fetched again. The two then fought over the shared
// announcement — one adding the new name, the other removing it — and the fleet's distribution serial advanced
// by two every minute, indefinitely. Every gate that waits for a settled serial was therefore shut, which is
// the failure this repository already has a name for. Only restarting the node that was behind resolved it,
// because a restart clears the number it was holding.
//
// ★ SO IT IS DERIVED FROM THE AUTHORITIES THEMSELVES, NOT COUNTED BESIDE THEM. Equal now means "the same
// authorities", which is the question actually being asked. A restart with nothing changed produces the same
// fingerprint — correctly telling every Edge there is nothing to fetch — and any change produces a different
// one whether or not the process has restarted since.
//
// It stays a uint64 on the wire: the first eight bytes of a SHA-256 over what each authority IS. Never zero,
// because zero is what an Edge that has never asked sends and must keep meaning "give me everything".
func materialFingerprint(parts []string) uint64 {
	sort.Strings(parts)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	g := binary.BigEndian.Uint64(sum[:8])
	if g == 0 {
		// One value in 2^64, and it would mean "never asked". Stepping off it costs nothing and removes the
		// case entirely.
		return 1
	}
	return g
}
