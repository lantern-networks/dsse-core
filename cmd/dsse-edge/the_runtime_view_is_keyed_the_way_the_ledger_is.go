package main

import (
	"github.com/lantern-networks/dsse-core/enrolledinventory"
)

// ★★★ TWO SPELLINGS OF ONE MACHINE, AND THE SCREEN JOINS THEM BY KEY (2026-09-01, measured on a real Mac the
// minute it started steering).
//
// The deployment's enrolled inventory stores a device identity normalised — enrolledinventory.NormalizeIdentity,
// lower-cased and trimmed — because a device that renames its own case must not become a second machine. The
// presence map is keyed by whatever the device called itself when it registered. A Mac whose hostname is
// "ShinnoMac-mini" therefore appeared as
//
//	/admin/enrolled-devices   shinnomac-mini      ← the row
//	/admin/device-runtime     ShinnoMac-mini      ← the state
//
// and the Console's Devices screen looks the second up with the key of the first (runtime[d.identity], and the
// same for the steer-state, risk and update overlays beside it). An exact-key lookup misses, so a device that
// is steering, inspected and reporting its posture renders as
//
//	No report — not steering yet
//
// which is the same false sentence this deployment spent the morning removing one gate further in: the Edge
// refusing to record a customer's device at all. The device was carried, decrypted and enforced throughout
// both times. Windows never showed it because its hostname was already lower-case — one machine looked fine
// and the second one did not, which is how this whole family announces itself.
//
// ★ THE LEDGER IS THE ONE THAT NORMALISES, SO IT IS THE ONE TO AGREE WITH. Not the Console: four joins on that
// screen use this key, other readers will grow, and a fix in one of them leaves the others wrong. The record's
// own reported id is untouched — this is the join key, and it is the deployment's canonical form of it.
func keyDeviceRuntimeTheWayTheLedgerDoes(devices map[string]deviceRuntimeView) map[string]deviceRuntimeView {
	if len(devices) == 0 {
		return devices
	}
	keyed := make(map[string]deviceRuntimeView, len(devices))
	for id, view := range devices {
		normalised := enrolledinventory.NormalizeIdentity(id)
		if normalised == "" {
			normalised = id // nothing to normalise to: keep what there is rather than dropping the device
		}
		// A collision means two spellings of one machine were being carried as two: fold them, newest wins, so
		// the screen shows the live one rather than whichever the map happened to yield.
		if held, clash := keyed[normalised]; clash && held.LastSeen > view.LastSeen {
			continue
		}
		keyed[normalised] = view
	}
	return keyed
}
