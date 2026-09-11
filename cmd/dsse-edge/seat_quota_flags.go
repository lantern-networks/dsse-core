package main

import "flag"

// The seat-quota enforcement switch. A SIBLING file, not main.go: the Phase 0 ratchet
//
//	freezes main.go's flag count, so a new flag lands
//
// next to the decision it carries rather than growing the file the split exists to shrink.
//
// ★ THE DEFAULT IS THE PRODUCT DECISION (2026-08-14). A tenant quota is a number an operator sets and watches;
// going past one raises an alert and the device still enrols. This switch is what turns it back into a refusal,
// and it is deliberately the ONLY thing that does — a future vendor-imposed cap has somewhere to live instead
// of enforcement being spread back through the enrolment path.
//
// Off by default is not timidity. What it enables is a refusal a tenant administrator cannot resolve
// themselves: their devices stop enrolling and the fix belongs to somebody else, which is a state to enter
// deliberately.
func registerSeatQuotaFlag() *bool {
	return flag.Bool("enforce-seat-quota", false, "refuse enrolment for a tenant that is past the seat quota it "+
		"was given. OFF by default: a quota is an operator's own capacity figure, and going past one raises an "+
		"alert while the device still enrols. Turn it on only where the quota is meant to STOP growth — what it "+
		"enables is a refusal the affected tenant's own administrator cannot fix.")
}
