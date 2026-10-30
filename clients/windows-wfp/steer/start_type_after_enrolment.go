package main

// SERVICE_DEMAND_START is 3 in the Windows service API. Enrolment may promote
// that state to automatic startup, but must preserve an administrator's disabled
// or driver-specific start type.
func shouldRaiseOwnStartType(current uint32) bool { return current == 3 }
