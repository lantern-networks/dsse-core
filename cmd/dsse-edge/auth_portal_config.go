package main

import (
	"flag"
	"os"
)

// Authentication configuration belongs beside its implementation, not in the
// frozen main flag block. This preserves the existing command-line contract.
func registerStepUpPortalOriginsFlag() *string {
	return flag.String("step-up-portal-origins", "", "comma-separated HTTPS origins of this deployment's authentication portals; carried as exact never-steer hosts in signed endpoint profiles, independently of Console CORS")
}

func registerEntrancePortalOriginsFlag() *string {
	return flag.String("entrance-portal-origins", os.Getenv("DSSE_ENTRANCE_PORTAL_ORIGINS"), "explicit JSON map of transport TLS SNI to an approved Portal HTTPS origin; enables shared-fleet routing after ceremony-recovery activation; unset preserves owner-pinned upgrade behavior")
}
