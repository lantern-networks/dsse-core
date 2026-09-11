package main

import (
	"log"
	"time"

	"github.com/lantern-networks/dsse-core/tenantca"
)

// How close an authority may get to its expiry before this node starts saying so on every check.
//
// 30 days is not a guess: it is longer than a customer's change window and longer than the lab's own CA
// lifetime, so an organization on a short-lived authority is inside the window from the day it is registered —
// which is the honest answer, not noise.
const tenantAuthorityExpiryWarningWindow = 30 * 24 * time.Hour

// watchTenantAuthorityExpiry says, at boot and then daily, which organizations' certificate authorities are
// running out.
//
// ★ THE EXPIRY OF AN AUTHORITY WAS VISIBLE NOWHERE (2026-08-16). The certificate-health screen reports DEVICE
// certificates; the tenant-CA surface reported a COUNT. So the one certificate whose lapse stops an entire
// organization from being admitted — every device, at the handshake, at the same moment — was the one nothing
// mentioned. The reference lab's second organization holds a 30-day CA and nobody would have been told.
//
// Said on a schedule rather than only at boot, because a node that has been up for three weeks is exactly the
// node whose authority is now three weeks closer to lapsing, and a warning printed once at startup is a
// warning nobody was in the room for.
func watchTenantAuthorityExpiry(registry *tenantca.TenantCARegistry, now func() time.Time) func() {
	if registry == nil {
		return func() {}
	}
	if now == nil {
		now = time.Now
	}
	report := func() {
		for _, fact := range registry.Facts(now()) {
			switch {
			case fact.Expired:
				log.Printf("tenant_authority ★ EXPIRED tenant=%q ca=%q sha256=%s expired_at=%s — devices of this "+
					"organization are NOT being admitted; their certificates chain to an authority that is no longer "+
					"valid. Register a replacement CA (POST /admin/tenant-cas) and re-issue their certificates.",
					fact.TenantID, fact.CommonName, fact.SHA256[:16], fact.NotAfter)
			case time.Duration(fact.DaysLeft)*24*time.Hour <= tenantAuthorityExpiryWarningWindow:
				log.Printf("tenant_authority ★ EXPIRING tenant=%q ca=%q sha256=%s not_after=%s days_left=%d — when "+
					"it lapses EVERY device of this organization stops being admitted at the handshake, together. "+
					"Register the replacement before then; both may be registered at once, which is how devices "+
					"are moved across rather than cut over.",
					fact.TenantID, fact.CommonName, fact.SHA256[:16], fact.NotAfter, fact.DaysLeft)
			}
		}
	}
	report()
	ticker := time.NewTicker(24 * time.Hour)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				report()
			case <-stop:
				ticker.Stop()
				return
			}
		}
	}()
	return func() { close(stop) }
}
