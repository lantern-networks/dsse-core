package revocation

import "strings"

// RemoveDevicesChecked saves before publishing removal. Device IDs preserve case.
// Explicit retries save even when no live marks remain, reconciling an earlier
// uncertain write. Nil persistence retains the overlay's volatile contract.
func (o *HighRiskOverlay) RemoveDevicesChecked(deviceIDs []string) (int, error) {
	return o.RemoveTenantRisksChecked("", deviceIDs)
}

// RemoveTenantRisksChecked removes a tenant's users and the specified devices in
// one shared risk snapshot. The caller must resolve device ownership from the
// inventory before erasing that inventory; this store cannot infer it. Other
// tenant stores are separate transactions. A save error can leave old or new
// saved bytes, but neither live map nor its generation is changed on error.
func (o *HighRiskOverlay) RemoveTenantRisksChecked(tenant string, deviceIDs []string) (int, error) {
	tenant = strings.TrimSpace(tenant)
	if o == nil || (tenant == "" && len(deviceIDs) == 0) {
		return 0, nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.loadErr != nil || o.legacy {
		return 0, ErrRiskUnavailable
	}
	devices := make(map[string]string, len(o.devices))
	for id, severity := range o.devices {
		devices[id] = severity
	}
	users := cloneUserRisks(o.users)
	n := 0
	for _, id := range deviceIDs {
		id = NormalizeDeviceID(id)
		if _, exists := devices[id]; exists {
			delete(devices, id)
			n++
		}
	}
	if tenant != "" {
		for key, mark := range users {
			if mark.TenantID == tenant {
				delete(users, key)
				n++
			}
		}
	}
	if _, err := o.saveStateLocked(devices, users); err != nil {
		return 0, err
	}
	if n > 0 {
		o.devices, o.users = devices, users
		o.rebuildUserIndexLocked()
		o.generation.Add(1)
	}
	return n, nil
}
