package main

import "sync"

const authWaitEdgeLimit = 1024
const authWaitTenantLimit = 256
const authWaitDeviceLimit = 32

type authWaitKey struct{ tenant, device string }

// A slot covers the entire wait, including its at-most 16 KiB mux buffer.
// Count per tenant/device, not per TCP tunnel, so opening more tunnels cannot
// bypass the quota. It is local to an Edge and grants no authorization.
// restart-durability: ephemeral — only reservations for live sockets; process exit closes those sockets.
// populated-by: side_effect — acquire/release around waitForStepUpGrant; no authorization or inventory is stored.
type authWaitBudget struct {
	mu      sync.Mutex
	total   int
	tenants map[string]int
	devices map[authWaitKey]int
}

func (b *authWaitBudget) acquire(tenant, device string) (func(), bool) {
	if tenant == "" || device == "" {
		return nil, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	key := authWaitKey{tenant, device}
	if b.total >= authWaitEdgeLimit || b.tenants[tenant] >= authWaitTenantLimit || b.devices[key] >= authWaitDeviceLimit {
		return nil, false
	}
	if b.tenants == nil {
		b.tenants = make(map[string]int)
		b.devices = make(map[authWaitKey]int)
	}
	b.total++
	b.tenants[tenant]++
	b.devices[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			b.total--
			b.tenants[tenant]--
			b.devices[key]--
			if b.tenants[tenant] == 0 {
				delete(b.tenants, tenant)
			}
			if b.devices[key] == 0 {
				delete(b.devices, key)
			}
		})
	}, true
}
