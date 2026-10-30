package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestStartupMaterialPresenceIncludesSharedTransportTenants(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		interception, device []string
		failInstall          bool
		want                 int64
		wantError            bool
	}{
		{name: "empty remains empty"},
		{name: "interception without tenant transport", interception: []string{"tenant_a"}, want: 1},
		{name: "device without tenant transport", device: []string{"tenant_a"}, want: 1},
		{name: "same organization across tiers counted once", interception: []string{"tenant_a"}, device: []string{"tenant_a"}, want: 1},
		{name: "different organizations counted", interception: []string{"tenant_a"}, device: []string{"tenant_b"}, want: 2},
		{name: "failed installations cannot signal readiness", interception: []string{"tenant_a"}, device: []string{"tenant_a"}, failInstall: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				interception := []tenantInterceptionMaterial{}
				device := []tenantDeviceMaterial{}
				for _, tenant := range tc.interception {
					interception = append(interception, tenantInterceptionMaterial{TenantID: tenant})
				}
				for _, tenant := range tc.device {
					device = append(device, tenantDeviceMaterial{TenantID: tenant})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"interception": interception, "device_identity": device, "generation": 1})
			}))
			defer server.Close()
			f := newTenantTransportMaterialFetcher(server.URL, "test-only", nil, func() []string { return nil })
			f.dataURL = func() string { return "" }
			load := func() error {
				if tc.failInstall {
					return errors.New("installation failed")
				}
				return nil
			}
			f.loadInterception = func(tenantInterceptionMaterial) error { return load() }
			f.loadDeviceIdentity = func(tenantDeviceMaterial) error { return load() }
			_, err := f.FetchOnce()
			if (err != nil) != tc.wantError {
				t.Fatalf("fetch error = %v, wantError %v", err, tc.wantError)
			}
			if got := f.installedTenants.Load(); got != tc.want {
				t.Fatalf("installed organizations = %d, want %d", got, tc.want)
			}
			if tc.failInstall && f.generation != 0 {
				t.Fatal("failed installation adopted the authority generation")
			}
		})
	}
}
