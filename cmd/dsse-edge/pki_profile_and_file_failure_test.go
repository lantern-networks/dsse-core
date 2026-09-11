package main

import (
	"bytes"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/installprofile"
)

func TestPKIProfileRefusesUnknownAuthorityAfterSharedReadFailure(t *testing.T) {
	unavailable := func() ([]byte, error) { return nil, errors.New("database unavailable") }
	configs := map[string]serverConfig{
		"transport":    {TenantTransportAuthority: newTenantTransportAuthorityWithReload(nil, nil, unavailable, time.Now)},
		"device":       {TenantDeviceAuthority: newTenantDeviceAuthorityWithReload(nil, nil, unavailable, time.Now)},
		"interception": {TenantInterceptionAuthority: newTenantInterceptionAuthorityWithReload(nil, nil, unavailable, time.Now)},
	}
	for kind, config := range configs {
		t.Run(kind, func(t *testing.T) {
			for _, spec := range []installprofile.DeploymentSpec{{}, {DeviceCAPinSHA256: "old", InterceptionRootPEM: "old"}} {
				if got := organizationAuthoritiesUnavailable(config, "tenant_unseen", spec); !strings.Contains(got, "read failed") {
					t.Fatalf("failed read was treated as absent authority: %q", got)
				}
			}
		})
	}
}

func TestPKIFileAuthorityRejectsAnotherWritersSnapshot(t *testing.T) {
	for _, key := range []string{"tenant_transport_authorities", "tenant_device_authorities", "tenant_interception_authorities"} {
		t.Run(key, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "authority.json")
			first, err := cpStateBlobPersister(path, nil, key)
			if err != nil {
				t.Fatal(err)
			}
			second, err := cpStateBlobPersister(path, nil, key)
			if err != nil {
				t.Fatal(err)
			}
			for _, p := range []blobstore.Persister{first, second} {
				if _, err := p.Load(); err != nil {
					t.Fatal(err)
				}
			}
			winner := []byte(`[{"tenant_id":"tenant_a"}]`)
			if err := first.Save(winner); err != nil {
				t.Fatal(err)
			}
			if err := second.Save([]byte(`[]`)); !errors.Is(err, blobstore.ErrConcurrentWriter) {
				t.Fatalf("lost write not rejected: %v", err)
			}
			got, err := second.Load()
			if err != nil || !bytes.Equal(got, winner) {
				t.Fatalf("winner was replaced: %s %v", got, err)
			}
		})
	}
}
