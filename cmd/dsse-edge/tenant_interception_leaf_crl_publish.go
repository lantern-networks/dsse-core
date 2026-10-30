package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// publishTenantLeafCRL uses the same authenticated Edge-to-CP channel as the
// material fetch. The public CDP itself carries no bearer or client identity.
func (f *tenantTransportMaterialFetcher) publishTenantLeafCRL(interception *edgeplane.NetworkExtensionLabTLSInterception, tenant string) error {
	now := time.Now().UTC()
	fp, der, enabled, err := interception.SignTenantLeafCRL(tenant, now)
	if err != nil || !enabled {
		return err
	}
	body, err := json.Marshal(map[string]any{"tenant_id": tenant, "issuer_sha256": fp, "der": der})
	if err != nil {
		return err
	}
	endpoint := strings.TrimSuffix(f.currentEndpoint(), "/tenant-edge-material") + "/tenant-inspection-crl"
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+f.token)
	resp, err := f.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("control plane rejected signed leaf CRL (HTTP %d)", resp.StatusCode)
	}
	return interception.ConfirmTenantLeafCRL(tenant, fp, der, now)
}
