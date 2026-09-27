package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	configversion "github.com/lantern-networks/dsse-core/configversion"
)

// shipConfigVersionToCP records a version of an Edge-side admin resource on the control plane (best-effort).
// A failure is logged but never fails the admin change (the change already applied). actor preserves the
// original admin's identity.
func shipConfigVersionToCP(r *http.Request, client *cpConfigVersionClient, resourceType, resourceID, action, note string, payload any) {
	if client == nil {
		return
	}
	actor := "admin"
	if identity, ok := adminIdentityFromRequest(r); ok && strings.TrimSpace(identity.PrincipalID) != "" {
		actor = identity.PrincipalID
	}
	if err := client.Ship(r.Context(), resourceType, resourceID, action, actor, note, payload); err != nil {
		log.Printf("WARNING: ship config version (%s/%s) to control plane failed: %v", resourceType, resourceID, err)
	}
}

// cpConfigVersionClient lets the zero-DB enforcing Edge record + read config versions on the control plane
// (which owns the durable config_versions store). The Edge ships a version whenever it applies an
// admin-managed change (e.g. tenant-restriction) and reads history / a snapshot to roll back. Reuses the
// CP→Edge sync channel (control-plane URL + admin bearer + pinned CA).
type cpConfigVersionClient struct {
	url    string
	token  string
	client *http.Client
}

type configVersionRecordRequest struct {
	ResourceType string          `json:"resource_type"`
	ResourceID   string          `json:"resource_id"`
	Action       string          `json:"action"`
	Actor        string          `json:"actor"`
	Note         string          `json:"note"`
	Payload      json.RawMessage `json:"payload"`
}

func (c *cpConfigVersionClient) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(c.url, "/")+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("control plane %s %s: %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

// Ship records a version on the control plane (best-effort caller). actor preserves the original admin.
func (c *cpConfigVersionClient) Ship(ctx context.Context, resourceType, resourceID, action, actor, note string, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, "/admin/config-versions",
		configVersionRecordRequest{ResourceType: resourceType, ResourceID: resourceID, Action: action, Actor: actor, Note: note, Payload: raw}, nil)
}

// List returns the version history (newest first) for a resource.
func (c *cpConfigVersionClient) List(ctx context.Context, resourceType, resourceID string) ([]configversion.Version, error) {
	var out struct {
		Versions []configversion.Version `json:"versions"`
	}
	if err := c.do(ctx, http.MethodGet, "/admin/config-versions/"+resourceType+"/"+resourceID, nil, &out); err != nil {
		return nil, err
	}
	return out.Versions, nil
}

// Get returns a specific version's snapshot.
func (c *cpConfigVersionClient) Get(ctx context.Context, resourceType, resourceID string, versionNo int64) (configversion.Version, bool, error) {
	var v configversion.Version
	err := c.do(ctx, http.MethodGet, fmt.Sprintf("/admin/config-versions/%s/%s/%d", resourceType, resourceID, versionNo), nil, &v)
	if err != nil {
		if strings.Contains(err.Error(), ": 404:") {
			return configversion.Version{}, false, nil
		}
		return configversion.Version{}, false, err
	}
	return v, true, nil
}

// recordConfigVersion appends a config version when versioning is enabled (control plane). Best-effort: a
// recording failure is logged but never fails the admin operation (the config change already succeeded).
func recordConfigVersion(r *http.Request, store configversion.Store, resourceType, resourceID, action, note string, payload any) {
	recordConfigVersionForTenant(r, store, adminTenantIDFromRequest(r), resourceType, resourceID, action, note, payload)
}

// The target must already be authorized by the route, including an operator's
// explicit body tenant when it differs from the current request context.
func recordConfigVersionForTenant(r *http.Request, store configversion.Store, tenantID, resourceType, resourceID, action, note string, payload any) {
	if store == nil {
		return
	}
	actor := "admin"
	if identity, ok := adminIdentityFromRequest(r); ok {
		if strings.TrimSpace(identity.PrincipalID) != "" {
			actor = identity.PrincipalID
		} else if strings.TrimSpace(identity.APITokenID) != "" {
			actor = "api-token:" + identity.APITokenID
		}
	}
	if _, err := store.Record(r.Context(), tenantID, resourceType, resourceID, action, actor, note, payload); err != nil {
		log.Printf("WARNING: record config version (%s/%s) failed: %v", resourceType, resourceID, err)
	}
}
