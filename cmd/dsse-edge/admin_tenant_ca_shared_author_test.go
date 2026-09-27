package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"

	"github.com/lantern-networks/dsse-core/tenantca"
)

type transactionalCAFixture struct {
	mu         sync.Mutex
	raw        []byte
	failCommit bool
}

func (p *transactionalCAFixture) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return bytes.Clone(p.raw), nil
}
func (p *transactionalCAFixture) Save(raw []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.raw = bytes.Clone(raw)
	return nil
}
func (p *transactionalCAFixture) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	next, err := edit(bytes.Clone(p.raw))
	if err == nil && p.failCommit {
		return fmt.Errorf("commit rejected")
	}
	if err == nil {
		p.raw = bytes.Clone(next)
	}
	return err
}
func TestSharedCAAuthorDoesNotResurrectPeerWithdrawal(t *testing.T) {
	a, _, _, _ := tenantCARoutesForTest(t)
	storeA := tenantCAHarnessTenantStore
	b, _, _, _ := tenantCARoutesForTest(t)
	oldP, oldCP := tenantCARegistryShared, edgeIsControlPlane
	defer func() { tenantCARegistryShared = oldP; edgeIsControlPlane = oldCP }()
	p := &transactionalCAFixture{}
	tenantCARegistryShared = p
	edgeIsControlPlane = true
	deviceClientCAs = nil
	gone, gonePEM := tenantCATestCA(t, "Retire")
	_, keep := tenantCATestCA(t, "Keep")
	_, peer := tenantCATestCA(t, "Peer")
	_, newPEM := tenantCATestCA(t, "New")
	for _, pem := range [][]byte{gonePEM, keep} {
		r := doTenantCARequest(t, a, "POST", "/admin/tenant-cas", map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(pem)}, storeA)
		if r.Code != 201 {
			t.Fatal(r.Code, r.Body)
		}
	}
	r := doTenantCARequest(t, b, "POST", "/admin/tenant-cas", map[string]string{"tenant_id": "tenant_acme", "ca_pem": string(peer)})
	if r.Code != 201 {
		t.Fatal(r.Code, r.Body)
	}
	rawExtension, _ := p.Load()
	var extension map[string]any
	json.Unmarshal(rawExtension, &extension)
	extension["future_field"] = "keep"
	rawExtension, _ = json.Marshal(extension)
	p.Save(rawExtension)
	r = doTenantCARequest(t, a, "DELETE", "/admin/tenant-cas/tenant_northwind/"+tenantca.CAAnchorKey(gone), nil, storeA)
	if r.Code != 200 {
		t.Fatal(r.Code, r.Body)
	}
	r = doTenantCARequest(t, b, "POST", "/admin/tenant-cas", map[string]string{"tenant_id": "tenant_acme", "ca_pem": string(newPEM)})
	if r.Code != 201 {
		t.Fatal(r.Code, r.Body)
	}
	raw, _ := p.Load()
	if !bytes.Contains(raw, []byte(`"future_field":"keep"`)) {
		t.Fatal("extension lost")
	}
	fresh, err := tenantca.RegistryFromSnapshot(raw)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Registrations()["tenant_northwind"] != 1 || fresh.Registrations()["tenant_acme"] != 2 {
		t.Fatal("stale writer resurrected withdrawal", fresh.Registrations())
	}
}

func TestSharedCAAuthorFailedCommitLeavesLocalUnchanged(t *testing.T) {
	out := &recordingAdminAuditOutboxDeadReader{}
	h, reg, _, _ := tenantCARoutesForTest(t, out)
	oldP, oldCP := tenantCARegistryShared, edgeIsControlPlane
	defer func() { tenantCARegistryShared = oldP; edgeIsControlPlane = oldCP }()
	p := &transactionalCAFixture{failCommit: true}
	tenantCARegistryShared = p
	edgeIsControlPlane = true
	deviceClientCAs = nil
	_, pem := tenantCATestCA(t, "Uncommitted")
	r := doTenantCARequest(t, h, "POST", "/admin/tenant-cas", map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(pem)})
	if r.Code != 503 || len(reg.Registrations()) != 0 || p.raw != nil {
		t.Fatal("failed commit changed live or durable attribution", r.Code, r.Body)
	}
	found := false
	for _, a := range out.insertedAudits {
		if a.Action != nil && *a.Action == "tenant_ca_register" {
			found = true
			if stringPtrValue(a.Result) != "error" || a.Metadata["applied"] != false || len(a.Metadata["ca_sha256"].([]string)) != 1 {
				t.Fatal("failed commit audit", a)
			}
		}
	}
	if !found {
		t.Fatal("missing domain audit")
	}
	p.failCommit = false
	r = doTenantCARequest(t, h, "POST", "/admin/tenant-cas", map[string]string{"tenant_id": "tenant_northwind", "ca_pem": string(pem)})
	if r.Code != 201 || reg.Registrations()["tenant_northwind"] != 1 {
		t.Fatal(r.Code, r.Body)
	}
}
