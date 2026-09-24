package main

import (
	"github.com/lantern-networks/dsse-core/internalca"
	"net/http"
	"testing"
	"time"
)

type changingInternalCAPool struct {
	store  *internalca.Store
	change bool
}

func (p *changingInternalCAPool) AnchorsPEM(tenant string, now time.Time) []string {
	material := p.store.AnchorsPEM(tenant, now)
	if p.change {
		p.change = false
		p.store.Delete("removed", tenant, now)
	}
	return material
}
func (p *changingInternalCAPool) Revision(tenant string) uint64 { return p.store.Revision(tenant) }
func TestInternalCATransportCannotCacheRemovedTrustUnderNewRevision(t *testing.T) {
	now := time.Now()
	asset, removed := privateAsset(t)
	_, retained := privateAsset(t)
	s, _ := internalca.NewStore(nil)
	for id, material := range map[string]string{"removed": removed, "retained": retained} {
		if _, err := s.Upsert(internalca.Authority{ID: id, TenantID: "tenant", CertificatePEM: material}, now); err != nil {
			t.Fatal(err)
		}
	}
	pool := &changingInternalCAPool{store: s, change: true}
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.DisableKeepAlives = true
	defer base.CloseIdleConnections()
	// A removal occurs after the request took its material snapshot, before it asks for the revision.
	stale := upstreamTransportTrustingTheOrganizationsPrivateAssets(base, pool, "tenant", now)
	response, err := (&http.Client{Transport: stale}).Get(asset.URL)
	if err != nil {
		t.Fatal("in-flight snapshot setup failed", err)
	}
	response.Body.Close()
	if len(s.AnchorsPEM("tenant", now)) != 1 {
		t.Fatal("removal setup failed")
	}
	next := upstreamTransportTrustingTheOrganizationsPrivateAssets(base, pool, "tenant", now)
	response, err = (&http.Client{Transport: next}).Get(asset.URL)
	if err == nil {
		response.Body.Close()
		t.Fatal("a later request reused trust removed before that request began")
	}
}
func TestInternalCATransportDoesNotShareDifferentStoresAtSameRevision(t *testing.T) {
	now := time.Now()
	asset, first := privateAsset(t)
	_, second := privateAsset(t)
	a, _ := internalca.NewStore(nil)
	b, _ := internalca.NewStore(nil)
	a.Upsert(internalca.Authority{ID: "a", TenantID: "tenant", CertificatePEM: first}, now)
	b.Upsert(internalca.Authority{ID: "b", TenantID: "tenant", CertificatePEM: second}, now)
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.DisableKeepAlives = true
	defer base.CloseIdleConnections()
	response, err := (&http.Client{Transport: upstreamTransportTrustingTheOrganizationsPrivateAssets(base, a, "tenant", now)}).Get(asset.URL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	response, err = (&http.Client{Transport: upstreamTransportTrustingTheOrganizationsPrivateAssets(base, b, "tenant", now)}).Get(asset.URL)
	if err == nil {
		response.Body.Close()
		t.Fatal("different store inherited cached trust at same revision")
	}
}
