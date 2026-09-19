package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/vlan"
)

func blockedNetworkStore(t *testing.T) (*vlan.Store, func()) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "private-networks.json")
	s := vlan.NewStore()
	if err := s.SetPersister(blobstore.FilePersister{Path: path}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.UpsertObject(model.VLANObject{ID: "own", TenantID: "tenant_own", Class: "server", CIDRs: []string{"10.61.0.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	return s, func() {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".saved", path); err != nil {
			t.Fatal(err)
		}
	}
}
func TestNetworkSaveFailureHTTP(t *testing.T) {
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/admin/vlan-objects", `{"id":"new","class":"server","cidrs":["10.62.0.0/24"]}`},
		{"DELETE", "/admin/vlan-objects/own", ""},
		{"POST", "/admin/vlan-boundary-policies", `{"id":"policy","source_class":"server","dest_class":"server","mode":"deny"}`},
	} {
		t.Run(c.method+c.path, func(t *testing.T) {
			s, repair := blockedNetworkStore(t)
			gen := s.ConfigGeneration()
			mux := http.NewServeMux()
			registerVLANRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, s, "")
			identity := adminIdentity{PrincipalID: "admin", TenantID: "tenant_own", Roles: []string{"admin"}, AuthMethod: "admin_session"}
			for i := 0; i < 2; i++ {
				status, body := vlanScopeCall(t, mux, c.method, c.path, c.body, identity)
				if status != 503 || strings.Contains(body, "private-networks") || s.ConfigGeneration() != gen {
					t.Fatalf("false/unsafe acknowledgement: %d %s", status, body)
				}
			}
			repair()
			if status, body := vlanScopeCall(t, mux, c.method, c.path, c.body, identity); status != 200 {
				t.Fatalf("retry %d %s", status, body)
			}
		})
	}
}
func TestNetworkBundleRefusesUnsavedGeneration(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(map[bool]string{false: "replacement", true: "complete-empty"}[empty], func(t *testing.T) {
			s, repair := blockedNetworkStore(t)
			payload := configBundlePayload{VLAN: &vlanBoundaryBundle{Complete: true}}
			if !empty {
				payload.VLAN.Objects = []model.VLANObject{{ID: "next", TenantID: "tenant_own", Class: "server", CIDRs: []string{"10.62.0.0/24"}}}
			}
			gen := s.ConfigGeneration()
			for i := 0; i < 2; i++ {
				if _, err := (configBundleSource{}).apply(payload, configApplyTargets{vlan: s}); !errors.Is(err, vlan.ErrPersistence) {
					t.Fatalf("unsaved bundle accepted: %v", err)
				}
				if _, ok := s.GetObject("own"); !ok || s.ConfigGeneration() != gen {
					t.Fatal("old network lost")
				}
			}
			repair()
			if _, err := (configBundleSource{}).apply(payload, configApplyTargets{vlan: s}); err != nil {
				t.Fatal(err)
			}
			if _, ok := s.GetObject("own"); ok {
				t.Fatal("retry not applied")
			}
		})
	}
}
func TestNetworkErasureReportsSaveFailure(t *testing.T) {
	s, repair := blockedNetworkStore(t)
	purge := func() adminTenantPurgeResult {
		return purgeAdminTenantData(context.Background(), "node", "tenant_own", nil, nil, nil, nil, nil, nil, "", nil, s, adminTenantExtraStores{}, nil, time.Now())
	}
	result := purge()
	if result.Complete || len(result.Failures) == 0 {
		t.Fatal("unsaved erasure completed")
	}
	if _, ok := s.GetObject("own"); !ok {
		t.Fatal("failed erasure lost network")
	}
	for _, r := range result.Erased {
		if strings.HasPrefix(r.Store, "named_network") {
			t.Fatal("unconfirmed erasure reported")
		}
	}
	repair()
	result = purge()
	if !result.Complete || len(result.Failures) != 0 {
		t.Fatalf("retry: %+v", result)
	}
}
