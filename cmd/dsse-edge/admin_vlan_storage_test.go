package main

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/vlan"
)

type vlanSaveProbe struct {
	data []byte
	fail bool
}

func (p *vlanSaveProbe) Load() ([]byte, error) { return append([]byte(nil), p.data...), nil }
func (p *vlanSaveProbe) Save(data []byte) error {
	if p.fail {
		return errors.New("private storage location unavailable")
	}
	p.data = append([]byte(nil), data...)
	return nil
}

func TestVLANObjectHTTPRejectsUnconfirmedStorageAndPermitsRetry(t *testing.T) {
	store := vlan.NewStore()
	p := &vlanSaveProbe{}
	if err := store.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerVLANRoutes(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }, store, "")
	caller := adminIdentity{PrincipalID: "adm_network", TenantID: "tenant_network", Roles: []string{"admin"}, AuthMethod: "admin_session"}
	post := func(id string) (int, string) {
		return vlanScopeCall(t, mux, http.MethodPost, "/admin/vlan-objects", `{"id":"`+id+`","name":"Network","class":"server","cidrs":["192.0.2.0/24"]}`, caller)
	}
	if code, body := post("net-old"); code != http.StatusOK {
		t.Fatalf("seed: %d %s", code, body)
	}
	baseGeneration := store.ConfigGeneration()
	baseData := string(p.data)
	p.fail = true
	for i := 0; i < 2; i++ {
		if code, body := post("net-new"); code != http.StatusServiceUnavailable || strings.Contains(body, "private storage location") {
			t.Fatalf("failed create %d: %d %s", i, code, body)
		}
		if _, ok := store.GetObject("net-new"); ok {
			t.Fatal("failed create became live")
		}
		if store.ConfigGeneration() != baseGeneration || string(p.data) != baseData {
			t.Fatal("failed create changed generation or saved bytes")
		}
	}
	for i := 0; i < 2; i++ {
		code, body := vlanScopeCall(t, mux, http.MethodDelete, "/admin/vlan-objects/net-old", "", caller)
		if code != http.StatusServiceUnavailable || strings.Contains(body, "private storage location") {
			t.Fatalf("failed delete %d: %d %s", i, code, body)
		}
		if _, ok := store.GetObject("net-old"); !ok {
			t.Fatal("failed delete removed live object")
		}
		if store.ConfigGeneration() != baseGeneration || string(p.data) != baseData {
			t.Fatal("failed delete changed generation or saved bytes")
		}
	}
	p.fail = false
	if code, body := post("net-new"); code != http.StatusOK {
		t.Fatalf("retry create: %d %s", code, body)
	}
	if code, body := vlanScopeCall(t, mux, http.MethodDelete, "/admin/vlan-objects/net-old", "", caller); code != http.StatusOK {
		t.Fatalf("retry delete: %d %s", code, body)
	}
	reloaded := vlan.NewStore()
	if err := reloaded.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, ok := reloaded.GetObject("net-new"); !ok {
		t.Fatal("new object missing after reload")
	}
	if _, ok := reloaded.GetObject("net-old"); ok {
		t.Fatal("deleted object revived after reload")
	}
}
