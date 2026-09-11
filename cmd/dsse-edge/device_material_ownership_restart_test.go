package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/deviceca"
	"github.com/lantern-networks/dsse-core/tenantca"
)

// Three sections, one situation: a node that has RESTARTED and not yet installed device material.
func TestMaterialOwnershipRejectsStaleConfigAfterDiskRestart(t *testing.T) {
	for _, tc := range []struct {
		name string
		make func(*tenantca.TenantCARegistry) *deviceCARegistryBundle
	}{
		{"cp declares this org managed", func(r *tenantca.TenantCARegistry) *deviceCARegistryBundle {
			s := deviceCABundleSection(r, nil)
			s.ManagedComplete, s.ManagedTenants = true, []string{"tenant_rotating"}
			return s
		}},
		{"old section, no managed declaration", func(r *tenantca.TenantCARegistry) *deviceCARegistryBundle {
			s := deviceCABundleSection(r, nil)
			s.ManagedComplete, s.ManagedTenants = false, nil
			return s
		}},
		{"cp has no device authority: declares managed set EMPTY", func(r *tenantca.TenantCARegistry) *deviceCARegistryBundle {
			return deviceCABundleSection(r, nil) // managed == nil -> ManagedComplete true, ManagedTenants []
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			isolatedDeviceAuthorityPools(t)
			reg := tenantca.NewTenantCARegistry()
			path := filepath.Join(t.TempDir(), "registry.json")
			persist := func(c *tenantca.TenantCARegistry) error { return c.Save(path) }
			old, oldPEM, oldKey := deviceAdmissionTestCA(t, "rotating-device-ca")
			next, nextPEM, nextKey := deviceAdmissionTestCA(t, "rotating-device-ca")
			if err := tenantDeviceIdentity.Install(deviceMaterialForCA(t, "tenant_rotating", old, oldKey, string(oldPEM)), reg, persist); err != nil {
				t.Fatal(err)
			}
			stale := tc.make(reg) // CP snapshot taken while the OLD CA was in force
			if err := tenantDeviceIdentity.Install(deviceMaterialForCA(t, "tenant_rotating", next, nextKey, string(nextPEM)), reg, persist); err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
			server.TLS = &tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				return &tls.Config{Certificates: server.TLS.Certificates, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: edgeClientCAPool()}, nil
			}}
			server.StartTLS()
			defer server.Close()
			roots := x509.NewCertPool()
			roots.AddCert(server.Certificate())
			admitted := func(c tls.Certificate) bool {
				tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{c}}, DisableKeepAlives: true}
				defer tr.CloseIdleConnections()
				res, err := (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Post(server.URL, "application/json", nil)
				if res != nil {
					io.Copy(io.Discard, res.Body)
					res.Body.Close()
				}
				return err == nil
			}
			oldLeaf, nextLeaf := deviceLeafForCA(t, old, oldKey), deviceLeafForCA(t, next, nextKey)
			if admitted(oldLeaf) || !admitted(nextLeaf) {
				t.Fatal("precondition failed before the restart")
			}
			// ---- the restart: signers are in-memory only and start empty.
			tenantDeviceIdentity = &tenantDeviceSigners{signers: map[string]*deviceca.Signer{}, rotation: map[string]deviceAuthorityFingerprints{}}
			var err error
			reg, err = tenantca.LoadTenantCARegistry(path)
			if err != nil {
				t.Fatal(err)
			}
			setEdgeClientRegistryCAs(reg.Anchors())
			applyDeviceCABundleSection(reg, stale, persist, func(f string, a ...interface{}) { t.Logf("    log: "+f, a...) })
			if admitted(oldLeaf) || !admitted(nextLeaf) {
				t.Fatal("stale configuration inverted device admission after disk restart")
			}
			t.Logf("  RESULT  managed_complete=%v managed=%v -> retired-admitted=%v current-admitted=%v anchors=%d",
				stale.ManagedComplete, stale.ManagedTenants, admitted(oldLeaf), admitted(nextLeaf), reg.Registrations()["tenant_rotating"])
		})
	}
}
