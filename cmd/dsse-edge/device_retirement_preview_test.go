package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestDeviceRetirementPreviewUsesRealCandidateWithoutChangingAuthority(t *testing.T) {
	for _, abandoned := range []bool{false, true} {
		_, de, _ := pkiTestAuthorities(t)
		if abandoned {
			if _, err := de.AbandonRotation("tenant_a"); err != nil {
				t.Fatal(err)
			}
		}
		before := encodeAuthoritySnapshot(de.cas)
		desired := de.cas["tenant_a"].Incoming.CACertPEM
		if abandoned {
			desired = de.cas["tenant_a"].CACertPEM
		}
		for _, deny := range []bool{false, true} {
			called := false
			out := previewDeviceRetirement(de, "tenant_a", []pkiTransitionAdmission{func(c pkiAuthorityTransition) error {
				called = true
				if c.Kind != "device" || c.Action != "retire-previous" || c.Tenant != "tenant_a" || c.DeviceBefore.Incoming == nil || c.DeviceAfter.Incoming != nil || c.DeviceAfter.CACertPEM != desired {
					t.Fatal("preview differs from actual retirement candidate")
				}
				if deny {
					return errors.New("pki_device_not_migrated: active device")
				}
				return nil
			}})
			if !called || out.Allowed == deny || (deny && out.Reason == "") {
				t.Fatalf("wrong preview verdict: %+v", out)
			}
			if !bytes.Equal(before, encodeAuthoritySnapshot(de.cas)) {
				t.Fatal("preview changed the authority")
			}
		}
		if out := previewDeviceRetirement(de, "tenant_a", nil); out.Allowed || out.Reason == "" {
			t.Fatal("missing authoritative gate reported ready")
		}
	}
}

func TestDeviceAuthorityReadPreviewFailsClosedOnDurableReadError(t *testing.T) {
	_, original, _ := pkiTestAuthorities(t)
	backend := &authorityMemoryCAS{data: encodeAuthoritySnapshot(original.cas)}
	de := newTenantDeviceAuthorityWithReload(backend.data, nil, backend.Load, time.Now)
	mux := http.NewServeMux()
	admin := func(_ string, h http.HandlerFunc) http.HandlerFunc { return h }
	called := false
	registerTenantAuthorityReadRoutes(mux, admin, de, nil, func(pkiAuthorityTransition) error {
		called = true
		return errors.New("pki_fleet_not_ready: region unavailable")
	})
	ask := func(path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		r = requestWithAdminIdentity(r, adminIdentity{PrincipalID: "adm_test", TenantID: "tenant_a"})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	w := ask("/admin/tenant-device-authority?readiness=1")
	if w.Code != 200 || !called {
		t.Fatalf("preview not measured: HTTP %d %s", w.Code, w.Body.String())
	}
	var answer struct {
		Readiness deviceRetirementPreview `json:"retirement_readiness"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	if answer.Readiness.Allowed || answer.Readiness.Reason != "pki_fleet_not_ready: region unavailable" {
		t.Fatal("preview concealed actual gate refusal")
	}
	called = false
	if w := ask("/admin/tenant-device-authority"); w.Code != 200 || called {
		t.Fatal("ordinary metadata read performed network preview")
	}
	backend.readErr = errors.New("database unavailable")
	if w := ask("/admin/tenant-device-authority?readiness=1"); w.Code != 503 || called {
		t.Fatal("database failure exposed stale authority or readiness")
	}
}
