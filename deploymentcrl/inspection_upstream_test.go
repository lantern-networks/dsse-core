package deploymentcrl

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOneEntranceServesBothKindsOfList(t *testing.T) {
	var sawHost, sawPath string
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawHost, sawPath = r.Host, r.URL.Path
		w.Header().Set("Content-Type", "application/pkix-crl")
		_, _ = w.Write([]byte("organization list"))
	}))
	defer controlPlane.Close()
	deploymentLists := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("deployment list")) })
	h, err := WithInspectionCRLUpstream(deploymentLists, []string{"http://crl.example.test"}, strings.TrimPrefix(controlPlane.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	get := func(method, host, path string) (int, string) {
		req := httptest.NewRequest(method, "http://"+host+path, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	const org = "/pki/crl/tenant_a/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.crl"
	if code, body := get("GET", "crl.example.test", org); code != 200 || body != "organization list" {
		t.Fatalf("organization list: %d %q", code, body)
	}
	if sawHost != "crl.example.test" || sawPath != org {
		t.Fatalf("the control plane was asked for %q on %q; it checks both against the certificate", sawPath, sawHost)
	}
	if code, body := get("GET", "crl.example.test", "/pki/deployment-crl/x/y.crl"); code != 200 || body != "deployment list" {
		t.Fatalf("deployment list: %d %q", code, body)
	}
	for name, c := range map[string][3]string{
		"another host":   {"GET", "other.example.test", org},
		"a query":        {"GET", "crl.example.test", org + "?a=1"},
		"not a list":     {"GET", "crl.example.test", "/pki/crl/tenant_a/secrets"},
		"a way upward":   {"GET", "crl.example.test", "/pki/crl/../admin/x.crl"},
		"another method": {"POST", "crl.example.test", org},
	} {
		if code, _ := get(c[0], c[1], c[2]); code == 200 {
			t.Errorf("%s was handed to the control plane", name)
		}
	}
	if _, err := WithInspectionCRLUpstream(deploymentLists, []string{"http://crl.example.test"}, "10.0.0.5:18080"); err == nil {
		t.Fatal("an upstream that is not on this machine was accepted")
	}
}

func TestTheSameOriginIsServedHoweverItsPortIsSpelled(t *testing.T) {
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("list")) }))
	defer controlPlane.Close()
	const path = "/pki/crl/tenant_a/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.crl"
	for _, declared := range []string{"http://crl.example.test:80", "http://crl.example.test", "http://CRL.example.test"} {
		h, err := WithInspectionCRLUpstream(http.NotFoundHandler(), []string{declared}, strings.TrimPrefix(controlPlane.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		for _, asked := range []string{"crl.example.test", "crl.example.test:80", "CRL.EXAMPLE.TEST"} {
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("GET", "http://"+asked+path, nil))
			if rec.Code != 200 {
				t.Errorf("declared %q, asked as %q: %d", declared, asked, rec.Code)
			}
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "http://crl.example.test:8080"+path, nil))
		if rec.Code == 200 {
			t.Errorf("declared %q: another port was served", declared)
		}
	}
}
