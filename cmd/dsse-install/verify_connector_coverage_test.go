package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConnectorVerificationRequiresEveryTenantAnswer(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "forbidden", status: http.StatusForbidden, body: `{}`},
		{name: "malformed", status: http.StatusOK, body: `not json`},
		{name: "missing list", status: http.StatusOK, body: `{}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/admin/connectors" {
					t.Errorf("unexpected path %q", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if r.URL.Query().Get("tenant_id") == "tenant-a" {
					_, _ = w.Write([]byte(`{"connectors":[],"count":0}`))
					return
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			if ids, answered := connectorsForEveryOrganization(server.Client(), server.URL, "test-token", []string{"tenant-a", "tenant-b"}); answered {
				t.Fatalf("partial tenant answers reported complete: ids=%v", ids)
			}
		})
	}
}

func TestConnectorRegistryComparesPeersEvenWhenFirstIsEmpty(t *testing.T) {
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/tenants":
			_, _ = w.Write([]byte(`{"tenants":[{"tenant_id":"tenant-a"}]}`))
		case "/admin/connectors":
			_, _ = w.Write([]byte(`{"connectors":[],"count":0}`))
		case "/admin/enrolled-devices":
			_, _ = w.Write([]byte(`{"devices":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/admin/connectors" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"connectors":[{"id":"connector-1"}],"count":1}`))
	}))
	defer second.Close()
	results := verifyConnectorRegistryIsShared(first.Client(), []string{first.URL, second.URL}, "test-token")
	if len(results) != 1 || results[0].ok || !strings.Contains(results[0].note, "holds 0") {
		t.Fatalf("registry mismatch was not reported: %+v", results)
	}
}

func TestConnectorRegistryDoesNotCallPastTenantEnrollmentNeverUsed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/tenants":
			_, _ = w.Write([]byte(`{"tenants":[{"tenant_id":"tenant-a"}]}`))
		case "/admin/connectors":
			_, _ = w.Write([]byte(`{"connectors":[],"count":0}`))
		case "/admin/enrolled-devices":
			if r.URL.Query().Get("tenant_id") != "tenant-a" {
				t.Errorf("enrolled inventory was not read for tenant-a")
			}
			_, _ = w.Write([]byte(`{"devices":[{"identity":"connector-1","kind":"connector"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	results := verifyConnectorRegistryIsShared(server.Client(), []string{server.URL, server.URL}, "test-token")
	if len(results) != 1 || results[0].ok || !strings.Contains(results[0].note, "admitted 1 connector") {
		t.Fatalf("missing registry after a real tenant enrollment passed: %+v", results)
	}
}

func TestWhoDependsDoesNotClaimNobodyWhenTenantsCannotBeListed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/admin/tenants":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/admin/enrolled-devices":
			_, _ = w.Write([]byte(`{"devices":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	results := verifyWhoDepends(server.Client(), server.URL, "test-token")
	if len(results) != 1 || results[0].ok || !strings.Contains(results[0].note, "could not be counted") {
		t.Fatalf("incomplete tenant inventory was reported as a count: %+v", results)
	}
}
