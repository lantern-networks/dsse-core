package main

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/appcatalog"
	"github.com/lantern-networks/dsse-core/connector"
	"github.com/lantern-networks/dsse-core/edgeplane"
	"github.com/lantern-networks/dsse-core/model"
)

func TestDisabledApplicationCannotSelectConnector(t *testing.T) {
	ctx := context.Background()
	tenant := "tenant_lab_001"
	catalog := appcatalog.NewStore()
	registry := connector.NewRegistry()
	_, err := registry.Register(model.ConnectorRegistration{ID: "conn-test", TenantID: tenant, ConnectorGroupID: "site", ApplicationIDs: []string{"wiki"}, PrivateBaseURL: "http://connector.invalid", Status: "registered"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for _, status := range []string{"active", "disabled", "active"} {
		entry, err := catalog.Upsert(ctx, appcatalog.Entry{TenantID: tenant, ApplicationID: "wiki", Name: "Wiki", ApplicationType: "private_app", Status: status, Published: true, Destination: "wiki.example.test", DestinationPort: 443, PublishProtocol: "web", ConnectorGroupID: "site"}, tenant, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/apps/wiki", "/apps/wiki?connector_id=conn-test"} {
			_, found, err := connectorForApplication(ctx, httptest.NewRequest("GET", path, nil), registry, catalog, tenant, "wiki")
			if err != nil || found != (status == "active") {
				t.Errorf("status=%s path=%s found=%v err=%v", status, path, found, err)
			}
		}
		base := map[string]edgeplane.ApplicationRouteProfile{"wiki": {Destination: "startup.example.test"}, "unrelated": {Destination: "other.example.test"}}
		routes := edgeplane.RouteProfilesWithPublishedCatalog(base, catalog, tenant)
		_, found := routes["wiki"]
		if found != (status == "active") {
			t.Errorf("status=%s effective route present=%v", status, found)
		}
		if base["wiki"].Destination != "startup.example.test" || routes["unrelated"].Destination != "other.example.test" {
			t.Fatal("unrelated/startup route changed")
		}
		if got := applicationPublishReview(entry, testEvaluator(), nil)["published_route"]; got != (status == "active") {
			t.Errorf("status=%s review route=%v", status, got)
		}
	}
}
