package edgeplane

import (
	"context"
	"errors"
	"testing"

	"github.com/lantern-networks/dsse-core/appcatalog"
)

type failingRouteCatalog struct{ appcatalog.RuntimeStore }

func (failingRouteCatalog) ListAll(context.Context, string, appcatalog.ListAllOptions) ([]appcatalog.Entry, error) {
	return nil, errors.New("injected catalog read failure")
}

func TestRouteProfilesWithPublishedCatalogReadFailureDoesNotRestoreDisabledBase(t *testing.T) {
	base := map[string]ApplicationRouteProfile{"wiki": {Destination: "startup.example.test"}}
	routes, err := RouteProfilesWithPublishedCatalog(context.Background(), base, failingRouteCatalog{}, "tenant_a")
	if err == nil || routes != nil {
		t.Fatalf("catalog read failure was hidden: routes=%#v err=%v", routes, err)
	}
}
