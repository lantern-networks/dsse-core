package main

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/logs"
)

type regionCounterFixture struct {
	hotstore.Store
	count int64
	err   error
	query hotstore.SearchQuery
}

func (s *regionCounterFixture) CountUnknownRegion(ctx context.Context, q hotstore.SearchQuery) (int64, error) {
	s.query = q
	return s.count, s.err
}
func TestAdminRegionCoverageDoesNotInventZero(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	base := hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap())
	for _, kind := range []string{"zero", "positive", "failure", "unsupported"} {
		t.Run(kind, func(t *testing.T) {
			fixture := &regionCounterFixture{Store: base}
			var store hotstore.Store = fixture
			switch kind {
			case "positive":
				fixture.count = 7
			case "failure":
				fixture.err = errors.New("private-count-error")
			case "unsupported":
				store = base
			}
			result, err := adminLogSearch(store, "tenant_own", "access", url.Values{"edge_region_id": {"region-a"}, "decision": {"deny"}, "from": {"2026-09-01T00:00:00Z"}, "q": {"test"}, "tenant_id": {"tenant_foreign"}})
			if err != nil {
				t.Fatal(err)
			}
			coverage := result.regionCoverage
			if coverage == nil {
				t.Fatal("missing region coverage")
			}
			if kind == "failure" || kind == "unsupported" {
				if coverage.Status != "unavailable" || coverage.UnknownRegionCount != nil {
					t.Fatal("unavailable count presented as zero")
				}
			} else {
				if coverage.Status != "available" || coverage.UnknownRegionCount == nil || *coverage.UnknownRegionCount != fixture.count {
					t.Fatal("wrong count")
				}
				if fixture.query.TenantID != "tenant_own" || fixture.query.Stream != "access" || fixture.query.Filters["decision"] != "deny" || fixture.query.From == nil || fixture.query.Text != "test" {
					t.Fatal("coverage lost query scope")
				}
			}
		})
	}
	unfiltered, err := adminLogSearch(base, "tenant_own", "access", url.Values{})
	if err != nil || unfiltered.regionCoverage != nil {
		t.Fatal("unfiltered search unexpectedly counts unknown regions")
	}
}

func TestRegionalPreviewReportsUnknownCountAvailability(t *testing.T) {
	writer, err := logs.NewWriter(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	fixture := &regionCounterFixture{Store: hotstore.NewJSONLStore(writer, adminLogStreamFilenameMap()), count: 3}
	handler := newServerWithConfig(serverConfig{Evaluator: testEvaluator(), Writer: writer, HotStore: fixture})
	for _, fail := range []bool{false, true} {
		if fail {
			fixture.err = errors.New("private-db-count-failure")
		}
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/admin/logs/access/export?edge_region_id=region-a", nil)
		handler.ServeHTTP(rec, req)
		if rec.Code != 200 {
			t.Fatalf("preview status=%d", rec.Code)
		}
		if fail {
			if rec.Header().Get("X-DSSE-Region-Coverage") != "unavailable" || rec.Header().Get("X-DSSE-Unknown-Region-Count") != "" {
				t.Fatal("failed count represented as zero")
			}
		} else {
			if rec.Header().Get("X-DSSE-Unknown-Region-Count") != "3" {
				t.Fatal("preview omitted count")
			}
		}
		if rec.Header().Get("X-DSSE-Region-Notice") == "" {
			t.Fatal("preview omitted exclusion notice")
		}
	}
}
