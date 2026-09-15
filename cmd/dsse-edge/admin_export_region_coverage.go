package main

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
)

// All strings here are fixed ASCII, so the manifest is a valid gzip Comment.
// The job's existing Filters/From/To hold the full search scope.
type adminExportRegionCoverage struct {
	Schema              string `json:"schema"`
	RegionFilterApplied bool   `json:"region_filter_applied"`
	Notice              string `json:"notice"`
	Status              string `json:"status"`
	UnknownRegionCount  *int64 `json:"unknown_region_count"`
	CheckedAt           string `json:"checked_at"`
	SnapshotConsistent  bool   `json:"snapshot_consistent"`
}

func exportRegionCoverage(ctx context.Context, store hotstore.Store, query hotstore.SearchQuery) *adminExportRegionCoverage {
	coverage := countAdminLogRegionCoverage(ctx, store, query)
	if coverage == nil {
		return nil
	}
	return &adminExportRegionCoverage{
		Schema: "dsse.export-region-coverage.v1", RegionFilterApplied: true,
		Notice: "Records without a region are excluded. Count is a separate live query, not an export snapshot.",
		Status: coverage.Status, UnknownRegionCount: coverage.UnknownRegionCount,
		CheckedAt: time.Now().UTC().Format(time.RFC3339), SnapshotConsistent: false,
	}
}

type exportCommentObjectStore struct {
	adminExportObjectStore
	coverage *adminExportRegionCoverage
}

func (s exportCommentObjectStore) WriteGzipJSONLStream(filename string, next func() (map[string]any, bool, error)) (string, error) {
	writer, ok := s.adminExportObjectStore.(interface {
		WriteGzipJSONLStreamWithComment(string, string, func() (map[string]any, bool, error)) (string, error)
	})
	if !ok {
		return "", fmt.Errorf("export object store cannot preserve regional coverage")
	}
	comment, err := json.Marshal(s.coverage)
	if err != nil {
		return "", err
	}
	return writer.WriteGzipJSONLStreamWithComment(filename, string(comment), next)
}
