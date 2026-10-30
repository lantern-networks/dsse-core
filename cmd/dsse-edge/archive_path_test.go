package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/archive"
	"github.com/lantern-networks/dsse-core/hotstore"
)

type crossTenantListingArchive struct{ fakeArchive }

func (a *crossTenantListingArchive) List(context.Context, string, int) ([]archive.ObjectInfo, error) {
	return []archive.ObjectInfo{{Key: "hot_events/tenant_other/audit/segment.ndjson.gz"}}, nil
}

func TestArchiveKeyComponentsCannotEscapeTenantPrefix(t *testing.T) {
	for _, value := range []string{"tenant_1", "tenant-prod", "tenant.example", "tenant:region", "audit"} {
		if !validArchivePathComponent(value) {
			t.Fatalf("valid archive component %q was refused", value)
		}
	}
	for _, value := range []string{"", ".", "..", "tenant/other", `tenant\other`, "tenant\nother", "tenant?other"} {
		if validArchivePathComponent(value) {
			t.Fatalf("unsafe archive component %q was accepted", value)
		}
		if safeAdminTenantToken(value) {
			t.Fatalf("unsafe tenant ID %q could be registered", value)
		}
		if n := archiveRetentionBatch(context.Background(), nil, retentionConfig{}, value, "audit", time.Time{}, time.Time{}); n != 0 {
			t.Fatalf("unsafe tenant %q was archived", value)
		}
		if _, err := verifyAuditChain(context.Background(), &fakeArchive{objs: map[string][]byte{}}, value); err == nil {
			t.Fatalf("unsafe tenant %q was listed", value)
		}
		lifecycle := &clickhouseRetentionLifecycle{}
		if err := lifecycle.prepare(context.Background(), value, "audit", time.Time{}, time.Time{}, []hotstore.RetentionRecord{{}}); err == nil {
			t.Fatalf("unsafe tenant %q entered ClickHouse archive journal", value)
		}
	}
	for _, stream := range []string{"", "..", "audit/../other", `audit\other`} {
		if n := archiveRetentionBatch(context.Background(), nil, retentionConfig{}, "tenant_1", stream, time.Time{}, time.Time{}); n != 0 {
			t.Fatalf("unsafe stream %q was archived", stream)
		}
		lifecycle := &clickhouseRetentionLifecycle{}
		if err := lifecycle.prepare(context.Background(), "tenant_1", stream, time.Time{}, time.Time{}, []hotstore.RetentionRecord{{}}); err == nil {
			t.Fatalf("unsafe stream %q entered ClickHouse archive journal", stream)
		}
	}
}

func TestAuditVerifierRejectsListingOutsideTenant(t *testing.T) {
	arc := &crossTenantListingArchive{fakeArchive{objs: map[string][]byte{}}}
	_, err := verifyAuditChain(context.Background(), arc, "tenant_1")
	if err == nil || !strings.Contains(err.Error(), "escaped tenant scope") {
		t.Fatalf("foreign archive listing was not refused: %v", err)
	}
}
