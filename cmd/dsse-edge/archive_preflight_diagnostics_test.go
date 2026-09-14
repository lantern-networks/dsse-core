package main

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/archive"
)

type archiveListFault struct {
	fakeArchive
	listErr error
}

func (a *archiveListFault) List(ctx context.Context, prefix string, limit int) ([]archive.ObjectInfo, error) {
	objects, _ := a.fakeArchive.List(ctx, prefix, limit)
	return objects, a.listErr
}

func TestArchivePreflightDistinguishesListingFailureFromCountMismatch(t *testing.T) {
	previous := log.Writer()
	defer log.SetOutput(previous)
	for _, kind := range []string{"listing_failure", "count_mismatch"} {
		t.Run(kind, func(t *testing.T) {
			var captured bytes.Buffer
			log.SetOutput(&captured)
			chain := newAuditChainStore(nil)
			if err := chain.Commit("tenant_test", 0, hashObjectBytes([]byte("saved"))); err != nil {
				t.Fatal(err)
			}
			arc := &archiveListFault{fakeArchive: fakeArchive{objs: map[string][]byte{}}}
			if kind == "listing_failure" {
				arc.listErr = errors.New("injected listing outage")
			}
			// A nil database makes any progression beyond preflight an observable failure.
			archiveThenPruneStream(context.Background(), nil, retentionConfig{archive: arc, auditChain: chain}, "tenant_test", "audit", time.Now(), time.Now())
			message := captured.String()
			if strings.Contains(message, "<nil>") || !strings.Contains(message, `tenant="tenant_test"`) {
				t.Fatalf("ambiguous diagnostic: %s", message)
			}
			if kind == "listing_failure" {
				if !strings.Contains(message, "archive listing failed") || !strings.Contains(message, "injected listing outage") || strings.Contains(message, "count mismatch") {
					t.Fatalf("listing failure misclassified: %s", message)
				}
			} else if !strings.Contains(message, "archive count mismatch expected=1 actual=0") || strings.Contains(message, "listing failed") {
				t.Fatalf("mismatch misclassified: %s", message)
			}
			seq, _, err := chain.Next("tenant_test")
			if err != nil || seq != 1 {
				t.Fatal("preflight changed saved chain position")
			}
		})
	}
}
