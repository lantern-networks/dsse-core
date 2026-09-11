package main

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/model"
)

// ★★★ THE OVERVIEW'S DECISION TILES ASKED THE NODE THEY WERE OPENED ON, AND THE CONSOLE IS SERVED BY THE ONE
// NODE THAT DECIDES NOTHING (2026-09-05, measured on a one-machine deployment that had been steering a real Mac
// all morning). The access-trend summary was built from decisionStore — a bounded in-memory ring of the
// decisions THIS process made. On a control plane that ring is structurally empty, so the screen said
//
//	Decisions · 24h   0        Deny rate · 24h   0.0%   0 denied
//
// while the edge on the same machine held 42 in its ring and the hot store on the same machine held 240 rows of
// this organization's access stream. Worse than a dash: a confident zero, with a coverage block that said
// decisions:0 retained:0 truncated:false — "we looked, and nothing happened" — about a deployment that was
// enforcing policy on every flow the device made.
//
// The report right above it in this file already had the answer: the AI-usage report reads the SAME access
// stream through the hot store, so it is fleet-wide and survives a restart. The DLP-findings route states the
// rule in as many words (admin_dlp_routes.go): serve from the aggregation hot store, fall back to the in-memory
// store ONLY when no hot store is wired (a standalone edge), and treat an empty non-error result as
// authoritative rather than falling back to a second opinion.
//
// So this is the same rule applied to the same stream. It also fixes the edge's own answer, which was a single
// node's ring where the operator reads a whole deployment's number.
const accessTrendsHotStoreRowCap = 100000

// accessDecisionFromRow decodes a hot-store access row back into the decision that was written. Every backend
// returns the original record shape (the ClickHouse store keeps the whole JSON in `raw` and hands that back), so
// this is a re-unmarshal rather than a field-by-field reconstruction — the same move inspectionEventFromRow
// makes for the inspection stream. A row without an id is not a decision and is dropped rather than counted as
// one with empty fields.
func accessDecisionFromRow(row map[string]any) (model.AccessDecision, bool) {
	b, err := json.Marshal(row)
	if err != nil {
		return model.AccessDecision{}, false
	}
	var dec model.AccessDecision
	if err := json.Unmarshal(b, &dec); err != nil || strings.TrimSpace(dec.ID) == "" {
		return model.AccessDecision{}, false
	}
	return dec, true
}

// accessTrendsFromHotStore reads a tenant's access decisions for [from, to] out of the hot store. ok is false
// when no hot store is wired or the read failed — only then may the caller fall back to this node's ring; an
// empty result with ok true means the deployment recorded nothing in the window, which is an answer.
//
// oldestRead is the earliest decision actually read, which is what tells a truncated window where it really
// begins; oldestHeld is the earliest this tenant has in the stream at all, ignoring the window, so "the first
// half is empty" can be told apart from "we no longer hold the first half".
func accessTrendsFromHotStore(ctx context.Context, store hotstore.Store, tenantID string, from, to time.Time) (decisions []model.AccessDecision, oldestRead, oldestHeld time.Time, truncated, ok bool) {
	if store == nil || strings.TrimSpace(tenantID) == "" {
		return nil, time.Time{}, time.Time{}, false, false
	}
	rows := 0
	export, err := store.ExportRows(ctx, hotstore.SearchQuery{
		TenantID:             tenantID,
		Stream:               "access",
		From:                 &from,
		To:                   &to,
		Limit:                accessTrendsHotStoreRowCap,
		IncludeOldestMatched: true,
	}, func(row map[string]any) error {
		rows++
		dec, decoded := accessDecisionFromRow(row)
		if !decoded {
			return nil
		}
		decisions = append(decisions, dec)
		// By comparison, not by trusting the backends' newest-first ordering: this value is what the operator
		// is shown as the start of the window, so it must not depend on an ORDER BY the interface does not
		// promise.
		if t, err := time.Parse(time.RFC3339, strings.TrimSpace(dec.Timestamp)); err == nil && (oldestRead.IsZero() || t.Before(oldestRead)) {
			oldestRead = t.UTC()
		}
		return nil
	})
	if err != nil {
		return nil, time.Time{}, time.Time{}, false, false
	}
	return decisions, oldestRead, export.OldestMatchedAt, rows >= accessTrendsHotStoreRowCap, true
}
