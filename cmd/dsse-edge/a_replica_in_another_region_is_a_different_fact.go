package main

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"time"
)

// ★★★ COUNTING REPLICAS CANNOT TELL YOU WHETHER A REGION CAN BE LOST (2026-08-27).
//
// The deployment already reports how many replicas stream from its primary, and that check passed on a
// deployment whose second region had no database at all — because the first region's own pair answered it. A
// replica beside the primary survives a machine; only a replica somewhere else survives the site.
//
// So the names are reported, not only the count. Patroni's member name reaches the primary as
// pg_stat_replication.application_name, and every region's members are named after their region, which makes
// "is any of these somewhere else" a question the deployment can answer about itself.
//
// ★ NAMES, NOT ADDRESSES. client_addr is whatever the network says today — behind NAT, a tunnel, or a
// front door it says something that is true and useless. The member name is what the member calls itself in
// the cluster it joined.

// streamingReplicaNames reports the member names streaming from this node's database, and whether the answer is
// known at all. Absent is not empty: a role that cannot read the view, and a primary with no replicas, are
// different answers and only one of them is a problem.
func streamingReplicaNames(db *sql.DB) ([]string, bool) {
	if db == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	rows, err := db.QueryContext(ctx,
		"SELECT coalesce(application_name, '') FROM pg_stat_replication WHERE state = 'streaming'")
	if err != nil {
		return nil, false
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, false
		}
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}
	if rows.Err() != nil {
		return nil, false
	}
	sort.Strings(names)
	return names, true
}

// replicaOutsideThisRegion reports whether any streaming replica belongs to a region other than this one.
//
// ★ THE COMPARISON IS ON THE REGION THIS NODE BELONGS TO, not on a list of regions somebody configured. A node
// knows its own region; asking it to also know every other region's naming convention would make this answer
// depend on configuration being right, which is the thing being checked.
func replicaOutsideThisRegion(names []string, thisRegion string) (string, bool) {
	region := strings.ToLower(strings.TrimSpace(thisRegion))
	for _, n := range names {
		lower := strings.ToLower(n)
		if region == "" || !strings.HasPrefix(lower, region+"-") {
			// A member that does not carry this region's name is either elsewhere, or from a deployment that
			// predates per-region member names. Both are worth saying out loud rather than counting as proof.
			if region != "" {
				return n, true
			}
		}
	}
	return "", false
}
