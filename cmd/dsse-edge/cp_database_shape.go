package main

import (
	"context"
	"database/sql"
	"sync"
	"time"
)

// cp_database_shape.go — how many replicas are streaming from this node's database.
//
// ★★★ A CONTROL PLANE INCLUDES ITS DATABASE, so "is the authority redundant" is a question about the
// database and not about how many control-plane processes are running. Two processes in front of one
// single-node Postgres are one control plane with two front ends — and the leadership advisory lock lives in
// that same database, so losing it loses leadership as well as the state.
//
// ★ AND AUTOMATIC PROMOTION IS WHAT MAKES IT FAILOVER. A replica that a person has to promote is a backup:
// it survives the data and not the outage. What this reports is only the first half — that the state EXISTS
// somewhere else — because whether promotion happens by itself is a property of what manages the cluster
// (Patroni and its store), which this process cannot see from inside a connection.
//
// Reported rather than asserted: the node says what it can see, and the deployment's own checks decide what
// that has to be.
type cpDatabaseShape struct {
	mu       sync.Mutex
	at       time.Time
	replicas int
	known    bool
}

var cpDatabaseShapeCache = &cpDatabaseShape{}

// cpDatabaseShapeRefresh bounds how often the health endpoint asks the database. A health check is polled by
// load balancers; making it a database round-trip every time turns a liveness probe into load.
const cpDatabaseShapeRefresh = 10 * time.Second

// streamingReplicas reports how many replicas are streaming from this node's database, and whether the answer
// is known at all. A standby answers zero — pg_stat_replication is the PRIMARY's view — so a caller reading
// this from a node that is not the leader learns nothing, which is why the leader is the one to ask.
func streamingReplicas(db *sql.DB) (int, bool) {
	if db == nil {
		return 0, false
	}
	c := cpDatabaseShapeCache
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.known && time.Since(c.at) < cpDatabaseShapeRefresh {
		return c.replicas, true
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	// ★★★ A ROW WHOSE COLUMNS ARE HIDDEN IS NOT AN ABSENT ROW (2026-08-24, measured). pg_stat_replication is
	// visible to everyone, but its columns are NULL for a role without pg_read_all_stats — so a plain
	// "count(*) WHERE state = 'streaming'" answers ZERO on a cluster that HAS a streaming replica, and this
	// check would have reported a redundant authority as not redundant. Counting both tells the difference:
	// rows present with no readable state means this role cannot see, which is not the same as none.
	var total, streaming int
	if err := db.QueryRowContext(ctx,
		"SELECT count(*), count(*) FILTER (WHERE state = 'streaming') FROM pg_stat_replication").
		Scan(&total, &streaming); err != nil {
		// Not known rather than zero. "I could not ask" and "there are none" are different answers, and
		// reporting the second for the first is how a deployment gets told its state is redundant when
		// nothing checked.
		return 0, false
	}
	if streaming == 0 && total > 0 {
		// Rows are there and their state is not readable: the answer is unknown, and saying zero would be
		// asserting the opposite of what is probably true.
		return 0, false
	}
	c.replicas, c.at, c.known = streaming, time.Now(), true
	return streaming, true
}
