package hotstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lantern-networks/dsse-core/durablefile"
	"strings"
	"sync"
	"time"
)

// batching.go — how records reach the OLAP tier without the writer waiting for it.
//
// ★ TWO DEFECTS, ONE SHAPE (2026-08-12, measured on the reference lab).
//
// 1. ONE INSERT PER RECORD. Every INSERT creates a PART, and parts must be merged. Three hours on a lab
//    holding 2.4M rows — a trivial volume — produced 12,428 inserts averaging ONE row each and 10,158 merges
//    costing 3,604 seconds. An hour of CPU spent merging per three hours of a nearly idle system, ending with
//    ClickHouse at 429% CPU and its own ingest timing out.
//
// 2. THE WRITER WAITED FOR IT. The mirror ran INSIDE the append hook, synchronously, with a 30-second timeout
//    — so every audit append was bounded by ClickHouse's latency, and when ClickHouse got slow the control
//    plane's ingest endpoint got slow with it. An analytics mirror was on the critical path of recording.
//
// So records go into a bounded queue and a single worker writes them in batches. The append hook returns
// immediately, and the OLAP tier receives the shape it is built for.
//
// ★ WHAT THIS DOES NOT CHANGE: the mirror was ALREADY best-effort. The durable record is the local jsonl the
// writer appends first; the hook returned nil on failure and reported through a monitor. Queueing widens the
// window in which a crash loses records that the jsonl still holds, and does not create it. The window is
// bounded by FlushInterval, and a full queue is reported rather than silently dropped — an OLAP tier that is
// quietly missing events is the thing this whole subsystem exists to avoid.

// BatchIngestor accepts records and writes them in batches.
type BatchIngestor struct {
	store    *ClickHouseStore
	queue    chan IngestRecord
	maxRows  int
	interval time.Duration

	onFlushError func(error, int)
	onDrop       func(IngestRecord)
	onFlush      func(rows int)

	spoolPath string

	stop     chan struct{}
	stopped  sync.WaitGroup
	stopOnce sync.Once
}

// BatchIngestorConfig bounds everything this can consume.
type BatchIngestorConfig struct {
	// QueueSize is how many records may wait. Beyond it, records are DROPPED and reported: blocking here would
	// put ClickHouse back on the critical path of recording, which is the defect being removed.
	QueueSize int
	// MaxRows is the largest batch written as one INSERT.
	MaxRows int
	// FlushInterval is the longest a record waits before being written. It is also the loss window on a crash.
	FlushInterval time.Duration

	OnFlushError func(err error, rows int)
	OnDrop       func(record IngestRecord)
	OnFlush      func(rows int)

	// SpoolPath is where a batch that could not be written waits ACROSS A RESTART.
	//
	// ★ THE BACKLOG WAS MEMORY ONLY (2026-08-12, twelfth review). Reporting how many rows were still held on
	// shutdown was an improvement in visibility and none at all in durability: the process exits, the rows are
	// gone from the hot store forever, and nothing replays the canonical jsonl. Empty keeps the old behaviour
	// and says so at startup.
	SpoolPath string
}

// DefaultBatchIngestorConfig is sized from what the lab actually produces, measured twice.
//
// ★ ONE SECOND WAS NOT ENOUGH, AND THE MEASUREMENT SAID SO (2026-08-12). Records arrive at ~0.74/second, so a
// one-second window collected ONE — 1.1 rows per insert, which is the defect with extra machinery around it.
// The window has to be long enough to actually collect at the rate records arrive, and at this rate that is
// tens of seconds:
//
//	 1s window  -> ~1 row/insert   -> ~2,400 parts/hour   (measured)
//	15s window  -> ~11 rows/insert -> ~240 parts/hour
//
// Fifteen seconds is what it costs: the Console's log views lag by up to that much, and a crash loses up to
// that much of the MIRROR — never of the record, which the local jsonl holds first and canonically. Both are
// cheap next to an OLAP tier that spends a third of a core merging parts it should never have been given.
//
// MaxRows is what bounds it under real fleet load, where the window will close on the count long before the
// clock.
func DefaultBatchIngestorConfig() BatchIngestorConfig {
	return BatchIngestorConfig{QueueSize: 20000, MaxRows: 1000, FlushInterval: 15 * time.Second}
}

const (
	// flushAttempts is how many times one batch is offered IN LINE before it moves aside. Three covers a merge
	// pause; anything longer must not stall the records behind it.
	flushAttempts     = 3
	flushRetryBackoff = 250 * time.Millisecond
	// retryBacklogBatches is how many failed batches wait for a later attempt.
	//
	// ★ 750ms OF RETRIES IS NOT AN OUTAGE BUDGET (2026-08-12, tenth review). Three quick attempts and then
	// `batch[:0]` meant any interruption longer than a second — a ClickHouse restart, a merge storm, the exact
	// conditions this whole change exists for — lost every row in flight permanently. Worse, the next
	// successful flush reported ok, so the gap looked healthy.
	//
	// Failed batches move to a bounded backlog and are re-offered on later flushes, newest work first so a
	// backlog cannot starve live traffic. When the backlog is full the OLDEST is dropped, loudly and with its
	// row count: the canonical jsonl still holds those records, and pretending otherwise is what this is for.
	retryBacklogBatches = 64
)

func NewBatchIngestor(store *ClickHouseStore, cfg BatchIngestorConfig) *BatchIngestor {
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = 20000
	}
	if cfg.MaxRows <= 0 {
		cfg.MaxRows = 1000
	}
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = time.Second
	}
	b := &BatchIngestor{
		store:        store,
		queue:        make(chan IngestRecord, cfg.QueueSize),
		maxRows:      cfg.MaxRows,
		interval:     cfg.FlushInterval,
		onFlushError: cfg.OnFlushError,
		onDrop:       cfg.OnDrop,
		onFlush:      cfg.OnFlush,
		spoolPath:    strings.TrimSpace(cfg.SpoolPath),
		stop:         make(chan struct{}),
	}
	b.stopped.Add(1)
	go b.run()
	return b
}

// spoolBacklog persists what could not be written, so a restart resumes instead of forgetting.
// spoolBacklog persists what could not be written. ★ EVERY FAILURE IS REPORTED (2026-08-12, thirteenth
// review): mkdir, write and rename errors were all discarded, so a full disk or a wrong permission left a
// deployment that had CONFIGURED a durable spool and had none — the exact shape of "the durability claim the
// deployment does not provide" this file was written to remove.
//
// fsync on the file AND on its directory, because a rename is only durable once the directory entry is. A
// spool that survives a clean shutdown and not a power cut is a spool for the case that was never the problem.
func (b *BatchIngestor) spoolBacklog(backlog [][]IngestRecord) error {
	if b.spoolPath == "" {
		return nil
	}
	if len(backlog) == 0 {
		if err := os.Remove(b.spoolPath); err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("clear the hot-store spool: %w", err)
			}
			return nil
		}
		// ★ THE UNLINK IS A DIRECTORY WRITE TOO (2026-08-12, fourteenth review). Without this, a power cut
		// after the backlog drained can bring the spool back, and the restart re-ingests rows the hot store
		// already has. They are de-duplicated by token, so the damage is work rather than wrong data — but a
		// spool that reappears is also a spool that never appears to shrink, and that is what an operator
		// watching the backlog depth would be reading.
		return durablefile.SyncDir(filepath.Dir(b.spoolPath))
	}
	dir := filepath.Dir(b.spoolPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create the hot-store spool directory: %w", err)
	}
	raw, err := json.Marshal(backlog)
	if err != nil {
		return fmt.Errorf("render the hot-store spool: %w", err)
	}
	// ★ THROUGH THE SHARED PACKAGE (2026-08-13, thirtieth review #20). This was a hand-written
	// open-write-fsync-close-rename-fsyncdir, one of the four copies durablefile was extracted from, and the
	// migration had stopped before reaching it. The guarantees are unchanged and now have one implementation:
	// the bytes are flushed before the rename, and the rename is made durable by the platform's own means —
	// which on Windows is the replace itself, because there is no directory to flush there.
	if werr := durablefile.Write(b.spoolPath, raw, 0o600); werr != nil {
		return fmt.Errorf("write the hot-store spool: %w", werr)
	}
	return nil
}

// syncSpoolDir persists a directory entry so the rename (or unlink) above survives a power cut, and REPORTS
// when it cannot. Per-platform, because HOW a rename is made durable is: see spool_dirsync_unix.go and
// spool_dirsync_windows.go, and agentupdate's syncDir, which is the same split for the same reason.

// persistBacklog spools and REPORTS. Called synchronously wherever the backlog changes.
func (b *BatchIngestor) persistBacklog(backlog [][]IngestRecord) {
	if err := b.spoolBacklog(backlog); err != nil && b.onFlushError != nil {
		rows := 0
		for _, held := range backlog {
			rows += len(held)
		}
		b.onFlushError(fmt.Errorf("the hot-store backlog could NOT be spooled (%w): %d row(s) are held in memory "+
			"only and a restart will lose them", err, rows), rows)
	}
}

// loadSpooledBacklog reads what a previous process could not write.
func (b *BatchIngestor) loadSpooledBacklog() [][]IngestRecord {
	if b.spoolPath == "" {
		return nil
	}
	raw, err := os.ReadFile(b.spoolPath)
	if err != nil {
		// ★ A READ ERROR IS NOT AN EMPTY SPOOL (2026-08-13, twenty-ninth review). This returned nil silently,
		// and the next spoolBacklog then OVERWRITES the file — so rows this subsystem had accepted as durably
		// held vanished with no log line and no counter, which is the one thing the spool exists to prevent.
		// The unmarshal error beside it was already reported; the read error was not.
		if !os.IsNotExist(err) && b.onFlushError != nil {
			b.onFlushError(fmt.Errorf("the hot-store spool could not be READ (%w): rows held for a later flush "+
				"cannot be recovered, and the next write will replace the file", err), 0)
		}
		return nil
	}
	var backlog [][]IngestRecord
	if json.Unmarshal(raw, &backlog) != nil {
		// Unreadable: removed rather than left to block every later write. One lost spool, said out loud.
		_ = os.Remove(b.spoolPath)
		if b.onFlushError != nil {
			b.onFlushError(errors.New("the hot-store spool could not be read and was discarded"), 0)
		}
		return nil
	}
	return backlog
}

// Add queues a record. It never blocks: a full queue drops the record and says so.
func (b *BatchIngestor) Add(record IngestRecord) {
	if b == nil {
		return
	}
	select {
	case b.queue <- record:
	default:
		if b.onDrop != nil {
			b.onDrop(record)
		}
	}
}

// Close flushes what is queued and stops the worker. Safe to call twice.
func (b *BatchIngestor) Close() error {
	if b == nil {
		return nil
	}
	b.stopOnce.Do(func() { close(b.stop) })
	b.stopped.Wait()
	return nil
}

func (b *BatchIngestor) run() {
	defer b.stopped.Done()
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()
	batch := make([]IngestRecord, 0, b.maxRows)
	// Anything a previous process could not write. Resumed rather than forgotten.
	backlog := b.loadSpooledBacklog()
	if len(backlog) > 0 && b.onFlushError != nil {
		rows := 0
		for _, held := range backlog {
			rows += len(held)
		}
		b.onFlushError(fmt.Errorf("resuming %d batch(es) / %d row(s) a previous process could not write",
			len(backlog), rows), rows)
	}

	// ★ A FAILED BATCH IS RETRIED, AND IT USED NOT TO BE (2026-08-12, ninth review). The first version reported
	// the error and then cleared the buffer — so a momentary ClickHouse hiccup lost every row in flight,
	// permanently, and the very next successful flush reset the monitor to "ok" so the gap looked healthy. The
	// comment beside it even said the batch would be retried as itself; it was not. A comment describing
	// behaviour the code does not have is worse than no comment.
	//
	// Bounded, because the alternative to dropping is not "retry forever": that would stall every later record
	// behind a batch that cannot be written. After the attempts are spent the rows ARE dropped — loudly, with
	// the count — and the canonical jsonl still holds them.
	flush := func() {
		if len(batch) == 0 {
			return
		}
		var err error
		for attempt := 1; attempt <= flushAttempts; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err = b.store.IngestBatch(ctx, batch)
			cancel()
			if err == nil {
				break
			}
			if attempt < flushAttempts {
				// The SAME batch, so its content-derived deduplication token is the same and a partial success
				// cannot become a duplicate.
				time.Sleep(time.Duration(attempt) * flushRetryBackoff)
			}
		}
		if err == nil {
			if b.onFlush != nil {
				b.onFlush(len(batch))
			}
			batch = batch[:0]
			return
		}
		if b.onFlushError != nil {
			b.onFlushError(err, len(batch))
		}
		// Aside, not away: re-offered on a later flush rather than discarded after three quick attempts.
		held := make([]IngestRecord, len(batch))
		copy(held, batch)
		backlog = append(backlog, held)
		for len(backlog) > retryBacklogBatches {
			dropped := backlog[0]
			backlog = backlog[1:]
			if b.onDrop != nil {
				for _, record := range dropped {
					b.onDrop(record)
				}
			}
		}
		// ★ SYNCHRONOUSLY, AND AFTER THE PRUNE (2026-08-12, thirteenth review). This was a `defer` taken before
		// the prune loop: it captured the slice header as it was THEN, so the spool could be written with
		// entries the prune had already dropped — and a defer is the one thing a crash never runs, which is the
		// case the spool exists for.
		b.persistBacklog(backlog)
		batch = batch[:0]
	}

	// drainBacklog re-offers what an earlier flush could not write. ONE batch per pass: a backlog that seized
	// the worker would starve the live records the queue is filling behind it.
	//
	// ★ A BACKLOG THAT NOBODY IS TOLD ABOUT IS A GAP THAT LOOKS HEALTHY (2026-08-12, eleventh review). A failed
	// re-offer used to return silently, so one successful LIVE batch afterwards reported ok and the health view
	// said the store was fine while rows were still unwritten. Every failed re-offer is reported, and the depth
	// is carried with it: "still 3 batches behind" is the sentence that was missing.
	drainBacklog := func() {
		if len(backlog) == 0 {
			return
		}
		oldest := backlog[0]
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := b.store.IngestBatch(ctx, oldest)
		cancel()
		if err != nil {
			if b.onFlushError != nil {
				b.onFlushError(fmt.Errorf("%d batch(es) still waiting to reach the hot store: %w", len(backlog),
					err), len(oldest))
			}
			return // it keeps its place
		}
		backlog = backlog[1:]
		b.persistBacklog(backlog)
		// ★ ONE BATCH LANDING IS NOT RECOVERY (2026-08-12, thirteenth review). Reporting a plain success here
		// let a monitor go green with sixty-three batches still owed, because the last success was newer than
		// the last failure. A drain that is still behind reports the DEPTH, and only an empty backlog is
		// reported as a success.
		if len(backlog) > 0 {
			if b.onFlushError != nil {
				b.onFlushError(fmt.Errorf("%d batch(es) still waiting to reach the hot store", len(backlog)),
					len(oldest))
			}
			return
		}
		if b.onFlush != nil {
			b.onFlush(len(oldest))
		}
	}

	for {
		select {
		case <-b.stop:
			// Drain what is already queued before going, so a clean shutdown does not lose the last second.
			for {
				select {
				case record := <-b.queue:
					batch = append(batch, record)
					if len(batch) >= b.maxRows {
						flush()
					}
					continue
				default:
				}
				break
			}
			flush()
			for len(backlog) > 0 {
				before := len(backlog)
				drainBacklog()
				if len(backlog) == before {
					break // still failing
				}
			}
			// ★ AND WHAT IS STILL HELD IS SAID OUT LOUD ON THE WAY OUT. The backlog is in memory, so a
			// shutdown that leaves it holding rows leaves the hot store permanently short of them — the
			// canonical jsonl has them, and nothing replays it. Somebody has to be told which records those
			// were, and the alternative (a durable spool with a cursor) is a design, not a line.
			b.persistBacklog(backlog)
			if len(backlog) > 0 {
				rows := 0
				for _, held := range backlog {
					rows += len(held)
				}
				if b.onFlushError != nil {
					where := "they are in the canonical jsonl and nothing replays it"
					if b.spoolPath != "" {
						where = "held in " + b.spoolPath + " and resumed on the next start"
					}
					b.onFlushError(fmt.Errorf("shutting down with %d batch(es) / %d row(s) not yet written to the "+
						"hot store: %s", len(backlog), rows, where), rows)
				}
			}
			return
		case record := <-b.queue:
			batch = append(batch, record)
			if len(batch) >= b.maxRows {
				flush()
			}
		case <-ticker.C:
			flush()
			drainBacklog()
		}
	}
}
