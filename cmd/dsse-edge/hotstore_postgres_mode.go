package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/logs"
	migrationstore "github.com/lantern-networks/dsse-core/migrations"

	_ "github.com/lib/pq"
)

type edgeHotStoreConfig struct {
	Mode          string
	DSN           string
	MigrationDir  string
	RunMigrations bool
	Writer        *logs.Writer
	MirrorMonitor *hotStoreAppendMirrorMonitor
	// ClickHouse hot-OLAP tier (mode=clickhouse). Reached over the HTTP interface — no Go client dependency
	// (event_log_design.md/S3).
	ClickHouseEndpoint string
	ClickHouseUser     string
	ClickHousePassword string
	ClickHouseDatabase string
	ClickHouseTable    string
	// BacklogSpoolPath is where batches that could not be written wait ACROSS a restart. Empty keeps them in
	// memory only, which is what made a shutdown lose them permanently.
	BacklogSpoolPath string
}

type hotStoreAppendMirrorHealth struct {
	Status        string           `json:"status"`
	Reasons       []string         `json:"reasons"`
	CheckedAt     string           `json:"checked_at"`
	Stats         map[string]int64 `json:"stats"`
	LastSuccessAt string           `json:"last_success_at,omitempty"`
	LastFailureAt string           `json:"last_failure_at,omitempty"`
	LastError     string           `json:"last_error,omitempty"`
	LastStream    string           `json:"last_stream,omitempty"`
	LastFilename  string           `json:"last_filename,omitempty"`
}

type hotStoreAppendMirrorMonitor struct {
	mu             sync.RWMutex
	mirrored       int64
	decodeFailures int64
	ingestFailures int64
	lastSuccessAt  time.Time
	lastFailureAt  time.Time
	lastError      string
	lastStream     string
	lastFilename   string
}

func newHotStoreAppendMirrorMonitor() *hotStoreAppendMirrorMonitor {
	return &hotStoreAppendMirrorMonitor{}
}

func (monitor *hotStoreAppendMirrorMonitor) RecordSuccess(stream, filename string, now time.Time) {
	if monitor == nil {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	monitor.mirrored++
	monitor.lastSuccessAt = now.UTC()
	monitor.lastStream = strings.TrimSpace(stream)
	monitor.lastFilename = strings.TrimSpace(filename)
}

func (monitor *hotStoreAppendMirrorMonitor) RecordDecodeFailure(filename string, err error, now time.Time) {
	monitor.recordFailure("", filename, "decode_failed", err, now)
}

func (monitor *hotStoreAppendMirrorMonitor) RecordIngestFailure(stream, filename string, err error, now time.Time) {
	monitor.recordFailure(stream, filename, "ingest_failed", err, now)
}

func (monitor *hotStoreAppendMirrorMonitor) recordFailure(stream, filename, code string, err error, now time.Time) {
	if monitor == nil {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	message := strings.TrimSpace(code)
	if err != nil {
		message = strings.TrimSpace(message + ": " + err.Error())
	}
	monitor.mu.Lock()
	defer monitor.mu.Unlock()
	if code == "decode_failed" {
		monitor.decodeFailures++
	} else {
		monitor.ingestFailures++
	}
	monitor.lastFailureAt = now.UTC()
	monitor.lastError = message
	monitor.lastStream = strings.TrimSpace(stream)
	monitor.lastFilename = strings.TrimSpace(filename)
}

func (monitor *hotStoreAppendMirrorMonitor) Health(now time.Time) hotStoreAppendMirrorHealth {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	health := hotStoreAppendMirrorHealth{
		Status:    "unconfigured",
		Reasons:   []string{"hot_store_mirror_unconfigured"},
		CheckedAt: now.UTC().Format(time.RFC3339),
		Stats: map[string]int64{
			"mirrored":        0,
			"decode_failures": 0,
			"ingest_failures": 0,
		},
	}
	if monitor == nil {
		return health
	}
	monitor.mu.RLock()
	defer monitor.mu.RUnlock()
	health.Status = "ok"
	health.Reasons = []string{}
	health.Stats["mirrored"] = monitor.mirrored
	health.Stats["decode_failures"] = monitor.decodeFailures
	health.Stats["ingest_failures"] = monitor.ingestFailures
	if !monitor.lastSuccessAt.IsZero() {
		health.LastSuccessAt = monitor.lastSuccessAt.UTC().Format(time.RFC3339)
	}
	if !monitor.lastFailureAt.IsZero() {
		health.LastFailureAt = monitor.lastFailureAt.UTC().Format(time.RFC3339)
		health.LastError = monitor.lastError
		if monitor.lastSuccessAt.IsZero() || monitor.lastFailureAt.After(monitor.lastSuccessAt) {
			health.Status = "degraded"
			health.Reasons = append(health.Reasons, "latest_mirror_attempt_failed")
		}
	}
	health.LastStream = monitor.lastStream
	health.LastFilename = monitor.lastFilename
	return health
}

func setupEdgeHotStore(ctx context.Context, config edgeHotStoreConfig) (hotstore.Store, func() error, error) {
	mode := strings.TrimSpace(strings.ToLower(config.Mode))
	if mode == "" {
		mode = "jsonl"
	}
	switch storeBackend(mode) {
	case "jsonl":
		if config.Writer == nil {
			return nil, nil, fmt.Errorf("hot store writer is required")
		}
		return hotstore.NewJSONLStore(config.Writer, adminLogStreamFilenameMap()), func() error { return nil }, nil
	case "postgres":
		if config.Writer == nil {
			return nil, nil, fmt.Errorf("hot store writer is required")
		}
		dsn := strings.TrimSpace(config.DSN)
		if dsn == "" {
			return nil, nil, fmt.Errorf("hot-store-postgres-dsn is required")
		}
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			return nil, nil, err
		}
		if err := db.PingContext(ctx); err != nil {
			db.Close()
			return nil, nil, err
		}
		if config.RunMigrations {
			migrations, err := migrationstore.LoadDir(config.MigrationDir)
			if err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("load hot store migrations: %w", err)
			}
			migrations, err = selectPostgresComponentMigrations(migrations, "hot store", postgresHotStoreMigrationVersions()...)
			if err != nil {
				db.Close()
				return nil, nil, err
			}
			if err := migrationstore.Apply(ctx, db, migrations); err != nil {
				db.Close()
				return nil, nil, fmt.Errorf("apply hot store migrations: %w", err)
			}
		}
		store := hotstore.NewPostgresStore(db)
		config.Writer.SetAppendHook(postgresHotStoreAppendHook(store, adminLogStreamFilenameMap(), config.MirrorMonitor))
		return store, func() error {
			config.Writer.SetAppendHook(nil)
			return db.Close()
		}, nil
	case "clickhouse":
		if config.Writer == nil {
			return nil, nil, fmt.Errorf("hot store writer is required")
		}
		endpoint := strings.TrimSpace(config.ClickHouseEndpoint)
		if endpoint == "" {
			return nil, nil, fmt.Errorf("hot-store-clickhouse-endpoint is required")
		}
		database := strings.TrimSpace(config.ClickHouseDatabase)
		if database == "" {
			database = "dsse"
		}
		table := strings.TrimSpace(config.ClickHouseTable)
		if table == "" {
			table = "events"
		}
		store := hotstore.NewClickHouseStore(endpoint, config.ClickHouseUser, config.ClickHousePassword, database, table)
		// ★ A SLOW ANALYTICS STORE MUST NOT STOP A CONTROL PLANE FROM STARTING (2026-08-12, watched happen).
		//
		// This health check returned an error and the process EXITED. So when ClickHouse got into trouble the
		// control plane crash-looped — and a control plane that will not start is one that publishes no config,
		// answers no admin write, and holds no halt. The store it was waiting for serves the Console's LOG
		// VIEWS: reading history is not what a control plane is for.
		//
		// The check still runs, and its failure is loud and recorded, because starting quietly with a hot store
		// nobody can read is how "the Logs tab is empty" becomes a mystery. What changed is the consequence:
		// degraded, not dead. The log views answer with the error; enforcement and configuration carry on.
		if _, err := store.Search(ctx, hotstore.SearchQuery{TenantID: "_healthcheck_", Limit: 1}); err != nil {
			log.Printf("★ HOT STORE DEGRADED: clickhouse at %s did not answer (%v). This process is starting "+
				"ANYWAY — configuration, enforcement and the halt do not depend on it. What IS affected: the "+
				"Console's log/DLP/usage views read this store, and they will report the error rather than an "+
				"empty result", endpoint, err)
		}
		// Mirror every hot-stream append into ClickHouse (the CP's audit-ingest receiver appends shipped records,
		// so this is where the aggregated events land in the OLAP tier).
		//
		// ★ THROUGH A BATCHING INGESTOR, NOT DIRECTLY (2026-08-12). The hook used to INSERT one row per append,
		// synchronously, with a 30-second timeout — so every audit append was bounded by ClickHouse's latency,
		// and every record became its own part for ClickHouse to merge. Measured: 12,428 single-row inserts and
		// 3,604 seconds of merging in three hours on a nearly idle lab.
		ingestor := hotstore.NewBatchIngestor(store, batchIngestorConfigWithMonitor(config.MirrorMonitor,
			config.BacklogSpoolPath))
		config.Writer.SetAppendHook(clickhouseHotStoreAppendHook(ingestor, adminLogStreamFilenameMap(), config.MirrorMonitor))
		return store, func() error {
			config.Writer.SetAppendHook(nil)
			_ = ingestor.Close()
			return nil
		}, nil
	default:
		return nil, nil, fmt.Errorf("unsupported hot store mode %q", config.Mode)
	}
}

// clickhouseHotStoreAppendHook ingests each hot-stream append into ClickHouse (mirrors the Postgres hook). A
// decode/ingest failure is logged + recorded but never blocks the local jsonl write (best-effort mirror).
// batchIngestorConfigWithMonitor keeps every failure and every drop visible: an OLAP tier quietly missing
// events is the thing this subsystem exists to avoid.
func batchIngestorConfigWithMonitor(monitor *hotStoreAppendMirrorMonitor, spoolPath string) hotstore.BatchIngestorConfig {
	cfg := hotstore.DefaultBatchIngestorConfig()
	// Where a batch that could not be written waits ACROSS a restart. Without it, a shutdown while the store is
	// unreachable leaves the hot store permanently short of those rows and nothing replays the jsonl.
	cfg.SpoolPath = spoolPath
	cfg.OnFlushError = func(err error, rows int) {
		log.Printf("clickhouse hot store batch ingest failed rows=%d: %v", rows, err)
		monitor.RecordIngestFailure("batch", "clickhouse", err, time.Now().UTC())
	}
	cfg.OnDrop = func(record hotstore.IngestRecord) {
		log.Printf("★ clickhouse hot store queue FULL — dropping a %s record; the OLAP tier will be missing it "+
			"(the local jsonl still holds it)", record.Stream)
		monitor.RecordIngestFailure(record.Stream, "clickhouse", errQueueFull, time.Now().UTC())
	}
	cfg.OnFlush = func(rows int) { monitor.RecordSuccess("batch", "clickhouse", time.Now().UTC()) }
	return cfg
}

var errQueueFull = errors.New("the clickhouse ingest queue is full")

func clickhouseHotStoreAppendHook(ingestor *hotstore.BatchIngestor, streamFiles map[string]string, monitor *hotStoreAppendMirrorMonitor) logs.AppendHook {
	filenameToStream := map[string]string{}
	for stream, filename := range streamFiles {
		stream = strings.TrimSpace(stream)
		filename = strings.TrimSpace(filename)
		if stream != "" && filename != "" {
			filenameToStream[filename] = stream
		}
	}
	return func(filename string, encoded []byte) error {
		stream := filenameToStream[strings.TrimSpace(filename)]
		if stream == "" {
			return nil
		}
		var row map[string]any
		if err := json.Unmarshal(encoded, &row); err != nil {
			log.Printf("clickhouse hot store ingest skipped: decode %s: %v", filename, err)
			monitor.RecordDecodeFailure(filename, err, time.Now().UTC())
			return nil
		}
		// Queued, not written: the writer must not wait for the OLAP tier. Failures and drops are reported by
		// the ingestor's callbacks, which is where the outcome is actually known.
		ingestor.Add(hotstore.IngestRecord{Stream: stream, Row: row, ReceivedAt: time.Now().UTC()})
		return nil
	}
}

func postgresHotStoreAppendHook(store *hotstore.PostgresStore, streamFiles map[string]string, monitor *hotStoreAppendMirrorMonitor) logs.AppendHook {
	filenameToStream := map[string]string{}
	for stream, filename := range streamFiles {
		stream = strings.TrimSpace(stream)
		filename = strings.TrimSpace(filename)
		if stream != "" && filename != "" {
			filenameToStream[filename] = stream
		}
	}
	return func(filename string, encoded []byte) error {
		stream := filenameToStream[strings.TrimSpace(filename)]
		if stream == "" {
			return nil
		}
		var row map[string]any
		if err := json.Unmarshal(encoded, &row); err != nil {
			log.Printf("postgres hot store ingest skipped: decode %s: %v", filename, err)
			monitor.RecordDecodeFailure(filename, err, time.Now().UTC())
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := store.Ingest(ctx, stream, row); err != nil {
			log.Printf("postgres hot store ingest failed stream=%s filename=%s: %v", stream, filename, err)
			monitor.RecordIngestFailure(stream, filename, err, time.Now().UTC())
			return nil
		}
		monitor.RecordSuccess(stream, filename, time.Now().UTC())
		return nil
	}
}
