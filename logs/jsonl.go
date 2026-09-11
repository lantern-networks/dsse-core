package logs

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// logFile holds a persistent append handle for one JSONL log file plus a mutex that
// serializes writes to that file only. Different files write concurrently (// removed the single global write lock + per-line open/close that serialized all flows).
type logFile struct {
	mu    sync.Mutex
	f     *os.File
	clean string // the on-disk relative path (rotation target)
	size  int64  // bytes in the current file (drives size-based rotation)
	// closed is set (under mu) when this handle has been EVICTED from the open-file LRU and its fd closed. A
	// writer that grabbed this *logFile just before eviction sees it and reopens via fileFor.
	closed bool
	// lastUsed is a recency stamp from Writer.useClock (guarded by Writer.mu), for LRU eviction.
	lastUsed uint64
}

// defaultMaxOpenLogFiles bounds how many append handles the Writer keeps open at once. On a multi-tenant Edge
// each distinct tenant-partitioned path (tenants/<tenant>/<file>) opened one persistent fd that was NEVER
// closed — unbounded fd growth (review #32). The LRU caps the working set; an evicted handle reopens on its
// next Append.
const defaultMaxOpenLogFiles = 512

// logLineBufPool reuses marshal buffers so the per-flow hot path does not allocate a
// fresh buffer per log line.
var logLineBufPool = sync.Pool{New: func() any { return new(bytes.Buffer) }}

type Writer struct {
	dir            string
	mu             sync.Mutex
	appendHook     AppendHook
	generatedLocks map[string]*sync.Mutex
	openFiles      map[string]*logFile
	// tenantPartitioned: log filenames whose rows are physically separated per tenant on disk
	// (tenant isolation). For these, Append routes each row to tenants/<tenant_id>/<filename>
	// based on the row's tenant_id; ReadJSONL aggregates the partitions (back-compat) and
	// ReadJSONLTenant reads exactly one tenant's partition. Default empty = no partitioning.
	tenantPartitioned map[string]bool
	// Rotation/retention (production: the jsonl logs must not grow unbounded → disk fill). When maxBytes>0
	// a file is rotated to <name>.1[.gz] once it reaches maxBytes, older backups shift up, and only the
	// newest maxBackups are kept. Zero maxBytes = disabled (default; tests opt out).
	maxBytes    int64
	maxBackups  int
	gzipBackups bool
	// maxOpenFiles caps the number of simultaneously-open append handles (LRU-evicted). 0 = the default.
	maxOpenFiles int
	// useClock is a monotonic recency counter stamped onto a logFile.lastUsed on each fileFor. Guarded by mu.
	useClock uint64
}

// SetMaxOpenFiles overrides the open-handle LRU cap (<=0 restores the default). Mainly for tests; production
// uses the default.
func (w *Writer) SetMaxOpenFiles(n int) {
	w.mu.Lock()
	w.maxOpenFiles = n
	w.mu.Unlock()
}

// SetRotation enables size-based rotation + retention for every log file. maxBytes<=0 disables it.
func (w *Writer) SetRotation(maxBytes int64, maxBackups int, gzipBackups bool) {
	w.mu.Lock()
	w.maxBytes = maxBytes
	if maxBackups < 0 {
		maxBackups = 0
	}
	w.maxBackups = maxBackups
	w.gzipBackups = gzipBackups
	w.mu.Unlock()
}

// SetTenantPartitionedFiles designates log filenames to physically partition per tenant. Call once at
// setup. Idempotent / replaces the set.
func (w *Writer) SetTenantPartitionedFiles(files ...string) {
	set := make(map[string]bool, len(files))
	for _, f := range files {
		if c, err := safeRelativeLogPath(f); err == nil {
			set[c] = true
		}
	}
	w.mu.Lock()
	w.tenantPartitioned = set
	w.mu.Unlock()
}

func (w *Writer) isTenantPartitioned(clean string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.tenantPartitioned[clean]
}

// SafeTenantSegment is safeTenantSegment, exported so that anything which has to FIND a tenant's partition —
// counting what is left of a tenant before an erasure, and erasing it — derives the path the same way the
// writer does. A second implementation of this mapping is a second answer to "where is that tenant's data",
// and the whole point of an erasure report is that there is only one.
func SafeTenantSegment(tenantID string) string { return safeTenantSegment(tenantID) }

// safeTenantSegment maps a tenant id to a single safe path segment. Empty/unknown → "_system" so
// tenant-less rows are kept in their own partition (never co-mingled with a real tenant).
func safeTenantSegment(tenantID string) string {
	t := strings.TrimSpace(tenantID)
	if t == "" {
		return "_system"
	}
	var b strings.Builder
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	seg := b.String()
	if seg == "" || seg == "." || seg == ".." {
		return "_system"
	}
	return seg
}

// tenantPartitionPath builds the on-disk relative path for a tenant's partition of a log file.
func tenantPartitionPath(tenantID, clean string) string {
	return filepath.Join("tenants", safeTenantSegment(tenantID), clean)
}

// tenantIDFromEncoded extracts the tenant_id from an encoded JSONL line (cheap, only used for the small
// set of tenant-partitioned files).
func tenantIDFromEncoded(line []byte) string {
	var probe struct {
		TenantID string `json:"tenant_id"`
	}
	_ = json.Unmarshal(line, &probe)
	return probe.TenantID
}

type AppendHook func(filename string, encoded []byte) error

func NewWriter(dir string) (*Writer, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	return &Writer{
		dir:            dir,
		generatedLocks: map[string]*sync.Mutex{},
		openFiles:      map[string]*logFile{},
	}, nil
}

// fileFor returns a persistent append handle for clean, opening it once and reusing it.
// The handle is opened with O_APPEND so concurrent writes (even from other handles to the
// same path) atomically append at EOF. Writes go straight to the OS page cache, so a fresh
// read (ReadJSONL / external verifier) observes prior appends immediately — read-after-write
// is preserved exactly as the previous open/write/close-per-line implementation.
func (w *Writer) fileFor(clean string) (*logFile, error) {
	w.mu.Lock()
	if lf := w.openFiles[clean]; lf != nil {
		w.useClock++
		lf.lastUsed = w.useClock
		w.mu.Unlock()
		return lf, nil
	}
	w.mu.Unlock()

	path := filepath.Join(w.dir, clean)
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create jsonl log dir: %w", err)
		}
	}
	f, err := openAppendLogFile(path)
	if err != nil {
		return nil, fmt.Errorf("open jsonl log: %w", err)
	}
	var size int64
	if st, serr := f.Stat(); serr == nil {
		size = st.Size() // resume size tracking across restarts
	}

	w.mu.Lock()
	if existing := w.openFiles[clean]; existing != nil {
		w.useClock++
		existing.lastUsed = w.useClock
		w.mu.Unlock()
		_ = f.Close()
		return existing, nil
	}
	w.useClock++
	lf := &logFile{f: f, clean: clean, size: size, lastUsed: w.useClock}
	w.openFiles[clean] = lf
	evicted := w.evictOpenFilesOverCapLocked()
	w.mu.Unlock()
	// Close evicted handles OUTSIDE w.mu: Append takes lf.mu then w.mu (via rotateLocked), so closing under
	// lf.mu while holding w.mu would be a lock-order inversion. The evicted entries are already out of the
	// map, so no new Append will find them; an Append that grabbed one just before eviction sees lf.closed
	// after taking lf.mu and reopens.
	for _, ev := range evicted {
		ev.mu.Lock()
		ev.closed = true
		_ = ev.f.Close()
		ev.mu.Unlock()
	}
	return lf, nil
}

// evictOpenFilesOverCapLocked removes least-recently-used open handles while the count exceeds the cap and
// returns them (their fds must be closed by the caller OUTSIDE w.mu). Caller holds w.mu. The cap is small
// (hundreds), so the O(n) LRU scan runs only on the rare over-cap insert, not on every append.
func (w *Writer) evictOpenFilesOverCapLocked() []*logFile {
	limit := w.maxOpenFiles
	if limit <= 0 {
		limit = defaultMaxOpenLogFiles
	}
	var evicted []*logFile
	for len(w.openFiles) > limit {
		var lruKey string
		var lru *logFile
		lruUsed := ^uint64(0)
		for k, lf := range w.openFiles {
			if lf.lastUsed < lruUsed {
				lruUsed, lruKey, lru = lf.lastUsed, k, lf
			}
		}
		if lru == nil {
			break
		}
		delete(w.openFiles, lruKey)
		evicted = append(evicted, lru)
	}
	return evicted
}

// Close closes every cached append handle. The Writer is long-lived in production; Close exists for
// orderly shutdown and for tests — Windows cannot delete an open file, so a test's TempDir cleanup fails
// unless the writer is closed first. The Writer stays usable after Close (handles reopen on next Append).
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	var firstErr error
	for _, lf := range w.openFiles {
		lf.mu.Lock()
		if err := lf.f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		lf.mu.Unlock()
	}
	w.openFiles = map[string]*logFile{}
	return firstErr
}

func (w *Writer) Dir() string {
	return w.dir
}

func (w *Writer) SetAppendHook(hook AppendHook) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.appendHook = hook
}

// AddAppendHook composes hook AFTER any existing append hook (both run per Append, in order). This lets
// independent consumers share the single hook slot — e.g. the postgres hot-store mirror and the audit
// shipper (audit/persistence decoupling). A nil hook is a no-op. If a prior hook returns an error, the
// added hook does not run (the prior error is returned).
func (w *Writer) AddAppendHook(hook AppendHook) {
	if hook == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	prev := w.appendHook
	if prev == nil {
		w.appendHook = hook
		return
	}
	w.appendHook = func(filename string, encoded []byte) error {
		if err := prev(filename, encoded); err != nil {
			return err
		}
		return hook(filename, encoded)
	}
}

func (w *Writer) Append(filename string, value any) error {
	clean, err := safeRelativeLogPath(filename)
	if err != nil {
		return err
	}

	// Marshal off any shared lock, into a pooled buffer. json.Encoder.Encode appends the
	// trailing newline, matching the previous Write(append(encoded, '\n')) behavior.
	buf := logLineBufPool.Get().(*bytes.Buffer)
	buf.Reset()
	if err := json.NewEncoder(buf).Encode(value); err != nil {
		logLineBufPool.Put(buf)
		return fmt.Errorf("encode jsonl value: %w", err)
	}
	line := buf.Bytes() // includes trailing '\n'

	w.mu.Lock()
	hook := w.appendHook
	partitioned := w.tenantPartitioned[clean]
	w.mu.Unlock()
	// The hook historically receives the encoded value WITHOUT the trailing newline.
	var hookBytes []byte
	if hook != nil {
		hookBytes = append([]byte(nil), line[:len(line)-1]...)
	}

	// tenant isolation: physically separate this row into its tenant's partition. The hook still
	// receives the LOGICAL filename (clean) so outbox/mirroring keys are unchanged.
	writeClean := clean
	if partitioned {
		writeClean = tenantPartitionPath(tenantIDFromEncoded(line), clean)
	}

	lf, err := w.fileFor(writeClean)
	if err != nil {
		logLineBufPool.Put(buf)
		return err
	}

	w.mu.Lock()
	maxBytes := w.maxBytes
	w.mu.Unlock()

	lf.mu.Lock()
	if lf.closed {
		// Evicted from the LRU between fileFor and here; reopen (it becomes most-recently-used, so it will
		// not be immediately re-evicted) and use the fresh handle.
		lf.mu.Unlock()
		lf, err = w.fileFor(writeClean)
		if err != nil {
			logLineBufPool.Put(buf)
			return err
		}
		lf.mu.Lock()
	}
	n, writeErr := lf.f.Write(line)
	lf.size += int64(n)
	rotateNow := writeErr == nil && maxBytes > 0 && lf.size >= maxBytes
	var rotErr error
	if rotateNow {
		rotErr = w.rotateLocked(lf) // lf.mu held
	}
	lf.mu.Unlock()
	logLineBufPool.Put(buf)
	if writeErr != nil {
		return fmt.Errorf("write jsonl value: %w", writeErr)
	}
	if rotErr != nil {
		return fmt.Errorf("rotate jsonl log: %w", rotErr)
	}

	if hook != nil {
		if err := hook(clean, hookBytes); err != nil {
			return fmt.Errorf("jsonl append hook: %w", err)
		}
	}

	return nil
}

// rotateLocked rotates lf's current file (caller holds lf.mu): close it, shift <name>.1..N backups up,
// move the current file into slot 1 (gzip if configured), drop anything beyond maxBackups, and reopen a
// fresh file. maxBackups<=0 discards the rotated content (cap only, no archive). On error it still reopens
// a writable file so logging never wedges.
func (w *Writer) rotateLocked(lf *logFile) error {
	w.mu.Lock()
	dir, maxBackups, doGzip := w.dir, w.maxBackups, w.gzipBackups
	w.mu.Unlock()
	path := filepath.Join(dir, lf.clean)

	_ = lf.f.Close()
	reopen := func() error {
		f, err := openAppendLogFile(path) // share-delete on Windows, like fileFor
		if err != nil {
			return err
		}
		lf.f = f
		lf.size = 0
		return nil
	}

	if maxBackups <= 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			_ = reopen()
			return err
		}
		return reopen()
	}

	suffix := ""
	if doGzip {
		suffix = ".gz"
	}
	bak := func(i int) string { return fmt.Sprintf("%s.%d%s", path, i, suffix) }
	_ = os.Remove(bak(maxBackups))
	for i := maxBackups - 1; i >= 1; i-- {
		_ = os.Rename(bak(i), bak(i+1)) // a missing intermediate backup is fine
	}
	var moveErr error
	if doGzip {
		moveErr = gzipRename(path, bak(1))
	} else if err := os.Rename(path, bak(1)); err != nil && !os.IsNotExist(err) {
		moveErr = err
	}
	if rErr := reopen(); rErr != nil {
		return rErr
	}
	return moveErr
}

// gzipRename gzips src into dstGz and removes src (used to archive a rotated log).
func gzipRename(src, dstGz string) error {
	in, err := os.Open(src)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer in.Close()
	out, err := os.Create(dstGz)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(out)
	if _, err := io.Copy(gz, in); err != nil {
		_ = gz.Close()
		_ = out.Close()
		return err
	}
	if err := gz.Close(); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	// Close src BEFORE removing it: the deferred Close runs only after this return, and Windows refuses to
	// delete a file with an open non-share-delete handle — gzip rotation failed every time there. The defer
	// stays for the early-return paths (a second Close is a harmless ErrClosed).
	_ = in.Close()
	return os.Remove(src)
}

// ReadJSONL reads a log file. For tenant-partitioned files it AGGREGATES across all tenant partitions
// (plus any legacy root file) so existing operator-wide readers keep working; use ReadJSONLTenant to read
// exactly one tenant's partition (strict isolation).
func (w *Writer) ReadJSONL(filename string) ([]map[string]any, error) {
	clean, err := safeRelativeLogPath(filename)
	if err != nil {
		return nil, err
	}
	if w.isTenantPartitioned(clean) {
		rows := []map[string]any{}
		// legacy/pre-partition data at the root path (if any)
		root, err := w.readJSONLClean(clean)
		if err != nil {
			return nil, err
		}
		rows = append(rows, root...)
		// every tenant partition
		segs, err := w.tenantPartitionSegments()
		if err != nil {
			return nil, err
		}
		for _, seg := range segs {
			part, err := w.readJSONLClean(filepath.Join("tenants", seg, clean))
			if err != nil {
				return nil, err
			}
			rows = append(rows, part...)
		}
		return rows, nil
	}
	return w.readJSONLClean(clean)
}

// ReadJSONLTenant reads exactly one tenant's partition of a tenant-partitioned log (strict
// isolation: no other tenant's rows are even read). Empty tenantID reads the "_system" partition.
func (w *Writer) ReadJSONLTenant(tenantID, filename string) ([]map[string]any, error) {
	clean, err := safeRelativeLogPath(filename)
	if err != nil {
		return nil, err
	}
	return w.readJSONLClean(tenantPartitionPath(tenantID, clean))
}

// tenantPartitionSegments lists the tenant segment dirs under tenants/.
func (w *Writer) tenantPartitionSegments() ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(w.dir, "tenants"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list tenant partitions: %w", err)
	}
	var segs []string
	for _, e := range entries {
		if e.IsDir() {
			segs = append(segs, e.Name())
		}
	}
	sort.Strings(segs)
	return segs, nil
}

// readJSONLClean reads a single already-cleaned log path.
func (w *Writer) readJSONLClean(clean string) ([]map[string]any, error) {
	// Serialize with concurrent writers to THIS file only (not every flow), so a read does
	// not observe a partially written line. Writes are synchronous to the OS, so a fresh
	// os.Open here sees all prior appends.
	w.mu.Lock()
	lf := w.openFiles[clean]
	w.mu.Unlock()
	if lf != nil {
		lf.mu.Lock()
		defer lf.mu.Unlock()
	}

	path := filepath.Join(w.dir, clean)
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []map[string]any{}, nil
		}
		return nil, fmt.Errorf("open jsonl log: %w", err)
	}
	defer file.Close()

	rows := []map[string]any{}
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for scanner.Scan() {
		var row map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return nil, fmt.Errorf("decode jsonl row: %w", err)
		}
		rows = append(rows, row)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan jsonl log: %w", err)
	}

	return rows, nil
}

func (w *Writer) WriteGzipJSONL(filename string, values []map[string]any) (string, error) {
	index := 0
	return w.WriteGzipJSONLStream(filename, func() (map[string]any, bool, error) {
		if index >= len(values) {
			return nil, false, nil
		}
		value := values[index]
		index++
		return value, true, nil
	})
}

func (w *Writer) WriteGzipJSONLStream(filename string, next func() (map[string]any, bool, error)) (string, error) {
	if next == nil {
		return "", fmt.Errorf("jsonl export stream source is required")
	}
	clean, err := safeRelativeLogPath(filename)
	if err != nil {
		return "", err
	}
	unlock := w.generatedFileLock(clean)
	defer unlock()

	path := filepath.Join(w.dir, clean)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("create jsonl export dir: %w", err)
	}
	file, err := os.Create(path)
	if err != nil {
		return "", fmt.Errorf("create jsonl export: %w", err)
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(path)
		}
	}()

	hash := sha256.New()
	gzipWriter := gzip.NewWriter(io.MultiWriter(file, hash))
	encoder := json.NewEncoder(gzipWriter)
	for {
		value, ok, err := next()
		if err != nil {
			gzipWriter.Close()
			return "", fmt.Errorf("read jsonl export row: %w", err)
		}
		if !ok {
			break
		}
		if err := encoder.Encode(value); err != nil {
			gzipWriter.Close()
			return "", fmt.Errorf("encode jsonl export row: %w", err)
		}
	}
	if err := gzipWriter.Close(); err != nil {
		return "", fmt.Errorf("close jsonl export gzip: %w", err)
	}
	committed = true

	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

func (w *Writer) ReadGeneratedFile(filename string) ([]byte, error) {
	clean, err := safeRelativeLogPath(filename)
	if err != nil {
		return nil, err
	}
	unlock := w.generatedFileLock(clean)
	defer unlock()

	path := filepath.Join(w.dir, clean)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read generated file: %w", err)
	}
	return data, nil
}

func (w *Writer) generatedFileLock(clean string) func() {
	w.mu.Lock()
	if w.generatedLocks == nil {
		w.generatedLocks = map[string]*sync.Mutex{}
	}
	lock := w.generatedLocks[clean]
	if lock == nil {
		lock = &sync.Mutex{}
		w.generatedLocks[clean] = lock
	}
	w.mu.Unlock()

	lock.Lock()
	return lock.Unlock
}

func (w *Writer) ListGeneratedFiles(prefix, suffix string, limit int) ([]string, error) {
	cleanPrefix, err := safeRelativeLogPath(strings.TrimSuffix(prefix, "/"))
	if err != nil {
		return nil, err
	}
	if limit < 1 {
		return nil, fmt.Errorf("generated file list limit must be positive")
	}
	w.mu.Lock()
	defer w.mu.Unlock()

	root := filepath.Join(w.dir, cleanPrefix)
	files := make([]string, 0)
	if _, err := os.Stat(root); err != nil {
		if os.IsNotExist(err) {
			return files, nil
		}
		return nil, fmt.Errorf("stat generated file prefix: %w", err)
	}
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(w.dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if suffix != "" && !strings.HasSuffix(rel, suffix) {
			return nil
		}
		files = append(files, rel)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("list generated files: %w", err)
	}
	sort.Strings(files)
	if len(files) > limit {
		files = files[:limit]
	}
	return files, nil
}

func safeRelativeLogPath(filename string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(filename))
	// filepath.IsLocal is the authoritative "stays under the log dir" check. The previous
	// IsAbs+dot-dot test missed Windows-only escapes: a rooted path ("/tmp/x" — NOT IsAbs on Windows),
	// a drive-relative path ("C:evil"), and NTFS alternate-data-stream colons. IsLocal rejects all of
	// those (plus reserved device names like NUL) on the platform's own rules.
	if !filepath.IsLocal(clean) {
		return "", fmt.Errorf("filename is outside log dir")
	}
	return clean, nil
}

// CloseTenant releases every cached append handle under one tenant's partition, so the partition can be
// removed from disk.
//
// ★ WHY AN ERASURE NEEDS THIS (2026-08-15). The writer keeps files open for append. Unlinking a path whose
// descriptor is still held frees the name and NOT the bytes — the data stays alive, and readable through
// /proc, until the process lets go. An erasure that only really happens at the next restart is not an
// erasure, and it would report success in the meantime.
//
// Handles are removed from the map under w.mu and closed outside it, the same lock order eviction uses. The
// writer stays usable: a later Append for that tenant simply reopens, which is correct — a purged tenant that
// somehow writes again is a fact worth having on disk rather than one silently dropped.
func (w *Writer) CloseTenant(tenantID string) error {
	prefix := filepath.Join("tenants", safeTenantSegment(tenantID)) + string(filepath.Separator)
	w.mu.Lock()
	var closing []*logFile
	for key, lf := range w.openFiles {
		if strings.HasPrefix(key, prefix) {
			delete(w.openFiles, key)
			closing = append(closing, lf)
		}
	}
	w.mu.Unlock()

	var firstErr error
	for _, lf := range closing {
		lf.mu.Lock()
		lf.closed = true
		if err := lf.f.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		lf.mu.Unlock()
	}
	return firstErr
}
