package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/lantern-networks/dsse-core/durablefile"
)

// shipSpool is the audit shipper's durable, bounded, restart-surviving buffer of un-acked records — the design's
// "rotated local WAL spill" ( step 2). Each queued record is appended here (O(1)) BEFORE
// it is shipped; a CP ack drops it from the in-memory queue; periodic COMPACTION rewrites the file to exactly the
// still-un-acked set (atomic temp+rename), bounding the file and dropping acked/dropped records from disk. On
// startup the file is replayed into the queue, so records that were appended but not yet acked when the Edge
// stopped are RE-SHIPPED rather than lost (previously the pending spool was in-memory only — an Edge restart
// silently dropped everything in flight; the canonical jsonl still held them but nothing resumed shipping).
//
// Because CP ingest is idempotent (event_log_design.md/ — dedup by (tenant, stream, event_id)), the file may
// transiently hold already-acked records (re-shipped after a crash, then deduped away), so the spool never needs a
// per-record fsync or a separate crash-durable ack cursor: correctness only requires never LOSING an un-acked
// record, and the compaction rewrite is atomic (temp + rename).
//
// All methods are called from the single shipper goroutine (remoteAuditShipper.run) except newShipSpool, which runs
// at startup before the loop — so there is no internal locking. A nil *shipSpool is a valid disabled spool (every
// method is a no-op), used by tests and when no log directory is configured.
type shipSpool struct {
	path      string
	tmp       string
	f         *os.File
	appends   int // appends since the last compaction; bounds the on-disk file to ~2x the queue cap
	compactAt int // compact once this many records have been appended since the last compaction
}

// spoolRecord is the on-disk encoding of one queued record. R is []byte so json base64-encodes the arbitrary
// record bytes — no NDJSON newline/escaping hazard regardless of the record's content.
type spoolRecord struct {
	S string `json:"s"`
	R []byte `json:"r"`
}

// newShipSpool opens (creating if needed) the durable spool at path and returns any records already on disk, for
// the caller to replay into its queue. compactAt bounds how far the file may drift from the live queue before a
// rewrite. An empty path returns a nil (disabled) spool — in-memory-only behavior, for tests and when no log dir
// is configured.
func newShipSpool(path string, compactAt int) (*shipSpool, []auditShipItem, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil, nil
	}
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, nil, fmt.Errorf("create audit ship spool dir: %w", err)
		}
	}
	replay, unterminatedTail, err := readShipSpoolForStartup(path)
	if err != nil {
		return nil, nil, err
	}
	if unterminatedTail {
		// Opening O_APPEND against a tail with no delimiter would concatenate the next record to it. Rewrite
		// only the parsed records before opening the append handle; a failed repair blocks startup and leaves
		// the original spool available for diagnosis.
		if err := repairUnterminatedShipSpool(path, replay); err != nil {
			return nil, nil, fmt.Errorf("repair unterminated audit ship spool before append: %w", err)
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, nil, fmt.Errorf("open audit ship spool: %w", err)
	}
	if compactAt <= 0 {
		compactAt = 4096
	}
	return &shipSpool{path: path, tmp: path + ".tmp", f: f, compactAt: compactAt}, replay, nil
}

// readShipSpool decodes records for inspection without changing the file. The startup caller also receives
// whether the final line lacks its delimiter, so it can repair that tail before opening the append handle.
func readShipSpool(path string) ([]auditShipItem, error) {
	out, _, err := readShipSpoolForStartup(path)
	return out, err
}

// A torn final line (a crash mid-append) is skipped; a complete JSON record missing only the delimiter is
// retained. Both forms require an atomic rewrite before append. A malformed newline-terminated line is not a
// torn append: refuse replay and preserve the file rather than silently deleting a record at compaction.
func readShipSpoolForStartup(path string) ([]auditShipItem, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("open audit ship spool for replay: %w", err)
	}
	defer f.Close()
	var out []auditShipItem
	var unterminatedTail bool
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1024*1024), 64*1024*1024)
	// Unlike ScanLines, retain the newline in each token so a completed corrupt record is distinguishable from
	// the single unterminated record that a crash can leave at EOF. Keep Scanner's existing per-record size cap.
	sc.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[:i+1], nil
		}
		if atEOF && len(data) > 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	lineNumber := 0
	for sc.Scan() {
		lineNumber++
		line := sc.Bytes()
		terminated := line[len(line)-1] == '\n'
		if !terminated {
			unterminatedTail = true
		}
		var rec spoolRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			if !terminated {
				continue // torn final append; canonical jsonl still holds it
			}
			return nil, false, fmt.Errorf("audit ship spool replay stopped at malformed completed line %d: %w", lineNumber, err)
		}
		out = append(out, auditShipItem{stream: rec.S, record: rec.R})
	}
	if err := sc.Err(); err != nil {
		return nil, false, fmt.Errorf("audit ship spool replay read: %w", err)
	}
	return out, unterminatedTail, nil
}

// repairUnterminatedShipSpool writes a complete, newline-delimited spool before appending can resume. The
// original path is not truncated or removed on staging failure. The canonical local JSONL still retains any
// incomplete final record that cannot be replayed here.
func repairUnterminatedShipSpool(path string, replay []auditShipItem) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".repair-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	w := bufio.NewWriter(tmp)
	for _, item := range replay {
		line, err := json.Marshal(spoolRecord{S: item.stream, R: item.record})
		if err != nil {
			_ = tmp.Close()
			return err
		}
		if _, err := w.Write(line); err != nil {
			_ = tmp.Close()
			return err
		}
		if err := w.WriteByte('\n'); err != nil {
			_ = tmp.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), info.Mode().Perm()); err != nil {
		return err
	}
	return durablefile.Replace(tmp.Name(), path)
}

// append durably records one queued item (best-effort: on a write error the canonical jsonl still holds the record).
func (s *shipSpool) append(item auditShipItem) {
	if s == nil || s.f == nil {
		return
	}
	line, err := json.Marshal(spoolRecord{S: item.stream, R: item.record})
	if err != nil {
		return
	}
	if _, err := s.f.Write(append(line, '\n')); err != nil {
		return
	}
	s.appends++
}

// maybeCompact rewrites the spool to exactly queue once enough records have been appended since the last rewrite,
// bounding the file to ~2x the queue cap and dropping acked/dropped records from disk.
func (s *shipSpool) maybeCompact(queue []auditShipItem) {
	if s == nil || s.appends < s.compactAt {
		return
	}
	s.compact(queue)
}

// compact atomically rewrites the spool file to hold exactly queue (the current un-acked set): write a temp file,
// rename over the live file, reopen the append handle. On any error it leaves the existing file intact (the queue
// is still in memory and the canonical jsonl is untouched), so a failed compaction never loses records.
func (s *shipSpool) compact(queue []auditShipItem) {
	if s == nil {
		return
	}
	tmp, err := os.OpenFile(s.tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		log.Printf("audit ship spool: compaction could not open %s: %v — the spool keeps growing", s.tmp, err)
		return
	}
	w := bufio.NewWriter(tmp)
	for _, item := range queue {
		line, err := json.Marshal(spoolRecord{S: item.stream, R: item.record})
		if err != nil {
			continue
		}
		_, _ = w.Write(line)
		_ = w.WriteByte('\n')
	}
	if err := w.Flush(); err != nil {
		_ = tmp.Close()
		log.Printf("audit ship spool: compaction could not write %s: %v — the spool keeps growing", s.tmp, err)
		return
	}
	if err := tmp.Close(); err != nil {
		log.Printf("audit ship spool: compaction could not close %s: %v — the spool keeps growing", s.tmp, err)
		return
	}
	// Release the append handle BEFORE the rename, not after. Unix lets a file be replaced while it is open, so
	// closing afterwards worked there; Windows refuses to replace a file that anyone still holds open, so the
	// rename failed every time and — because every error path here simply returned — the spool silently never
	// compacted and grew without bound. Closing first is correct on both.
	s.closeHandle()
	if err := os.Rename(s.tmp, s.path); err != nil {
		// The original file is still intact and still holds the records; reopen and carry on appending to it.
		log.Printf("audit ship spool: compaction could not replace %s: %v — the spool keeps growing", s.path, err)
		s.reopen()
		return
	}
	s.reopen()
	s.appends = 0
}

// closeHandle drops the append handle, leaving nil rather than a closed *os.File so append cannot write into
// something already closed.
func (s *shipSpool) closeHandle() {
	if s.f != nil {
		_ = s.f.Close()
		s.f = nil
	}
}

// reopen re-establishes the append handle after a compaction. A failure here is reported and leaves the spool
// disabled for appends rather than half-open: the canonical jsonl still holds every record, so losing the
// durable mirror degrades restart recovery but never loses data.
func (s *shipSpool) reopen() {
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		log.Printf("audit ship spool: could not reopen %s after compaction: %v — records stay in the canonical jsonl, "+
			"but un-acked records will no longer survive a restart", s.path, err)
		return
	}
	s.f = f
}

// close releases the append handle (best-effort; shutdown).
func (s *shipSpool) close() {
	if s == nil {
		return
	}
	s.closeHandle()
}
