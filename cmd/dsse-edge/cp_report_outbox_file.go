package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/lantern-networks/dsse-core/durablefile"
)

func decodeCPReportObject(line []byte, target any) error {
	trimmed := bytes.TrimSpace(line)
	// json.Unmarshal("null", &struct) succeeds with a zero-value struct. That
	// is never a report written by these queues and must not be acknowledged.
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("outbox report is not a JSON object")
	}
	return json.Unmarshal(trimmed, target)
}

// appendCPReportOutbox is called under the reporter's mutex. A torn final
// record must stay on disk, but it must not consume the next valid report.
func appendCPReportOutbox(path string, line []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	stat, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	payload := make([]byte, 0, len(line)+2)
	if stat.Size() > 0 {
		var last [1]byte
		if _, err := f.ReadAt(last[:], stat.Size()-1); err != nil {
			f.Close()
			return err
		}
		if last[0] != '\n' {
			payload = append(payload, '\n')
		}
	}
	payload = append(payload, line...)
	payload = append(payload, '\n')
	if n, err := f.Write(payload); err != nil || n != len(payload) {
		f.Close()
		if err != nil {
			return err
		}
		return io.ErrShortWrite
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return durablefile.SyncDir(filepath.Dir(path))
}

// replaceCPReportOutbox commits the remaining obligations without truncating
// the live file. Persist an empty snapshot before unlinking a drained queue so
// a crash cannot resurrect previously acknowledged reports.
func replaceCPReportOutbox(path string, pending []byte) error {
	if err := durablefile.Write(path, pending, 0o600); err != nil {
		return err
	}
	if len(pending) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove drained outbox: %w", err)
		}
		return durablefile.SyncDir(filepath.Dir(path))
	}
	return nil
}
