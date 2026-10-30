package dlp

import (
	"bytes"
	"testing"
)

func TestEncryptedSpillCompactsConsumedFrames(t *testing.T) {
	s, err := newEncryptedSpill(0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.close() }()
	block := bytes.Repeat([]byte("synthetic-data-"), 4096)
	var maxSize int64
	var released int64
	for i := 0; i < 120; i++ {
		if err := s.append(block); err != nil {
			t.Fatal(err)
		}
		// Keep the final chunk unresolved, as happens when a second email
		// candidate begins before the first spill has drained completely.
		safeUntil := s.end - int64(len(block))
		for s.readPos < safeUntil {
			var out [chunkSize]byte
			n, err := s.readSafe(out[:], safeUntil)
			if err != nil || n == 0 {
				t.Fatalf("readSafe n=%d err=%v", n, err)
			}
			for j := 0; j < n; j++ {
				if out[j] != block[int((released+int64(j))%int64(len(block)))] {
					t.Fatal("authenticated spill changed the body")
				}
			}
			released += int64(n)
		}
		stat, err := s.file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if stat.Size() > maxSize {
			maxSize = stat.Size()
		}
	}
	if maxSize >= 3*spillCompactThreshold/2 {
		t.Fatalf("consumed encrypted frames accumulated: max file bytes=%d", maxSize)
	}
	for s.readPos < s.end {
		var out [chunkSize]byte
		n, err := s.readSafe(out[:], s.end)
		if err != nil || n == 0 {
			t.Fatalf("drain n=%d err=%v", n, err)
		}
	}
}
