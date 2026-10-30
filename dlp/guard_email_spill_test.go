package dlp

import (
	"bytes"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func longSyntheticEmail() string {
	return "local@a." + strings.Repeat("bb.", 40000) + "cc"
}

func TestGuardLongEmailBlockedBeforeRelease(t *testing.T) {
	email := longSyntheticEmail()
	for _, size := range []int{1, 7, 4097, 5000, 32768} {
		t.Run(strings.Repeat("x", size%11+1), func(t *testing.T) {
			body := "safe-prefix " + email + " ending"
			g := NewGuardReader(&fixedChunkReader{data: []byte(body), size: size}, map[IdentifierType]int{Email: 1})
			var sink bytes.Buffer
			_, err := io.Copy(&sink, g)
			if !errors.Is(err, ErrBlocked) || findingCount(g.Findings(), Email) != 1 {
				t.Fatalf("blocked=%v findings=%v", err, g.Findings())
			}
			if !strings.HasPrefix(body, sink.String()) || strings.Contains(sink.String(), "local@") {
				t.Fatal("pending email bytes were released")
			}
			if g.spool != nil || len(g.hold) != 0 || len(g.ready) != 0 {
				t.Fatal("blocked guard retained pending body")
			}
		})
	}
}

func TestGuardLongEmailAllowlistAndBoundedMemory(t *testing.T) {
	email := longSyntheticEmail()
	allow := NewAllowlist("test-salt", []string{email})
	for _, tc := range []struct {
		name, body string
		blocked    bool
	}{
		{"allowed", email + " ending", false},
		{"changed", strings.Replace(email, "bb.bb.", "bc.bb.", 1) + " ending", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewGuardReaderWithOptions(&fixedChunkReader{data: []byte(tc.body), size: 5000}, map[IdentifierType]int{Email: 1}, Options{Allowlist: allow})
			var sink bytes.Buffer
			_, err := io.Copy(&sink, g)
			if tc.blocked {
				if !errors.Is(err, ErrBlocked) || sink.Len() != 0 {
					t.Fatalf("changed email released: n=%d err=%v", sink.Len(), err)
				}
			} else if err != nil || sink.String() != tc.body {
				t.Fatalf("allowed address changed: n=%d err=%v", sink.Len(), err)
			}
			if cap(g.hold) > 2*chunkSize || cap(g.ready) > 2*chunkSize {
				t.Fatalf("guard retained excessive body in RAM: hold=%d ready=%d", cap(g.hold), cap(g.ready))
			}
			if g.spool != nil {
				t.Fatal("spool not cleaned up")
			}
		})
	}
}

type fixedChunkReader struct {
	data []byte
	size int
}

func (r *fixedChunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := len(p)
	if n > r.size {
		n = r.size
	}
	n = copy(p[:n], r.data)
	r.data = r.data[n:]
	return n, nil
}

type hookedChunkReader struct {
	chunks [][]byte
	before func(int)
	index  int
	offset int
}

func (r *hookedChunkReader) Read(p []byte) (int, error) {
	if r.index == len(r.chunks) {
		return 0, io.EOF
	}
	if r.before != nil && r.offset == 0 {
		r.before(r.index)
	}
	n := copy(p, r.chunks[r.index][r.offset:])
	r.offset += n
	if r.offset == len(r.chunks[r.index]) {
		r.index++
		r.offset = 0
	}
	return n, nil
}

func TestGuardEncryptedSpoolPrivateAndAuthenticated(t *testing.T) {
	email := longSyntheticEmail()
	first := []byte(email[:20000])
	second := []byte(email[20000:] + " ending")
	src := &hookedChunkReader{chunks: [][]byte{first, second}}
	g := NewGuardReader(src, nil)
	src.before = func(i int) {
		if i != 1 {
			return
		}
		if g.spool == nil {
			t.Error("long pending match did not enter encrypted spill")
			return
		}
		fileInfo, err := g.spool.file.Stat()
		if err != nil {
			t.Fatal(err)
		}
		if runtime.GOOS != "windows" && fileInfo.Mode().Perm() != 0o600 {
			t.Errorf("spill file mode=%v", fileInfo.Mode().Perm())
		}
		if runtime.GOOS != "windows" {
			if _, err := os.Stat(g.spool.path); !os.IsNotExist(err) {
				t.Fatal("spill retained a named body file")
			}
			if _, err := os.Stat(g.spool.dir); !os.IsNotExist(err) {
				t.Fatal("anonymous spill retained its directory")
			}
		}
		ciphertext := make([]byte, fileInfo.Size())
		_, err = g.spool.file.ReadAt(ciphertext, 0)
		if err != nil || bytes.Contains(ciphertext, []byte("local@a.")) {
			t.Errorf("spill contains plaintext or is unreadable: %v", err)
		}
	}
	got, err := io.ReadAll(g)
	if err != nil || string(got) != email+" ending" {
		t.Fatalf("guard changed benign body: n=%d err=%v", len(got), err)
	}
	if g.spool != nil {
		t.Fatal("spool remained after complete read")
	}
}

func TestGuardEncryptedSpoolFailureDoesNotReleasePendingBytes(t *testing.T) {
	for _, failure := range []string{"create", "write", "decrypt"} {
		t.Run(failure, func(t *testing.T) {
			if failure == "create" {
				t.Setenv("TMPDIR", t.TempDir()+"/missing")
			}
			email := longSyntheticEmail()
			src := &hookedChunkReader{chunks: [][]byte{[]byte(email[:20000]), []byte(email[20000:] + " end")}}
			g := NewGuardReader(src, nil)
			src.before = func(i int) {
				if i != 1 || g.spool == nil {
					return
				}
				switch failure {
				case "write":
					_ = g.spool.file.Close()
				case "decrypt":
					_, _ = g.spool.file.WriteAt([]byte{0xff}, spillHeaderSize+1)
				}
			}
			var sink bytes.Buffer
			_, err := io.Copy(&sink, g)
			if !errors.Is(err, ErrInspectionFailed) || sink.Len() != 0 {
				t.Fatalf("unsafe release after %s fault: n=%d err=%v", failure, sink.Len(), err)
			}
			if g.spool != nil {
				t.Fatal("failed guard retained spool")
			}
		})
	}
}

type blockedReadCloser struct {
	entered chan struct{}
	closed  chan struct{}
	once    sync.Once
	closes  int
}

func (r *blockedReadCloser) Read(_ []byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	<-r.closed
	return 0, io.ErrClosedPipe
}

func (r *blockedReadCloser) Close() error {
	r.closes++
	close(r.closed)
	return nil
}

func TestGuardCloseInterruptsBlockedReadAndIsIdempotent(t *testing.T) {
	src := &blockedReadCloser{entered: make(chan struct{}), closed: make(chan struct{})}
	g := NewGuardReader(src, nil)
	readDone := make(chan error, 1)
	go func() { _, err := g.Read(make([]byte, 32)); readDone <- err }()
	select {
	case <-src.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("source Read did not start")
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- g.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Close failed to interrupt source Read")
	}
	if err := <-readDone; !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Read after concurrent Close = %v", err)
	}
	if err := g.Close(); err != nil || src.closes != 1 {
		t.Fatalf("duplicate Close: closes=%d err=%v", src.closes, err)
	}
	if _, err := g.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Read after Close = %v", err)
	}
}

type pendingThenBlockedReadCloser struct {
	first   []byte
	entered chan struct{}
	closed  chan struct{}
	closes  int
}

func (r *pendingThenBlockedReadCloser) Read(p []byte) (int, error) {
	if r.first != nil {
		n := copy(p, r.first)
		r.first = nil
		return n, nil
	}
	close(r.entered)
	<-r.closed
	return 0, io.ErrClosedPipe
}

func (r *pendingThenBlockedReadCloser) Close() error {
	r.closes++
	close(r.closed)
	return nil
}

func TestGuardCloseCleansPendingSpillDuringBlockedRead(t *testing.T) {
	src := &pendingThenBlockedReadCloser{
		first: []byte(longSyntheticEmail()[:20000]), entered: make(chan struct{}), closed: make(chan struct{}),
	}
	g := NewGuardReader(src, map[IdentifierType]int{Email: 1})
	readDone := make(chan error, 1)
	go func() { _, err := g.Read(make([]byte, 32)); readDone <- err }()
	select {
	case <-src.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("source Read did not reach pending state")
	}
	if g.spool == nil {
		t.Fatal("pending email did not enter spill")
	}
	dir := g.spool.dir
	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-readDone; !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Read after Close = %v", err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) || src.closes != 1 {
		t.Fatalf("spool cleanup/source close: stat=%v closes=%d", err, src.closes)
	}
}
