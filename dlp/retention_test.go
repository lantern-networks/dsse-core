package dlp

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func testRetentionBudget(perStream, process int64) *RetentionBudget {
	return &RetentionBudget{perStream: perStream, process: process}
}

func TestGuardRetentionLimitRefusesUndecidedBytesAndReleases(t *testing.T) {
	for _, size := range []int{1, 32768} {
		b := testRetentionBudget(guardWorkingBytes+24000, guardWorkingBytes+24000)
		g := NewGuardReaderWithOptions(&fixedChunkReader{data: []byte("a@b" + strings.Repeat(".cc", 40000)), size: size}, map[IdentifierType]int{Email: 1}, Options{RetentionBudget: b})
		var sent bytes.Buffer
		_, err := io.Copy(&sent, g)
		if !errors.Is(err, ErrRetentionLimit) || !g.ResourceLimited() || g.Tripped() || sent.Len() != 0 {
			t.Fatalf("resource refusal misclassified or leaked bytes: size=%d n=%d err=%v", size, sent.Len(), err)
		}
		if got := b.Status(); got.UsedBytes != 0 || got.ActiveGuards != 0 {
			t.Fatalf("resources retained: %+v", got)
		}
		if g.tmp != nil || g.hold != nil || g.ready != nil || g.email != nil || g.custom != nil || g.spool != nil {
			t.Fatal("terminal guard retained body state")
		}
		_ = g.Close()
		_ = g.Close()
		if b.Status().UsedBytes != 0 {
			t.Fatal("repeated close corrupted accounting")
		}
	}
}

func TestSpillBudgetChargesCiphertextOverheadAndCompaction(t *testing.T) {
	b := testRetentionBudget(guardWorkingBytes+100, guardWorkingBytes+100)
	l, _ := b.acquire()
	s, err := newEncryptedSpillWithLease(0, l)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.close(); l.releaseWorking() }()
	for i := 0; i < 2; i++ {
		if err := s.append([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if s.writeAt != 82 || b.Status().UsedBytes != guardWorkingBytes+82 {
		t.Fatal("AEAD frame overhead was not charged")
	}
	if err := s.append([]byte("x")); !errors.Is(err, ErrRetentionLimit) {
		t.Fatal("one-byte frames exceeded physical budget")
	}
	var out [1]byte
	if n, err := s.readSafe(out[:], 1); n != 1 || err != nil {
		t.Fatal(n, err)
	}
	// append must reclaim the consumed frame even below the usual 2MiB
	// compaction threshold instead of treating bytes ever sent as a quota.
	if err := s.append([]byte("x")); err != nil {
		t.Fatal(err)
	}
	stat, _ := s.file.Stat()
	if stat.Size() != 82 || b.Status().UsedBytes != guardWorkingBytes+82 {
		t.Fatal("compaction did not return actual truncated bytes")
	}
}

type spillFaultFile struct {
	spillFile
	failClose, failTruncate bool
}

func (f spillFaultFile) Close() error {
	if f.failClose {
		return errors.New("injected close failure")
	}
	return f.spillFile.Close()
}
func (f spillFaultFile) Truncate(n int64) error {
	if f.failTruncate {
		return errors.New("injected truncate failure")
	}
	return f.spillFile.Truncate(n)
}

func TestSpillFailedCleanupCannotReleaseUnreclaimedBudget(t *testing.T) {
	for _, fault := range []string{"close", "truncate"} {
		t.Run(fault, func(t *testing.T) {
			b := testRetentionBudget(guardWorkingBytes+1000, guardWorkingBytes+1000)
			l, _ := b.acquire()
			s, err := newEncryptedSpillWithLease(0, l)
			if err != nil {
				t.Fatal(err)
			}
			original := s.file
			defer func() { _ = original.Close(); _ = retireEphemeralSpill(s.dir) }()
			if err := s.append([]byte("abc")); err != nil {
				t.Fatal(err)
			}
			charged := s.charged
			if fault == "truncate" {
				var out [1]byte
				_, _ = s.readSafe(out[:], 1)
				s.file = spillFaultFile{spillFile: original, failTruncate: true}
				if err := s.compactConsumed(true); err == nil {
					t.Fatal("injected truncate failure ignored")
				}
				if b.Status().UsedBytes != guardWorkingBytes+charged {
					t.Fatal("failed truncate released budget")
				}
				s.file = original
				_ = s.close()
				l.releaseWorking()
				if b.Status().UsedBytes != 0 {
					t.Fatal("confirmed close did not release budget")
				}
			} else {
				s.file = spillFaultFile{spillFile: original, failClose: true}
				if err := s.close(); err == nil {
					t.Fatal("injected close failure ignored")
				}
				l.releaseWorking()
				if got := b.Status(); got.UsedBytes != charged || got.UnreleasedBytes != charged {
					t.Fatalf("unreclaimed disk became reusable: %+v", got)
				}
			}
		})
	}
}

type blankBody struct{}

func (blankBody) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	return len(p), nil
}

func TestGuardRetentionDoesNotLimitTotalTransfer(t *testing.T) {
	b := testRetentionBudget(DefaultRetentionPerStreamBytes, DefaultRetentionProcessBytes)
	const size = 65 << 20
	g := NewGuardReaderWithOptions(io.LimitReader(blankBody{}, size), map[IdentifierType]int{Email: 1}, Options{RetentionBudget: b})
	n, err := io.Copy(io.Discard, g)
	if err != nil || n != size {
		t.Fatalf("normal streaming body hit a transfer quota: %d %v", n, err)
	}
	if b.Status().UsedBytes != 0 {
		t.Fatal("EOF without Close retained reservation")
	}
}

func TestGuardProcessRetentionIsSharedAndRefusalsDoNotPoisonOtherUploads(t *testing.T) {
	b := testRetentionBudget(guardWorkingBytes+64000, 2*guardWorkingBytes+80000)
	first := NewGuardReaderWithOptions(strings.NewReader("benign"), nil, Options{RetentionBudget: b})
	defer first.Close()
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			g := NewGuardReaderWithOptions(strings.NewReader("a@b"+strings.Repeat(".cc", 40000)), nil, Options{RetentionBudget: b})
			defer g.Close()
			n, err := io.Copy(io.Discard, g)
			if !errors.Is(err, ErrRetentionLimit) || n != 0 {
				t.Errorf("unresolved upload escaped limit: %d %v", n, err)
			}
			if s := b.Status(); s.UsedBytes > s.ProcessBytes || s.UsedBytes < 0 {
				t.Errorf("aggregate reservation invalid: %+v", s)
			}
		}()
	}
	wg.Wait()
	got, err := io.ReadAll(first)
	if err != nil || string(got) != "benign" {
		t.Fatal("another upload was interrupted")
	}
	if b.Status().UsedBytes != 0 {
		t.Fatal("concurrent reservations leaked")
	}
}

type sourceFailure struct{}

func (sourceFailure) Read([]byte) (int, error) { return 0, errors.New("injected source failure") }
func TestGuardRetentionReleasedOnAllTerminalPaths(t *testing.T) {
	for _, kind := range []string{"eof", "block", "source-error", "close"} {
		t.Run(kind, func(t *testing.T) {
			b := testRetentionBudget(guardWorkingBytes+64000, guardWorkingBytes+64000)
			var src io.Reader = strings.NewReader("ordinary text")
			if kind == "block" {
				src = strings.NewReader("a@example.test ")
			}
			if kind == "source-error" {
				src = sourceFailure{}
			}
			g := NewGuardReaderWithOptions(src, map[IdentifierType]int{Email: 1}, Options{RetentionBudget: b})
			if kind == "close" {
				_ = g.Close()
			} else {
				_, _ = io.Copy(io.Discard, g)
			}
			if s := b.Status(); s.UsedBytes != 0 || s.ActiveGuards != 0 {
				t.Fatalf("%s leaked: %+v", kind, s)
			}
			_ = g.Close()
		})
	}
}

func TestRetentionConfigurationKeepsProtectionEnabled(t *testing.T) {
	p, total, err := retentionLimits(0, 0)
	if err != nil || p != DefaultRetentionPerStreamBytes || total != DefaultRetentionProcessBytes {
		t.Fatal("zero disabled protection")
	}
	for _, v := range [][2]int64{{-1, 0}, {1, 0}, {2 << 20, 1 << 20}, {0, -1}} {
		if _, _, err := retentionLimits(v[0], v[1]); err == nil {
			t.Fatal("invalid resource limits accepted")
		}
	}
	g := NewGuardReader(strings.NewReader("body"), nil)
	if g.lease == nil || g.lease.budget != DefaultRetentionBudget() {
		t.Fatal("default constructor bypassed shared budget")
	}
	_ = g.Close()
}

func TestSpillAbruptExitLeavesNoBodyFile(t *testing.T) {
	if os.Getenv("DSSE_DLP_SPILL_EXIT_CHILD") == "1" {
		s, err := newEncryptedSpill(0)
		if err != nil {
			os.Exit(2)
		}
		if err := s.append([]byte("private synthetic body")); err != nil {
			os.Exit(3)
		}
		os.Exit(0) // Deliberately bypass Close/defer, like abrupt process death.
	}
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSpillAbruptExitLeavesNoBodyFile$")
	cmd.Env = append(os.Environ(), "DSSE_DLP_SPILL_EXIT_CHILD=1", "TMPDIR="+dir, "TMP="+dir, "TEMP="+dir)
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			t.Errorf("body file survived process exit: %s", filepath.Base(path))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
