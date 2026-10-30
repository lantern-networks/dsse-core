package dlp

import (
	"fmt"
	"sync"
)

const (
	DefaultRetentionPerStreamBytes int64 = 64 << 20
	DefaultRetentionProcessBytes   int64 = 512 << 20
	// Covers the bounded body buffers: read/hold/ready, authenticated plaintext,
	// ciphertext/frame construction and in-place compaction, including capacity
	// growth. It does not claim to bound classifier metadata or total process RSS.
	guardWorkingBytes int64 = 512 << 10
)

// ErrRetentionLimit refuses only the upload whose undecided body cannot fit.
// It is not a content finding or a request to authenticate again.
var ErrRetentionLimit = fmt.Errorf("dlp: undecided body retention limit: %w", ErrInspectionFailed)

// RetentionBudget is shared by every streaming guard in an Edge process.
// Accounting includes actual encrypted file bytes, even consumed frames until
// truncation succeeds, and a conservative reservation for body working buffers.
type RetentionBudget struct {
	mu                                           sync.Mutex
	perStream, process, used, active, unreleased int64
}

type RetentionStatus struct {
	PerStreamBytes       int64 `json:"per_stream_bytes"`
	ProcessBytes         int64 `json:"process_bytes"`
	WorkingBytesPerGuard int64 `json:"working_bytes_per_guard"`
	UsedBytes            int64 `json:"used_bytes"`
	ActiveGuards         int64 `json:"active_guards"`
	UnreleasedBytes      int64 `json:"unreleased_bytes"`
}

var processRetention = &RetentionBudget{perStream: DefaultRetentionPerStreamBytes, process: DefaultRetentionProcessBytes}

// DefaultRetentionBudget also serves constructors without explicit Options.
func DefaultRetentionBudget() *RetentionBudget { return processRetention }

func retentionLimits(perStream, process int64) (int64, int64, error) {
	if perStream == 0 {
		perStream = DefaultRetentionPerStreamBytes
	}
	if process == 0 {
		process = DefaultRetentionProcessBytes
	}
	if perStream < guardWorkingBytes || process < perStream {
		return 0, 0, fmt.Errorf("DLP retention requires per-stream >= %d and process >= per-stream; zero selects protected defaults", guardWorkingBytes)
	}
	return perStream, process, nil
}

// ConfigureProcessRetention is a startup setting. Updating the same object
// ensures default constructors and both SWG entry paths share the effective
// process budget. Zero selects defaults; there is no unprotected setting.
func ConfigureProcessRetention(perStream, process int64) (*RetentionBudget, error) {
	perStream, process, err := retentionLimits(perStream, process)
	if err != nil {
		return nil, err
	}
	b := processRetention
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used != 0 {
		return nil, fmt.Errorf("DLP retention cannot be reconfigured while resources are held")
	}
	b.perStream, b.process = perStream, process
	return b, nil
}

func (b *RetentionBudget) Status() RetentionStatus {
	if b == nil {
		b = processRetention
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return RetentionStatus{b.perStream, b.process, guardWorkingBytes, b.used, b.active, b.unreleased}
}

type retentionLease struct {
	budget  *RetentionBudget
	disk    int64
	working bool
}

func (b *RetentionBudget) acquire() (*retentionLease, error) {
	if b == nil {
		b = processRetention
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if guardWorkingBytes > b.perStream || guardWorkingBytes > b.process-b.used {
		return nil, ErrRetentionLimit
	}
	b.used += guardWorkingBytes
	b.active++
	return &retentionLease{budget: b, working: true}, nil
}

func (l *retentionLease) reserveDisk(n int64) error {
	if l == nil {
		return ErrRetentionLimit
	}
	b := l.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	if n < 0 || !l.working || n > b.perStream-guardWorkingBytes-l.disk || n > b.process-b.used {
		return ErrRetentionLimit
	}
	l.disk += n
	b.used += n
	return nil
}

func (l *retentionLease) releaseDisk(n int64) {
	if l == nil {
		return
	}
	b := l.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	l.disk -= n
	b.used -= n
}

func (l *retentionLease) releaseWorking() {
	if l == nil {
		return
	}
	b := l.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	if l.working {
		l.working = false
		b.used -= guardWorkingBytes
		b.active--
		// A cleanup failure must not make unreclaimed disk available for reuse.
		b.unreleased += l.disk
	}
}
