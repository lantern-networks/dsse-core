package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

type deadlineBeforeCancellationPropagation struct {
	context.Context
	deadline time.Time
}

func (c deadlineBeforeCancellationPropagation) Deadline() (time.Time, bool) { return c.deadline, true }

func TestCPCommitChecksDeadlineWithoutWaitingForChildCancellation(t *testing.T) {
	parent := context.Background()
	child := deadlineBeforeCancellationPropagation{Context: parent, deadline: time.Now().Add(-time.Millisecond)}
	if child.Err() != nil {
		t.Fatal("fixture must represent child cancellation not yet propagated")
	}
	if e := cpWriteContextError(parent, child); !errors.Is(e, context.DeadlineExceeded) {
		t.Fatal("expired request could commit", e)
	}
	canceled, cancel := context.WithCancel(parent)
	cancel()
	if e := cpWriteContextError(canceled, parent); !errors.Is(e, context.Canceled) {
		t.Fatal("parent cancellation ignored", e)
	}
	if e := cpWriteContextError(parent, deadlineBeforeCancellationPropagation{Context: parent, deadline: time.Now().Add(time.Minute)}); e != nil {
		t.Fatal("live request rejected", e)
	}
}
