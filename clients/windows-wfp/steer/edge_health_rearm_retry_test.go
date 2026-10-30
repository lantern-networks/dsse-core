package main

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestEdgeHealthMonitorRetriesFailedLocalRearm(t *testing.T) {
	h := newEdgeHealth(1, time.Hour)
	var disarmed atomic.Bool
	disarmed.Store(true)
	var attempts atomic.Int32
	stop := make(chan struct{})
	defer close(stop)
	go runEdgeHealthMonitor(stop, h, func() bool { return true }, 5*time.Millisecond, 0,
		&disarmed, nil, func() {
			if attempts.Add(1) == 2 {
				disarmed.Store(false)
			}
		})
	deadline := time.After(time.Second)
	for disarmed.Load() {
		select {
		case <-deadline:
			t.Fatalf("local rearm was not retried; attempts=%d", attempts.Load())
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if attempts.Load() != 2 {
		t.Fatalf("rearm calls=%d, want retry after the first failure", attempts.Load())
	}
}
