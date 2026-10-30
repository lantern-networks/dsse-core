package main

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRecoverWaitsForObservedStoppedState(t *testing.T) {
	queries := 0
	err := waitForServiceStopped(context.Background(), func() (uint32, error) {
		queries++
		if queries < 3 {
			return 3, nil
		} // STOP_PENDING is not stopped
		return 1, nil
	}, 1)
	if err != nil || queries != 3 {
		t.Fatalf("stop was accepted before observed STOPPED: queries=%d err=%v", queries, err)
	}
}

func TestRecoverRefusesUnconfirmedServiceStop(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if err := waitForServiceStopped(ctx, func() (uint32, error) { return 3, nil }, 1); err == nil {
		t.Fatal("STOP_PENDING was treated as a completed stop")
	}
	want := errors.New("status unavailable")
	if err := waitForServiceStopped(context.Background(), func() (uint32, error) { return 0, want }, 1); !errors.Is(err, want) {
		t.Fatalf("query failure lost: %v", err)
	}
}
