package main

import (
	"context"
	"sync"
)

// cpWriterMutex serializes use and release of the advisory-lock session. Its
// zero value is usable. A queued write may leave on cancellation without touching
// the SQL session owned by the current writer.
type cpWriterMutex struct {
	once sync.Once
	held chan struct{}
}

func (m *cpWriterMutex) LockContext(ctx context.Context) error {
	m.once.Do(func() { m.held = make(chan struct{}, 1) })
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case m.held <- struct{}{}:
		if err := ctx.Err(); err != nil {
			m.Unlock()
			return err
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (m *cpWriterMutex) Lock() { _ = m.LockContext(context.Background()) }
func (m *cpWriterMutex) Unlock() {
	select {
	case <-m.held:
	default:
		panic("unlock of unlocked CP writer mutex")
	}
}
