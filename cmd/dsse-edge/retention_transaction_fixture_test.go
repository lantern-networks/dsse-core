package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
)

type retentionTransactionFixture struct {
	mu         sync.Mutex
	raw        []byte
	failCommit bool
}

func (p *retentionTransactionFixture) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return bytes.Clone(p.raw), nil
}
func (p *retentionTransactionFixture) Save(raw []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.raw = bytes.Clone(raw)
	return nil
}
func (p *retentionTransactionFixture) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	next, err := edit(bytes.Clone(p.raw))
	if err == nil && p.failCommit {
		return fmt.Errorf("commit rejected")
	}
	if err == nil {
		p.raw = bytes.Clone(next)
	}
	return err
}

type retentionTermBody struct {
	*strings.Reader
	before func()
}

func (b *retentionTermBody) Read(p []byte) (int, error) {
	if b.before != nil {
		f := b.before
		b.before = nil
		f()
	}
	return b.Reader.Read(p)
}
func (b *retentionTermBody) Close() error { return nil }
