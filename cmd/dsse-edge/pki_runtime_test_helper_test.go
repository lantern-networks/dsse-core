package main

import "context"

type pkiRuntimeLeaseGate struct {
	postgresBlobPersister
	before func()
}

func (p *pkiRuntimeLeaseGate) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	if p.before != nil {
		p.before()
	}
	return p.postgresBlobPersister.UpdateContext(ctx, edit)
}
