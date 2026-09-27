package main

import "context"

type organizationRuntimeLeaseGate struct {
	postgresBlobPersister
	before func()
}

func (p *organizationRuntimeLeaseGate) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	if p.before != nil {
		p.before()
	}
	return p.postgresBlobPersister.UpdateContext(ctx, edit)
}
