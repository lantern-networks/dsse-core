package main

import "context"

// Observations may originate from background capture or data-plane requests.
// Preserve an existing request term; otherwise capture at observation admission.
func candidateWriteContext(ctx context.Context) context.Context {
	if _, ok := ctx.Value(cpWriteLeaseKey{}).(cpWriteLease); ok {
		return ctx
	}
	return captureCPWriteLease(ctx)
}
