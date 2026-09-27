package main

import (
	"context"
	"time"

	"github.com/lantern-networks/dsse-core/enrolltoken"
)

func issueEnrolmentToken(ctx context.Context, tokens enrolltoken.Authority, policy enrolltoken.Policy, tenant, group, label, issuedBy, issuedByLabel string, expires, now time.Time) (enrolltoken.Token, string, error) {
	if checked, ok := tokens.(interface {
		IssueContext(context.Context, enrolltoken.Policy, string, string, string, string, string, time.Time, time.Time) (enrolltoken.Token, string, error)
	}); ok {
		return checked.IssueContext(ctx, policy, tenant, group, label, issuedBy, issuedByLabel, expires, now)
	}
	return tokens.Issue(policy, tenant, group, label, issuedBy, issuedByLabel, expires, now)
}
func spendEnrolmentToken(ctx context.Context, tokens enrolltoken.Authority, id, tenant, device string, now time.Time) (enrolltoken.Token, error) {
	if checked, ok := tokens.(interface {
		SpendContext(context.Context, string, string, string, time.Time) (enrolltoken.Token, error)
	}); ok {
		return checked.SpendContext(ctx, id, tenant, device, now)
	}
	return tokens.Spend(id, tenant, device, now)
}
