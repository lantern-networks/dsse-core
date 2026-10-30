package main

import "time"

// This IdP request bound is distinct from policy max_age=0, which authorizes
// only one held request. A successful post-revocation login may issue a normal
// reusable grant. Later SSO remains usable if its auth_time is after the fence.
func authenticationAgeAfterRevocation(policy *int64, after, now time.Time) *int64 {
	if after.IsZero() {
		return policy
	}
	age := int64(now.Sub(after) / time.Second)
	if age < 0 {
		age = 0
	}
	if age > 86400 {
		age = 86400
	}
	if policy != nil && *policy < age {
		age = *policy
	}
	return &age
}
