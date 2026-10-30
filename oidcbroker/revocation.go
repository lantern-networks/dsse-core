package oidcbroker

import (
	"fmt"
	"time"
)

// Token issue time, callback time and grant mint time are not authentication
// time. No clock-skew allowance may make a pre-revocation authentication fresh.
func ValidateAuthenticationAfter(authTime string, after, now time.Time) error {
	if after.IsZero() {
		return nil
	}
	auth, err := time.Parse(time.RFC3339, authTime)
	if err != nil || auth.Unix() <= 0 || !auth.After(after) || auth.After(now) {
		return fmt.Errorf("fresh authentication after administrator revocation is required")
	}
	return nil
}
