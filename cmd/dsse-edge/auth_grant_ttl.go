package main

import "time"

// Policy grant lifetime is separate from IdP auth_time freshness. Its clock
// starts at issuance, and fractional, non-positive or overflowing caps deny.
func validAuthGrantTTLSeconds(seconds int64) bool {
	return seconds > 0 && seconds <= int64((1<<63-1)/int64(time.Second))
}

func authGrantWithinTTL(issuedAt string, seconds int64, now time.Time) bool {
	if !validAuthGrantTTLSeconds(seconds) {
		return false
	}
	issued, err := time.Parse(time.RFC3339, issuedAt)
	return err == nil && !issued.After(now) && now.Before(issued.Add(time.Duration(seconds)*time.Second))
}
