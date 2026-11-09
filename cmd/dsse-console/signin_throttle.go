package main

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/lantern-networks/dsse-core/frontdoor"
	"github.com/lantern-networks/dsse-core/runtimequota"
)

// signin_throttle.go — the Console is the door an administrator's browser actually knocks on, so it is where
// "too many attempts from one address" can be judged per browser (review R2). The control plane behind it sees
// every proxied attempt arrive from the Console and judges per source AND account; this bound is the one
// keyed on the person's own address, recovered from the front door's PROXY protocol header.

// signInPaths are the routes a credential or activation token travels on.
func isSignInPath(p string) bool {
	return strings.HasPrefix(p, "/admin/login/") || p == "/admin/activate" || strings.HasPrefix(p, "/admin/activate/")
}

// newSignInThrottle sizes the bound from the environment: SIGNIN_REQUESTS_PER_SECOND (default 5, 0 = off)
// and SIGNIN_BURST (default 20).
func newSignInThrottle() *frontdoor.TokenBucket {
	rps, burst := float64(5), float64(20)
	if strings.TrimSpace(os.Getenv("SIGNIN_REQUESTS_PER_SECOND")) != "" {
		rps = runtimequota.Rate("SIGNIN_REQUESTS_PER_SECOND")
		burst = rps
	}
	if strings.TrimSpace(os.Getenv("SIGNIN_BURST")) != "" {
		burst = runtimequota.Rate("SIGNIN_BURST")
	}
	if burst < 1 {
		burst = 1
	}
	if rps <= 0 {
		return nil
	}
	return frontdoor.NewTokenBucket(rps, burst)
}

// signInThrottled answers 429 to a browser address that is trying the sign-in routes faster than a person
// does, and passes everything else through untouched.
func signInThrottled(limiter *frontdoor.TokenBucket, next http.Handler) http.Handler {
	if limiter == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSignInPath(r.URL.Path) {
			source := frontdoor.ClientIP(r, nil)
			if !limiter.Allow(source) {
				log.Printf("admin console: sign-in attempts from %s throttled on %s", source, r.URL.Path)
				w.Header().Set("Retry-After", "1")
				w.Header().Set("Cache-Control", "no-store")
				http.Error(w, "too many sign-in attempts from this address; wait a moment and try again", http.StatusTooManyRequests)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
