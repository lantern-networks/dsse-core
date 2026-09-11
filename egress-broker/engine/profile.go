package engine

import (
	"os"
	"strings"
)

// defaultImpersonateProfile is the SINGLE source for which Chrome the engine impersonates.
//
// It used to be stated in three places — this constant, the README, and a compose comment — and on
// 2026-08-04 they disagreed: the code said chrome116 while the docs said chrome146, the environment
// override was unset, and the stale one is the one that ran. Every decrypt-all flow went out with a
// Chrome-149 User-Agent over a Chrome-116 TLS/H2 stack, which is precisely the inconsistency this engine
// exists to remove. The contract test in this package fails when the code, the Dockerfiles and the README
// stop naming the same profile, so that disagreement cannot recur silently.
const defaultImpersonateProfile = "curl_chrome146"

// ImpersonateBinary is the curl-impersonate profile to re-originate with — the CLI binary name, which is
// also the profile identifier with a `curl_` prefix. Override via EGRESS_IMPERSONATE_BIN to keep the engine
// in step with the real Chrome generation the fleet runs; a profile that lags the fleet is itself a signal.
func ImpersonateBinary() string {
	if b := strings.TrimSpace(os.Getenv("EGRESS_IMPERSONATE_BIN")); b != "" {
		return b
	}
	return defaultImpersonateProfile
}

// impersonateTarget is what libcurl's curl_easy_impersonate wants: the profile without the `curl_` prefix.
func impersonateTarget() string { return strings.TrimPrefix(ImpersonateBinary(), "curl_") }

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}
