package main

import (
	"flag"
	"time"
)

// Keep new archive configuration outside main.go's flag-definition ratchet.
func coldArchiveAuthModeFlag() *string {
	return flag.String("cold-archive-auth-mode", "static", "external archive credentials: static or iam")
}

func coldArchiveAlertAfterFlag() *time.Duration {
	return flag.Duration("cold-archive-alert-after", 2*time.Hour, "alert when rows remain due for archival this long; defaults to two hourly sweeps")
}
