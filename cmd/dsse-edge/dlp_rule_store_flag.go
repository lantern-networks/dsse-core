package main

import "flag"

// Keep new flag definitions outside main.go's decomposition ratchet while
// registering the same operator-facing flag before flag.Parse.
func registerDLPRuleStoreFlag() *string {
	return flag.String("dlp-rule-store", "", "durable store for admin-authored egress DLP rules (/admin/dlp-rules); restored on boot and distributed in the signed fleet bundle. Empty derives from state-dir when configured; otherwise in-memory. Accepts \"postgres\" or a file path")
}
