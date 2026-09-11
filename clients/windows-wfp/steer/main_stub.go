//go:build !windows

// This binary targets Windows (WFP). On other platforms it builds to a no-op so the module's
// `go build ./...` stays green; the real entrypoint is in main_windows.go.
package main

func main() {}
