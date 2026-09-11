//go:build !windows

package logs

import "os"

// openAppendLogFile opens (creating if absent) a log file for appending. On non-Windows platforms the
// plain os.OpenFile is all that is needed; see open_windows.go for why Windows takes a different path.
func openAppendLogFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
}
