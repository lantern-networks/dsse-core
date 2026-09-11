//go:build windows

package logs

import (
	"os"
	"syscall"
)

// openAppendLogFile opens (creating if absent) a log file for appending WITH FILE_SHARE_DELETE. Go's
// os.OpenFile shares read+write but not delete on Windows, so every long-lived cached append handle made
// rename/remove of that file fail ("being used by another process") — breaking size-based rotation while
// the writer holds its own handle, and breaking any cleanup (test TempDirs, retention sweeps) done while
// the Edge is running. Sharing delete matches POSIX semantics: the file can be renamed or marked for
// deletion while this handle stays valid.
func openAppendLogFile(path string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	// Access/share flags mirror what Go's syscall.Open produces for O_CREATE|O_WRONLY|O_APPEND
	// (FILE_APPEND_DATA access, read+write sharing, OPEN_ALWAYS) with exactly one addition:
	// FILE_SHARE_DELETE.
	h, err := syscall.CreateFile(
		p,
		syscall.FILE_APPEND_DATA,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil,
		syscall.OPEN_ALWAYS,
		syscall.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}
