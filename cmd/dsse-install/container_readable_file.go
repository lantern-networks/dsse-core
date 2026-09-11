package main

import "os"

// writeContainerReadableFile publishes non-secret configuration read by a
// container running under a different UID. WriteFile's mode is filtered by the
// caller's umask; an operator using umask 077 must not make HAProxy's config or
// Patroni's public CA unreadable. Private keys and credentials do not use this.
func writeContainerReadableFile(path string, body []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(body); err != nil {
		return err
	}
	if err := f.Chmod(0o644); err != nil {
		return err
	}
	return f.Close()
}
