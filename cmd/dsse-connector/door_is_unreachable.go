package main

import (
	"errors"
	"net"
	"os"
	"strings"
)

// doorIsUnreachable reports whether an error means the door could not be REACHED, as opposed to reached and
// refused.
//
// ★ THE DISTINCTION IS THE WHOLE POINT. A door that answers "I do not know this connector" is a fault
// re-registration fixes, and failing over would carry the connector to another region on evidence that has
// nothing to do with the region. A door that does not answer at all is a region this connector must leave.
func doorIsUnreachable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	// The transport's own words, for errors that arrive already wrapped as text by an HTTP client.
	text := strings.ToLower(err.Error())
	for _, phrase := range []string{
		"i/o timeout", "connection timed out", "connection refused", "connection reset", "no such host",
		"network is unreachable", "no route to host", "context deadline exceeded", "timeout awaiting",
	} {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}
