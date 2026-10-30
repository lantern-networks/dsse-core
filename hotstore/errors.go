package hotstore

import "errors"

// ErrUnavailable marks a request that did not get an answer from the hot
// store: the connection failed, timed out, or the response could not be read.
// The wrapped detail names the store host for server logs. HTTP handlers must
// not return it to the caller.
var ErrUnavailable = errors.New("hot store unavailable")

// ErrInvalidQuery marks a query the caller can correct, such as a cursor that
// belongs to a different query. Its message describes the caller's input and
// is safe to return.
var ErrInvalidQuery = errors.New("invalid hot store query")

type unavailableError struct {
	detail string
	cause  error
}

func (e *unavailableError) Error() string {
	if e.cause == nil {
		return "hot store unavailable: " + e.detail
	}
	return "hot store unavailable: " + e.detail + ": " + e.cause.Error()
}

func (e *unavailableError) Unwrap() error { return e.cause }

func (e *unavailableError) Is(target error) bool { return target == ErrUnavailable }

func unavailable(detail string, cause error) error {
	return &unavailableError{detail: detail, cause: cause}
}

type invalidQueryError struct{ err error }

func (e *invalidQueryError) Error() string { return e.err.Error() }

func (e *invalidQueryError) Unwrap() error { return e.err }

func (e *invalidQueryError) Is(target error) bool { return target == ErrInvalidQuery }

func invalidQuery(err error) error {
	if err == nil {
		return nil
	}
	return &invalidQueryError{err: err}
}
