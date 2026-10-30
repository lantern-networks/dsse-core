package main

import (
	"errors"
	"log"
	"net/http"

	"github.com/lantern-networks/dsse-core/hotstore"
)

// Hot-store failures carry the store host, ClickHouse's own error text, and
// sometimes the query that failed. None of that belongs in an API response:
// it names internal endpoints and can repeat another request's search terms.
// The detail goes to the server log; the caller gets a fixed message.
var (
	errLogStoreUnavailable   = errors.New("log store unavailable")
	errLogStoreRequestFailed = errors.New("log store request failed")
	errLogSearchFailed       = errors.New("log search failed")
	errHotStoreNotConfigured = errors.New("hot store is not configured")
)

// publicHotStoreError replaces a hot-store failure with a fixed message and
// a server-side status. Other errors pass through unchanged.
func publicHotStoreError(status int, err error) (int, error) {
	var clickHouseErr *hotstore.ClickHouseHTTPError
	switch {
	case errors.Is(err, hotstore.ErrUnavailable):
		log.Printf("admin api: %v", err)
		return http.StatusServiceUnavailable, errLogStoreUnavailable
	case errors.As(err, &clickHouseErr):
		log.Printf("admin api: %v", err)
		return http.StatusBadGateway, errLogStoreRequestFailed
	}
	return status, err
}

// adminLogQueryInputError marks a search request the caller can correct. Its
// message describes the caller's own input.
type adminLogQueryInputError struct{ err error }

func (e adminLogQueryInputError) Error() string { return e.err.Error() }

func (e adminLogQueryInputError) Unwrap() error { return e.err }

// adminLogSearchResponseError decides what a log search route returns. Only
// errors about the caller's input keep their message; a store failure, or any
// failure not recognized here, is logged and answered with a fixed message.
func adminLogSearchResponseError(err error) (int, error) {
	var unknownStream unknownAdminLogStreamError
	var input adminLogQueryInputError
	switch {
	case errors.As(err, &unknownStream):
		return http.StatusNotFound, err
	case errors.As(err, &input), errors.Is(err, hotstore.ErrInvalidQuery):
		return http.StatusBadRequest, err
	case errors.Is(err, errHotStoreNotConfigured):
		return http.StatusServiceUnavailable, err
	}
	if status, public := publicHotStoreError(0, err); status != 0 {
		return status, public
	}
	log.Printf("admin api: log search: %v", err)
	return http.StatusInternalServerError, errLogSearchFailed
}
