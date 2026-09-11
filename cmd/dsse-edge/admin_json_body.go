package main

// Admin request-body decoding. Split out of main.go: the decomposition ratchet requires new declarations to
// live in a sibling file, and a decoder whose behaviour decides whether a mistyped field is caught or dropped
// deserves its own place to be read.

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"reflect"
	"strings"
)

// decodeLimitedJSONBody decodes a size-limited JSON body, and SAYS SO when the caller sent a field this route
// does not read.
//
// ★ WHY THE WARNING EXISTS (2026-08-15). Unknown fields are dropped in silence, and twice in one session that
// silence produced a wrong result with a success code. An invite carrying {"tenant_id": "..."} answered 201
// and seated the administrator in the CALLER's organization instead. A seat allocation sent as
// {"max_devices": 25} answered 200 and set the tenant's device cap to ZERO — a typo in a field name became an
// enforcement change that blocks every enrolment, and nothing anywhere said a word.
//
// Both were found by accident. This makes the family visible instead: every dropped field is logged with the
// route that dropped it. It deliberately does NOT reject — 118 call sites take this decoder and turning
// silence into a hard 400 across all of them at once is its own outage. Routes where a dropped field changes
// enforcement or identity reject on their own terms (see the invite and seat-allocation handlers), and the
// warning is how the rest get found rather than waited for.
func decodeLimitedJSONBody(w http.ResponseWriter, r *http.Request, dst any, limit int64) error {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, dst); err != nil {
		return err
	}
	warnUnknownJSONBodyFields(r, body, dst)
	return nil
}

// warnUnknownJSONBodyFields re-decodes the same bytes strictly, into a throwaway of the same type, purely to
// find out whether anything was dropped. Best-effort by construction: it never changes what the handler sees
// and never fails a request.
func warnUnknownJSONBodyFields(r *http.Request, body []byte, dst any) {
	if len(body) == 0 || dst == nil {
		return
	}
	value := reflect.ValueOf(dst)
	if value.Kind() != reflect.Pointer || value.IsNil() || value.Elem().Kind() != reflect.Struct {
		return // maps and slices have no fixed field set, so nothing can be "unknown"
	}
	probe := reflect.New(value.Elem().Type()).Interface()
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(probe); err != nil && strings.Contains(err.Error(), "unknown field") {
		log.Printf("WARNING: %s %s — the request body carried a field this route does not read, and it was "+
			"DROPPED: %v. The call will answer as if it had been applied.", r.Method, r.URL.Path, err)
	}
}
