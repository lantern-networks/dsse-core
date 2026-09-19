package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

var errMeshOutboxLoad = errors.New("cannot read revocation mesh outbox snapshot")
var errMeshOutboxSnapshot = errors.New("invalid revocation mesh outbox snapshot")

// Decode the entire queue before adopting any entries. The stored format remains
// the original array; omitted legacy metadata is accepted, but null is not a string.
func decodeMeshOutboxSnapshot(data []byte) ([]revocationMeshOutboxEntry, error) {
	invalid := func() ([]revocationMeshOutboxEntry, error) { return nil, errMeshOutboxSnapshot }
	if !utf8.Valid(data) {
		return invalid()
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if v, err := d.Token(); err != nil || v != json.Delim('[') {
		return invalid()
	}
	entries := []revocationMeshOutboxEntry{}
	keys := map[string]bool{}
	for d.More() {
		if v, err := d.Token(); err != nil || v != json.Delim('{') {
			return invalid()
		}
		var e revocationMeshOutboxEntry
		fields := map[string]*string{"region": &e.Region, "url": &e.URL, "identity": &e.Identity, "reason": &e.Reason, "origin_region": &e.OriginRegion, "enqueued_at": &e.EnqueuedAt}
		seen := map[string]bool{}
		for d.More() {
			v, err := d.Token()
			name, ok := v.(string)
			if err != nil || !ok || seen[name] {
				return invalid()
			}
			seen[name] = true
			dst, ok := fields[name]
			if !ok {
				return invalid()
			}
			v, err = d.Token()
			value, ok := v.(string)
			if err != nil || !ok {
				return invalid()
			}
			*dst = value
		}
		if v, err := d.Token(); err != nil || v != json.Delim('}') {
			return invalid()
		}
		if !seen["region"] || !seen["url"] || !seen["identity"] || !canonicalMeshKey(e.Region) || !canonicalMeshIdentity(e.Identity) || !validMeshPeerURL(e.URL) {
			return invalid()
		}
		key := revocationMeshOutboxKey(e.Region, e.Identity)
		if keys[key] {
			return invalid()
		}
		keys[key] = true
		entries = append(entries, e)
	}
	if v, err := d.Token(); err != nil || v != json.Delim(']') {
		return invalid()
	}
	if _, err := d.Token(); err != io.EOF {
		return invalid()
	}
	return entries, nil
}

// Match the existing admission identity normalization; character-policy changes
// belong at every identity writer, not solely at restart.
func canonicalMeshIdentity(value string) bool {
	return value != "" && value == strings.ToLower(strings.TrimSpace(value))
}

func canonicalMeshKey(value string) bool {
	return value != "" && value == strings.ToLower(strings.TrimSpace(value)) && strings.IndexFunc(value, unicode.IsControl) < 0
}

// The sender appends a route to this base. Query, fragment and userinfo would
// alter that route or authentication; preserve HTTP loopback/lab compatibility.
func validMeshPeerURL(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return false
	}
	u, err := url.Parse(value)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" && u.User == nil && u.Opaque == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && !strings.Contains(value, "#")
}
