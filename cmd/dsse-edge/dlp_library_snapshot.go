package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Existing snapshots require their complete collection. A missing file is
// handled separately by the caller; {} or null must never become an empty library.
func decodeDLPLibrarySnapshot(data []byte, key string, target any) error {
	invalid := fmt.Errorf("invalid DLP %s snapshot", key)
	var shape map[string]json.RawMessage
	if json.Unmarshal(data, &shape) != nil || len(shape) != 1 || shape[key] == nil || bytes.Equal(bytes.TrimSpace(shape[key]), []byte("null")) {
		return invalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(target) != nil {
		return invalid // Do not include stored names, patterns or values in logs.
	}
	return nil
}

func validDLPLibraryTenant(tenant string) bool {
	return tenant != "" && strings.TrimSpace(tenant) == tenant && !strings.ContainsRune(tenant, '\x00')
}
