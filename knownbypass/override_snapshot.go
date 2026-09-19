package knownbypass

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

// ErrInvalidSnapshot deliberately excludes tenant IDs and saved override content.
var ErrInvalidSnapshot = errors.New("invalid catalog override snapshot")

func decodeOverrideSnapshot(data []byte) (map[string]map[string]Override, error) {
	if !utf8.Valid(data) {
		return nil, ErrInvalidSnapshot
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := overrideJSONValue(decoder); err != nil {
		return nil, ErrInvalidSnapshot
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrInvalidSnapshot
	}
	var raw map[string]map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil || raw == nil {
		return nil, ErrInvalidSnapshot
	}
	result := make(map[string]map[string]Override, len(raw))
	for tenant, rows := range raw {
		if tenant == "" || strings.TrimSpace(tenant) != tenant || rows == nil {
			return nil, ErrInvalidSnapshot
		}
		result[tenant] = make(map[string]Override, len(rows))
		for id, body := range rows {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
				return nil, ErrInvalidSnapshot
			}
			// All override fields are strings. Check canonical names and null explicitly;
			// encoding/json otherwise accepts case aliases and null string values.
			for name, value := range fields {
				if name != "entry_id" && name != "mode" && name != "reason" && name != "updated_at" {
					return nil, ErrInvalidSnapshot
				}
				var field any
				if err := json.Unmarshal(value, &field); err != nil {
					return nil, ErrInvalidSnapshot
				}
				if _, ok := field.(string); !ok {
					return nil, ErrInvalidSnapshot
				}
			}
			var o Override
			if err := json.Unmarshal(body, &o); err != nil || o.EntryID != id || !validStoredOverride(o) {
				return nil, ErrInvalidSnapshot
			}
			result[tenant][id] = o
		}
	}
	return result, nil
}

func validStoredOverride(o Override) bool {
	if o.EntryID == "" || strings.TrimSpace(o.EntryID) != o.EntryID || !utf8.ValidString(o.EntryID) || !utf8.ValidString(o.Reason) {
		return false
	}
	if o.Mode != OverrideForceInspect && o.Mode != OverrideDisabled {
		return false
	}
	// Attribution time was optional in the original format. Retain an absent time,
	// rather than inventing one; when present, it must parse without normalization.
	if o.UpdatedAt != "" {
		if _, err := time.Parse(time.RFC3339, o.UpdatedAt); err != nil {
			return false
		}
	}
	return true
}

// Reject duplicate keys before maps or structs can discard them. Names in the
// organization and entry maps remain case-sensitive, as they are during writes.
func overrideJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	if delim != '{' && delim != '[' {
		return ErrInvalidSnapshot
	}
	seen := map[string]bool{}
	for decoder.More() {
		if delim == '{' {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := token.(string)
			if !ok || seen[name] {
				return ErrInvalidSnapshot
			}
			seen[name] = true
		}
		if err := overrideJSONValue(decoder); err != nil {
			return err
		}
	}
	_, err = decoder.Token()
	return err
}
