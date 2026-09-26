package enrolledinventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"unicode/utf8"
)

// ErrInventoryLoad omits backend details, identities and saved contents.
var ErrInventoryLoad = errors.New("cannot read enrolled inventory snapshot")

func inventoryObject(raw []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, ErrInventoryLoad
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, ErrInventoryLoad
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || fields[key] != nil {
			return nil, ErrInventoryLoad
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, ErrInventoryLoad
		}
		fields[key] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrInventoryLoad
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInventoryLoad
	}
	return fields, nil
}

func inventoryRow(raw []byte, allowed string, required []string, dst any) error {
	fields, err := inventoryObject(raw)
	if err != nil {
		return err
	}
	for key, value := range fields {
		if !slices.Contains(strings.Fields(allowed), key) || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return ErrInventoryLoad
		}
	}
	for _, key := range required {
		if fields[key] == nil {
			return ErrInventoryLoad
		}
	}
	if json.Unmarshal(raw, dst) != nil {
		return ErrInventoryLoad
	}
	return nil
}

// Decode before publishing either collection. Omitted groups are the historical
// writer's encoding of an empty registry; they must clear a previously held one.
func decodeInventorySnapshot(raw []byte) (stateFile, error) {
	f := stateFile{Entries: map[string]Entry{}, Groups: map[string]Group{}}
	invalid := func() (stateFile, error) { return stateFile{}, ErrInventoryLoad }
	fields, err := inventoryObject(raw)
	if err != nil {
		return invalid()
	}
	for key := range fields {
		if key != "schema_version" && key != "entries" && key != "groups" {
			return invalid()
		}
	}
	if version, exists := fields["schema_version"]; exists {
		if bytes.Equal(version, []byte("null")) || json.Unmarshal(version, &f.SchemaVersion) != nil ||
			(f.SchemaVersion != enrolledInventoryStateSchemaVersion && f.SchemaVersion != enrolledInventoryStateSchemaVersionV1) {
			return invalid()
		}
	}
	entries, err := inventoryObject(fields["entries"])
	if err != nil {
		return invalid()
	}
	for key, raw := range entries {
		var entry Entry
		if inventoryRow(raw, "identity enabled tenant_id group note enrolled_at updated_at device_enrolled_at reenrolment_nonce device_enrolled_nonce removed_at kind machine_ref", []string{"identity", "enabled"}, &entry) != nil ||
			key == "" || key != NormalizeIdentity(key) || entry.Identity != key || !ValidKind(entry.Kind) ||
			entry.ReenrolmentNonce < 0 || entry.DeviceEnrolledNonce < 0 || (entry.isTombstone() && entry.Enabled) {
			return invalid()
		}
		if f.SchemaVersion != enrolledInventoryStateSchemaVersion && strings.TrimSpace(entry.DeviceEnrolledAt) == "" {
			entry.DeviceEnrolledAt = migratedDeviceEnrolmentSentinel
		}
		f.Entries[key] = entry
	}
	if raw, exists := fields["groups"]; exists {
		groups, err := inventoryObject(raw)
		if err != nil {
			return invalid()
		}
		for key, raw := range groups {
			var group Group
			if inventoryRow(raw, "id tenant_id name description risk created_at updated_at", []string{"id", "name"}, &group) != nil ||
				strings.TrimSpace(key) == "" || group.ID != key || strings.TrimSpace(group.Name) == "" {
				return invalid()
			}
			f.Groups[key] = group
		}
	}
	return f, nil
}
