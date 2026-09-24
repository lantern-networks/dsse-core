package revocation

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

// ErrInvalidAdmissionSnapshot never includes device identities or saved reasons.
var ErrInvalidAdmissionSnapshot = errors.New("invalid admission revocation snapshot")

// Decode field-by-field to reject duplicate keys, case aliases and null maps or
// reasons. Unmarshalling straight into maps/structs silently accepts those forms.
func decodeAdmissionSnapshot(data []byte) (admissionRevocationsStateFile, error) {
	f := admissionRevocationsStateFile{MeshReceived: map[string]string{}}
	invalid := func() (admissionRevocationsStateFile, error) {
		return admissionRevocationsStateFile{}, ErrInvalidAdmissionSnapshot
	}
	if !utf8.Valid(data) {
		return invalid()
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return invalid()
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		name, ok := token.(string)
		if err != nil || !ok || seen[name] {
			return invalid()
		}
		seen[name] = true
		switch name {
		case "schema_version":
			if err := d.Decode(&f.SchemaVersion); err != nil || f.SchemaVersion != admissionRevocationsStateSchemaVersion {
				return invalid()
			}
		case "revoked":
			f.Revoked, err = decodeAdmissionMap(d)
		case "mesh_received":
			f.MeshReceived, err = decodeAdmissionMap(d)
		default:
			return invalid()
		}
		if err != nil {
			return invalid()
		}
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || !seen["schema_version"] || !seen["revoked"] {
		return invalid()
	}
	if _, err := d.Token(); err != io.EOF {
		return invalid()
	}
	return f, nil
}

func decodeAdmissionMap(d *json.Decoder) (map[string]string, error) {
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, ErrInvalidAdmissionSnapshot
	}
	rows := map[string]string{}
	for d.More() {
		token, err := d.Token()
		id, ok := token.(string)
		if err != nil || !ok || id == "" || id != normalizeIdentity(id) {
			return nil, ErrInvalidAdmissionSnapshot
		}
		if _, duplicate := rows[id]; duplicate {
			return nil, ErrInvalidAdmissionSnapshot
		}
		token, err = d.Token()
		reason, ok := token.(string)
		if err != nil || !ok || reason != strings.TrimSpace(reason) {
			return nil, ErrInvalidAdmissionSnapshot
		}
		rows[id] = reason
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrInvalidAdmissionSnapshot
	}
	return rows, nil
}
