package revocation

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

var ErrInvalidRiskSnapshot = errors.New("invalid risk snapshot")

// Decode every object explicitly: encoding/json otherwise accepts duplicate
// keys, case aliases and null values, silently dropping or weakening marks.
func riskSnapshotObject(data []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, ErrInvalidRiskSnapshot
	}
	rows := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, ErrInvalidRiskSnapshot
		}
		if _, duplicate := rows[key]; duplicate {
			return nil, ErrInvalidRiskSnapshot
		}
		var raw json.RawMessage
		if err := d.Decode(&raw); err != nil {
			return nil, ErrInvalidRiskSnapshot
		}
		rows[key] = raw
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, ErrInvalidRiskSnapshot
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalidRiskSnapshot
	}
	return rows, nil
}

func riskSnapshotString(data []byte) (string, error) {
	var value *string
	if err := json.Unmarshal(data, &value); err != nil || value == nil {
		return "", ErrInvalidRiskSnapshot
	}
	return *value, nil
}

func decodeRiskSnapshot(data []byte) (highRiskOverlayStateFile, error) {
	f := highRiskOverlayStateFile{Devices: map[string]string{}, Users: map[string]UserRisk{}}
	invalid := func() (highRiskOverlayStateFile, error) { return highRiskOverlayStateFile{}, ErrInvalidRiskSnapshot }
	if !utf8.Valid(data) {
		return invalid()
	}
	fields, err := riskSnapshotObject(data)
	if err != nil {
		return invalid()
	}
	for key := range fields {
		if key != "schema_version" && key != "devices" && key != "users" {
			return invalid()
		}
	}
	f.SchemaVersion, err = riskSnapshotString(fields["schema_version"])
	if err != nil || (f.SchemaVersion != highRiskOverlayStateSchemaVersion && f.SchemaVersion != "high_risk_overlay_state.v1") {
		return invalid()
	}
	devices, err := riskSnapshotObject(fields["devices"])
	if err != nil {
		return invalid()
	}
	for id, raw := range devices {
		severity, err := riskSnapshotString(raw)
		if err != nil || id == "" || id != NormalizeDeviceID(id) || riskRank(severity) == 0 {
			return invalid()
		}
		f.Devices[id] = severity
	}
	if raw, present := fields["users"]; present {
		users, err := riskSnapshotObject(raw)
		if err != nil || (f.SchemaVersion == "high_risk_overlay_state.v1" && len(users) > 0) {
			return invalid()
		}
		for key, raw := range users {
			mark, err := decodeSavedUserRisk(raw)
			if err != nil || key != userRiskKey(mark.TenantID, mark.ID) {
				return invalid()
			}
			f.Users[key] = mark
		}
	}
	return f, nil
}

func decodeSavedUserRisk(data []byte) (UserRisk, error) {
	fields, err := riskSnapshotObject(data)
	if err != nil {
		return UserRisk{}, err
	}
	mark := UserRisk{}
	for key, raw := range fields {
		switch key {
		case "tenant_id":
			mark.TenantID, err = riskSnapshotString(raw)
		case "id":
			mark.ID, err = riskSnapshotString(raw)
		case "severity":
			mark.Severity, err = riskSnapshotString(raw)
		case "subjects":
			var subjects []json.RawMessage
			if json.Unmarshal(raw, &subjects) != nil || subjects == nil {
				return UserRisk{}, ErrInvalidRiskSnapshot
			}
			for _, raw := range subjects {
				s, e := riskSnapshotString(raw)
				if e != nil || s == "" || s != strings.TrimSpace(s) || strings.ContainsRune(s, '\x00') {
					return UserRisk{}, ErrInvalidRiskSnapshot
				}
				mark.Subjects = append(mark.Subjects, s)
			}
		default:
			return UserRisk{}, ErrInvalidRiskSnapshot
		}
		if err != nil {
			return UserRisk{}, ErrInvalidRiskSnapshot
		}
	}
	normalized, err := normalizeUserRisk(mark)
	if err != nil || riskRank(mark.Severity) == 0 || mark.TenantID != normalized.TenantID || mark.ID != normalized.ID {
		return UserRisk{}, ErrInvalidRiskSnapshot
	}
	return normalized, nil
}
