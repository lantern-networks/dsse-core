package nhi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/lantern-networks/dsse-core/model"
)

var errInvalidSnapshot = errors.New("invalid non-human identity registry snapshot")

// A missing snapshot is nil, handled by SetPersister. An existing snapshot must
// explicitly contain its registry. Otherwise null or a duplicate field could
// empty it and make the optional-registry enforcement path permissive.
func decodeRegistrySnapshot(raw []byte) (registryPersistSnapshot, error) {
	snapshot := registryPersistSnapshot{Identities: map[string]model.NonHumanIdentity{}}
	fields, err := registryObject(raw)
	if err != nil || len(fields) != 1 || fields["identities"] == nil {
		return snapshot, errInvalidSnapshot
	}
	rows, err := registryObject(fields["identities"])
	if err != nil {
		return snapshot, err
	}
	for key, raw := range rows {
		fields, err := registryObject(raw)
		if err != nil {
			return snapshot, err
		}
		for field := range fields {
			if field != strings.ToLower(field) {
				return snapshot, errInvalidSnapshot
			}
		}
		var identity model.NonHumanIdentity
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if err := d.Decode(&identity); err != nil {
			return snapshot, errInvalidSnapshot
		}
		// Attribution is from the row, including legacy bare-ID map keys.
		if identity.ID != strings.TrimSpace(identity.ID) || identity.TenantID != strings.TrimSpace(identity.TenantID) {
			return snapshot, errInvalidSnapshot
		}
		snapshot.Identities[key] = identity
	}
	return snapshot, nil
}

func registryObject(raw []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, errInvalidSnapshot
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, errInvalidSnapshot
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, errInvalidSnapshot
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, errInvalidSnapshot
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, errInvalidSnapshot
		}
		fields[key] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') {
		return nil, errInvalidSnapshot
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errInvalidSnapshot
	}
	return fields, nil
}
