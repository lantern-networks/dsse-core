package catalogfeed

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/knownbypass"
	"github.com/lantern-networks/dsse-core/signedconfig"
)

// Do not disclose saved catalog content or signer identifiers in startup errors.
var ErrInvalidSnapshot = errors.New("invalid catalog feed snapshot")

func (s *Store) decodeSnapshot(data []byte) (snapshot, error) {
	var snap snapshot
	if err := feedJSON(data, &snap); err != nil || len(snap.History) > historyLimit {
		return snapshot{}, ErrInvalidSnapshot
	}
	if snap.Current == nil {
		if len(snap.History) != 0 {
			return snapshot{}, ErrInvalidSnapshot
		}
		return snap, nil
	}
	if len(snap.History) == 0 || s.validateApplied(*snap.Current) != nil {
		return snapshot{}, ErrInvalidSnapshot
	}
	for _, af := range snap.History {
		if s.validateApplied(af) != nil {
			return snapshot{}, ErrInvalidSnapshot
		}
	}
	// Every successful Apply/Rollback appends the exact current record. Repeated
	// catalog versions are legitimate after explicit rollback and re-application.
	current, _ := json.Marshal(snap.Current)
	last, _ := json.Marshal(snap.History[len(snap.History)-1])
	if !bytes.Equal(current, last) {
		return snapshot{}, ErrInvalidSnapshot
	}
	return snap, nil
}

func (s *Store) validateApplied(af AppliedFeed) error {
	// Expired, previously applied feeds remain last-known-good. Verify the signed
	// envelope at its expiry boundary, not at the unsigned saved AppliedAt time.
	when := time.Now().UTC()
	if af.Envelope.ExpiresAt != "" {
		expires, err := time.Parse(time.RFC3339, af.Envelope.ExpiresAt)
		if err != nil {
			return ErrInvalidSnapshot
		}
		if when.After(expires) {
			when = expires
		}
	}
	doc, err := s.validateEnvelope(af.Envelope, when)
	if err != nil {
		return ErrInvalidSnapshot
	}
	if af.CatalogVersion != doc.Version || !reflect.DeepEqual(af.Entries, doc.Entries) ||
		af.EnvelopeVersion != af.Envelope.Version || af.SigningKeyID != af.Envelope.SigningKeyID ||
		af.CreatedAt != af.Envelope.CreatedAt || af.ExpiresAt != af.Envelope.ExpiresAt {
		return ErrInvalidSnapshot
	}
	if _, err := time.Parse(time.RFC3339, af.AppliedAt); err != nil {
		return ErrInvalidSnapshot
	}
	return nil
}

func (s *Store) validateEnvelope(env signedconfig.Envelope, now time.Time) (knownbypass.CatalogDocument, error) {
	if err := signedconfig.Validate(env, FeedType, now, s.trustedKeys); err != nil {
		return knownbypass.CatalogDocument{}, err
	}
	if env.CreatedAt != "" {
		if _, err := time.Parse(time.RFC3339, env.CreatedAt); err != nil {
			return knownbypass.CatalogDocument{}, errors.New("invalid feed creation timestamp")
		}
	}
	var doc knownbypass.CatalogDocument
	if err := feedJSON(env.Payload, &doc); err != nil || doc.Version <= 0 || len(doc.Entries) == 0 {
		return knownbypass.CatalogDocument{}, errors.New("invalid feed catalog document")
	}
	ids := map[string]bool{}
	for _, entry := range doc.Entries {
		if entry.ID == "" || strings.TrimSpace(entry.ID) != entry.ID || ids[entry.ID] {
			return knownbypass.CatalogDocument{}, errors.New("invalid or duplicate feed catalog entry id")
		}
		ids[entry.ID] = true
	}
	return doc, nil
}

// Reject ambiguous object keys and unknown/alternate-case struct fields before
// encoding/json can silently discard them. Metadata keys remain extensible.
// UseNumber also preserves signed metadata integers when re-marshaling.
func feedJSON(data []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := feedJSONValue(d); err != nil {
		return ErrInvalidSnapshot
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalidSnapshot
	}
	if err := feedJSONFields(data, reflect.TypeOf(out).Elem()); err != nil {
		return err
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := d.Decode(out); err != nil {
		return ErrInvalidSnapshot
	}
	return nil
}

func feedJSONFields(data []byte, typ reflect.Type) error {
	if typ == reflect.TypeOf(json.RawMessage{}) {
		return nil // The signed payload is checked against its own document type.
	}
	if typ.Kind() == reflect.Pointer {
		if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
			return nil
		}
		return feedJSONFields(data, typ.Elem())
	}
	switch typ.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(data, &object); err != nil || object == nil {
			return ErrInvalidSnapshot
		}
		fields := map[string]reflect.Type{}
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			fields[strings.Split(field.Tag.Get("json"), ",")[0]] = field.Type
		}
		for name, value := range object {
			field, ok := fields[name]
			if !ok || feedJSONFields(value, field) != nil {
				return ErrInvalidSnapshot
			}
		}
	case reflect.Slice:
		var values []json.RawMessage
		if err := json.Unmarshal(data, &values); err != nil {
			return ErrInvalidSnapshot
		}
		for _, value := range values {
			if err := feedJSONFields(value, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

func feedJSONValue(d *json.Decoder) error {
	token, err := d.Token()
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
	for d.More() {
		if delim == '{' {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return ErrInvalidSnapshot
			}
			seen[name] = true
		}
		if err := feedJSONValue(d); err != nil {
			return err
		}
	}
	_, err = d.Token()
	return err
}
