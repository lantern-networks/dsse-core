// Package strictjson checks integrity properties that encoding/json's normal
// last-key-wins object decoding does not enforce for authorization snapshots.
package strictjson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// RejectDuplicateKeys rejects any JSON object containing the same decoded key
// twice, including keys nested in records or metadata. A later duplicate may
// otherwise replace a saved deny or disabled policy during restoration.
func RejectDuplicateKeys(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := walkValue(dec); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}

// RejectUnknownFields requires an object's field spellings to match the JSON
// tags of exemplar exactly. encoding/json otherwise accepts case variants such
// as Enabled for enabled and silently lets the later alias override a deny.
func RejectUnknownFields(data []byte, exemplar any) error {
	typ := reflect.TypeOf(exemplar)
	if typ == nil || typ.Kind() != reflect.Struct {
		return fmt.Errorf("JSON schema must be a struct")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if fields == nil {
		return fmt.Errorf("JSON object is required")
	}
	allowed := make(map[string]struct{}, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		allowed[name] = struct{}{}
	}
	for name := range fields {
		if _, ok := allowed[name]; !ok {
			return fmt.Errorf("unexpected JSON field")
		}
	}
	return nil
}

func walkValue(dec *json.Decoder) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("invalid JSON object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key")
			}
			seen[key] = struct{}{}
			if err := walkValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	case '[':
		for dec.More() {
			if err := walkValue(dec); err != nil {
				return err
			}
		}
		_, err = dec.Token()
		return err
	default:
		return fmt.Errorf("unexpected JSON delimiter")
	}
}
