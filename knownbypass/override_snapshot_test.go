package knownbypass

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestOverrideSnapshotRejectsWholeInvalidStateAndKeepsWriter(t *testing.T) {
	valid := `{"own":{"apple_time":{"entry_id":"apple_time","mode":"disabled","updated_at":"2026-09-17T00:00:00Z","reason":"PRIVATE_SAVED_VALUE"}}}`
	cases := map[string][]byte{
		"zero-byte": {}, "whitespace": []byte(" \n"), "null": []byte(`null`), "array": []byte(`[]`), "scalar": []byte(`true`), "truncated": []byte(`{"own":`), "trailing": []byte(valid + `{}`),
		"empty-tenant": []byte(`{"":{}}`), "spaced-tenant": []byte(`{" own":{}}`), "null-tenant": []byte(`{"own":null}`), "array-tenant": []byte(`{"own":[]}`),
		"null-row": []byte(`{"own":{"apple_time":null}}`), "array-row": []byte(`{"own":{"apple_time":[]}}`), "scalar-row": []byte(`{"own":{"apple_time":"x"}}`),
		"wrong-key": []byte(strings.Replace(valid, `"own":{"apple_time":`, `"own":{"wrong":`, 1)),
		"empty-key": []byte(`{"own":{"":{"entry_id":"","mode":"disabled"}}}`), "trimmed-key": []byte(`{"own":{" apple_time":{"entry_id":" apple_time","mode":"disabled"}}}`),
		"missing-id": []byte(strings.Replace(valid, `"entry_id":"apple_time",`, "", 1)), "missing-mode": []byte(strings.Replace(valid, `"mode":"disabled",`, "", 1)),
		"invalid-mode": []byte(strings.Replace(valid, `"disabled"`, `"bypass"`, 1)), "trimmed-mode": []byte(strings.Replace(valid, `"disabled"`, `" disabled"`, 1)), "mode-case": []byte(strings.Replace(valid, `"disabled"`, `"Disabled"`, 1)),
		"duplicate-tenant": []byte(`{"own":{},"own":{}}`), "duplicate-entry": []byte(`{"own":{"x":{},"x":{}}}`),
		"duplicate-field":   []byte(strings.Replace(valid, `"mode":"disabled"`, `"mode":"force_inspect","mode":"disabled"`, 1)),
		"escaped-duplicate": []byte(`{"own":{},"\u006fwn":{}}`),
		"alias-field":       []byte(strings.Replace(valid, `"entry_id"`, `"Entry_ID"`, 1)), "unknown-field": []byte(strings.Replace(valid, `"reason"`, `"future"`, 1)),
		"invalid-time":   []byte(strings.Replace(valid, `2026-09-17T00:00:00Z`, `not-a-time`, 1)),
		"null-time":      []byte(strings.Replace(valid, `"2026-09-17T00:00:00Z"`, `null`, 1)),
		"null-reason":    []byte(strings.Replace(valid, `"PRIVATE_SAVED_VALUE"`, `null`, 1)),
		"number-reason":  []byte(strings.Replace(valid, `"PRIVATE_SAVED_VALUE"`, `123`, 1)),
		"invalid-utf8":   bytes.ReplaceAll([]byte(valid), []byte("PRIVATE_SAVED_VALUE"), []byte{0xff}),
		"mixed-good-bad": []byte(`{"other":{"apple_push":{"entry_id":"apple_push","mode":"disabled"}},"own":{"apple_time":{"entry_id":"wrong","mode":"disabled"}}}`),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			s := NewOverrideStore()
			old := &overrideTestPersister{}
			if e := s.SetPersister(old); e != nil {
				t.Fatal(e)
			}
			setTestOverride(t, s, "own", "github_asset_cdn", OverrideForceInspect)
			setTestOverride(t, s, "other", "apple_push", OverrideDisabled)
			before := sortedOverrideSnapshot(s)
			saved := bytes.Clone(old.data)
			bad := &overrideTestPersister{data: data}
			err := s.SetPersister(bad)
			if !errors.Is(err, ErrInvalidSnapshot) || err.Error() != "invalid catalog override snapshot" {
				t.Fatalf("error must exclude saved contents: %v", err)
			}
			if !reflect.DeepEqual(sortedOverrideSnapshot(s), before) || !bytes.Equal(old.data, saved) || bad.saves != 0 || s.dirty {
				t.Fatal("bad load changed state, writer or dirty bit")
			}
			setTestOverride(t, s, "own", "apple_time", OverrideDisabled)
			if bad.saves != 0 || bytes.Equal(old.data, saved) {
				t.Fatal("subsequent mutation used wrong writer")
			}
			reopened := NewOverrideStore()
			if e := reopened.SetPersister(old); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(sortedOverrideSnapshot(s), sortedOverrideSnapshot(reopened)) {
				t.Fatal("original writer lost later save")
			}
		})
	}
	t.Logf("rejected %d malformed complete snapshots", len(cases))
}

func TestOverrideSnapshotPreservesLegacyInactiveEntriesAndIdentity(t *testing.T) {
	raw := []byte(`{"own":{"inactive_feed_id":{"entry_id":"inactive_feed_id","mode":"force_inspect","reason":"preserve"},"apple_time":{"entry_id":"apple_time","mode":"disabled","updated_at":"2026-09-17T09:00:00+09:00"}},"other":{"apple_push":{"entry_id":"apple_push","mode":"disabled","updated_at":""}},"empty":{}}`)
	p := &overrideTestPersister{data: raw}
	s := NewOverrideStore()
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if p.saves != 0 || s.CountForTenant("own") != 2 || s.CountForTenant("other") != 1 {
		t.Fatal("load mutated history")
	}
	before := sortedOverrideSnapshot(s)
	if before["own"][1].UpdatedAt != "" || before["own"][0].UpdatedAt != "2026-09-17T09:00:00+09:00" {
		t.Fatal("timestamp normalized or invented", before)
	}
	entries := []Group{{ID: "inactive_feed_id", Patterns: []string{"inactive.example"}}, {ID: "apple_time", Patterns: []string{"time.example"}}}
	if len(s.EffectiveBypassHostsFrom(entries, "own")) != 0 || len(s.EffectiveBypassHostsFrom(entries, "other")) != 2 {
		t.Fatal("inactive feed override lost owner or effect")
	}
	if cleared, e := s.Clear("own", "inactive_feed_id"); e != nil || !cleared {
		t.Fatal("listed inactive entry cannot be removed", e)
	}
	reopened := NewOverrideStore()
	if e := reopened.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if len(reopened.List("own")) != 1 || reopened.List("own")[0].EntryID != "apple_time" || len(reopened.List("other")) != 1 {
		t.Fatal("clear not durable or foreign change")
	}
	if !reflect.DeepEqual(reopened.EffectiveBypassHostsFrom(entries, "own"), []string{"inactive.example"}) {
		t.Fatal("cleared entry still affects policy")
	}
}

func TestOverrideSnapshotDistinguishesEmptyMissingAndDirtyStorage(t *testing.T) {
	s := NewOverrideStore()
	p := &overrideTestPersister{}
	s.SetPersister(p)
	setTestOverride(t, s, "own", "apple_time", OverrideDisabled)
	missing := &overrideTestPersister{}
	if e := s.SetPersister(missing); e != nil {
		t.Fatal(e)
	}
	if len(s.List("own")) != 1 || missing.saves != 0 {
		t.Fatal("missing destination silently erased or persisted state")
	}
	setTestOverride(t, s, "other", "apple_push", OverrideForceInspect)
	var raw map[string]map[string]Override
	json.Unmarshal(missing.data, &raw)
	if len(raw) != 2 {
		t.Fatal("new destination missed retained state")
	}
	empty := &overrideTestPersister{data: []byte(`{}`)}
	if e := s.SetPersister(empty); e != nil || len(s.List("own")) != 0 || empty.saves != 0 {
		t.Fatal("explicit empty not adopted", e)
	}
	empty.fail = errors.New("save uncertain")
	if _, e := s.Set("own", Override{EntryID: "apple_time", Mode: OverrideDisabled}, time.Now()); !errors.Is(e, ErrPersistence) {
		t.Fatal(e)
	}
	if e := s.SetPersister(&overrideTestPersister{data: []byte(`{}`)}); !errors.Is(e, ErrPersistence) {
		t.Fatal("dirty storage replaced", e)
	}
	path := filepath.Join(t.TempDir(), "empty.json")
	if e := os.WriteFile(path, nil, 0600); e != nil {
		t.Fatal(e)
	}
	fresh := NewOverrideStore()
	if e := fresh.SetStatePath(path); !errors.Is(e, ErrInvalidSnapshot) {
		t.Fatal("existing empty file accepted", e)
	}
	if e := fresh.SetStatePath(path + ".missing"); e != nil {
		t.Fatal("missing file rejected", e)
	}
}

func TestOverrideAdmissionCannotCreateUnrestorableFields(t *testing.T) {
	cases := []struct {
		tenant string
		o      Override
		when   time.Time
	}{
		{"own", Override{EntryID: "apple_time", Mode: OverrideDisabled, Reason: string([]byte{0xff})}, time.Now()},
		{string([]byte{0xff}), Override{EntryID: "apple_time", Mode: OverrideDisabled}, time.Now()},
		{"own", Override{EntryID: "apple_time", Mode: OverrideDisabled}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		s := NewOverrideStore()
		p := &overrideTestPersister{}
		s.SetPersister(p)
		if _, e := s.Set(tc.tenant, tc.o, tc.when); e == nil {
			t.Fatal("invalid fields accepted")
		}
		if p.saves != 0 || len(s.List(tc.tenant)) != 0 {
			t.Fatal("invalid input saved")
		}
	}
	s := NewOverrideStore()
	entry := string([]byte{0xff})
	if _, e := s.SetFromCatalog("own", Override{EntryID: entry, Mode: OverrideDisabled}, []Group{{ID: entry}}, time.Now()); e == nil {
		t.Fatal("invalid UTF-8 entry accepted")
	}
}
