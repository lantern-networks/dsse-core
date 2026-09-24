package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

const meshRestoreValid = `[{"region":"peer","url":"https://peer.invalid/base","identity":"device","reason":"block","origin_region":"origin","enqueued_at":"2026-09-17T00:00:00Z"}]`

func invalidMeshSnapshots() map[string][]byte {
	row := strings.TrimSuffix(strings.TrimPrefix(meshRestoreValid, "["), "]")
	return map[string][]byte{
		"empty": {}, "whitespace": []byte(" \n"), "null": []byte("null"), "object": []byte("{}"), "truncated": []byte("["), "trailing": []byte(meshRestoreValid + "[]"),
		"null-entry": []byte("[null]"), "empty-entry": []byte("[{}]"), "partial": []byte("[" + row + ",{}]"), "duplicate-entry": []byte("[" + row + "," + row + "]"),
		"missing-region": []byte(strings.Replace(meshRestoreValid, `"region":"peer",`, "", 1)), "missing-url": []byte(strings.Replace(meshRestoreValid, `"url":"https://peer.invalid/base",`, "", 1)), "missing-identity": []byte(strings.Replace(meshRestoreValid, `"identity":"device",`, "", 1)),
		"duplicate-field": []byte(strings.Replace(meshRestoreValid, `"region":"peer"`, `"region":"old","region":"peer"`, 1)), "escaped-duplicate": []byte(strings.Replace(meshRestoreValid, `"region":"peer"`, `"region":"old","\u0072egion":"peer"`, 1)),
		"alias": []byte(strings.Replace(meshRestoreValid, `"region":`, `"Region":`, 1)), "unknown": []byte(strings.Replace(meshRestoreValid, `"region":`, `"PRIVATE_CONTENT":false,"region":`, 1)),
		"null-required": []byte(strings.Replace(meshRestoreValid, `"device"`, `null`, 1)), "null-metadata": []byte(strings.Replace(meshRestoreValid, `"block"`, `null`, 1)), "typed-metadata": []byte(strings.Replace(meshRestoreValid, `"origin"`, `3`, 1)),
		"blank-region": []byte(strings.Replace(meshRestoreValid, `"peer"`, `""`, 1)), "padded-region": []byte(strings.Replace(meshRestoreValid, `"peer"`, `" peer "`, 1)), "upper-region": []byte(strings.Replace(meshRestoreValid, `"peer"`, `"PEER"`, 1)),
		"upper-identity": []byte(strings.Replace(meshRestoreValid, `"device"`, `"DEVICE"`, 1)), "padded-identity": []byte(strings.Replace(meshRestoreValid, `"device"`, `" device "`, 1)), "nul-region": []byte(strings.Replace(meshRestoreValid, `"peer"`, `"pe\u0000er"`, 1)),
		"blank-url": []byte(strings.Replace(meshRestoreValid, `https://peer.invalid/base`, "", 1)), "invalid-url": []byte(strings.Replace(meshRestoreValid, `https://peer.invalid/base`, "%PRIVATE_CONTENT", 1)), "relative-url": []byte(strings.Replace(meshRestoreValid, `https://peer.invalid/base`, "peer.invalid/base", 1)),
		"url-auth": []byte(strings.Replace(meshRestoreValid, `https://peer.invalid/base`, "https://user:PRIVATE_CONTENT@peer.invalid", 1)), "url-query": []byte(strings.Replace(meshRestoreValid, `https://peer.invalid/base`, "https://peer.invalid?PRIVATE_CONTENT", 1)), "url-fragment": []byte(strings.Replace(meshRestoreValid, `https://peer.invalid/base`, "https://peer.invalid#PRIVATE_CONTENT", 1)),
		"invalid-utf8": append([]byte(meshRestoreValid[:len(meshRestoreValid)-2]), 0xff, '}', ']'),
	}
}

func TestMeshSnapshotRefusesWholeInvalidQueue(t *testing.T) {
	for name, data := range invalidMeshSnapshots() {
		t.Run(name, func(t *testing.T) {
			p := &meshOutboxTestPersister{data: data}
			o, err := newRevocationMeshOutbox(p)
			if o != nil || err != errMeshOutboxSnapshot || p.count() != 0 || !bytes.Equal(data, p.data) {
				t.Fatal("invalid queue adopted, rewritten, or error disclosed", o, err)
			}
		})
	}
}

type meshRestoreLoadFailure struct{}

func (meshRestoreLoadFailure) Load() ([]byte, error) {
	return nil, errors.New("PRIVATE_CONTENT backend path")
}
func (meshRestoreLoadFailure) Save([]byte) error { panic("must not write after load failure") }
func TestMeshSnapshotLoadFailureIsGeneric(t *testing.T) {
	o, err := newRevocationMeshOutbox(meshRestoreLoadFailure{})
	if o != nil || err != errMeshOutboxLoad || strings.Contains(err.Error(), "PRIVATE_CONTENT") {
		t.Fatal(o, err)
	}
}

func TestMeshSnapshotPreservesLegacyAndAllPeers(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		want int
	}{
		{"first-boot", nil, 0}, {"empty-set", []byte("[]"), 0}, {"current", []byte(meshRestoreValid), 1},
		{"legacy", []byte(`[{"region":"peer","url":"http://127.0.0.1:12345","identity":"device"}]`), 1},
		{"legacy-identity-characters", []byte(`[{"region":"peer","url":"https://peer.invalid","identity":"de\u0000vice"}]`), 1},
		{"optional-empty", []byte(`[{"region":"peer","url":"https://[::1]:443/","identity":"device","reason":"","origin_region":"","enqueued_at":""}]`), 1},
		{"metadata-compatibility", []byte(`[{"region":"peer","url":"https://peer.invalid","identity":"device","reason":" retained ","origin_region":"Legacy Region","enqueued_at":"legacy display value"}]`), 1},
		{"other-peers", []byte(`[{"region":"b","url":"https://b.invalid","identity":"device"},{"region":"a","url":"https://a.invalid","identity":"device"},{"region":"a","url":"https://a.invalid","identity":"foreign"}]`), 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &meshOutboxTestPersister{data: tc.data}
			o, err := newRevocationMeshOutbox(p)
			if err != nil {
				t.Fatal(err)
			}
			items := o.snapshot()
			if len(items) != tc.want || p.count() != 0 || !bytes.Equal(tc.data, p.data) {
				t.Fatal("restore changed input", items)
			}
			for _, e := range items {
				if e.sequence == 0 || !o.isCurrent(e) {
					t.Fatal("restored entry lacks completion binding")
				}
			}
			if len(items) > 0 {
				// A normal save preserves every optional field and other peer when reloaded.
				candidate := items[0]
				candidate.Identity = "additional"
				o.enqueue(candidate)
				reloaded, err := newRevocationMeshOutbox(p)
				if err != nil {
					t.Fatal(err)
				}
				a, _ := json.Marshal(o.snapshot())
				b, _ := json.Marshal(reloaded.snapshot())
				if !bytes.Equal(a, b) {
					t.Fatal("round trip changed queue")
				}
				if strings.Contains(string(a), "sequence") {
					t.Fatal("local revision leaked into stored format")
				}
			}
		})
	}
}

func TestMeshPeerConfigurationMatchesRestoreURLContract(t *testing.T) {
	for _, raw := range []string{"https://cp.invalid:9443", "http://127.0.0.1:1234", "https://[::1]:443/prefix/", "https://cp.invalid/a%20b"} {
		peers, err := parseRevocationMeshPeers(" PEER = " + raw + " ")
		if err != nil || !reflect.DeepEqual(peers, []revocationMeshPeer{{region: "peer", url: raw}}) {
			t.Fatal(peers, err)
		}
	}
	for _, raw := range []string{"%PRIVATE_CONTENT", "cp.invalid", "ftp://cp.invalid", "https:///missing", "https://cp.invalid:bad", "https://user:PRIVATE_CONTENT@cp.invalid", "https://cp.invalid?", "https://cp.invalid?x=y", "https://cp.invalid#", "https://cp.invalid#x", "https://cp.invalid/\npath"} {
		t.Run(raw, func(t *testing.T) {
			if _, err := parseRevocationMeshPeers("peer=" + raw); err == nil || strings.Contains(err.Error(), "PRIVATE_CONTENT") {
				t.Fatal("invalid URL accepted or disclosed", err)
			}
		})
	}
	if _, err := parseRevocationMeshPeers("pe\x00er=https://cp.invalid"); err == nil {
		t.Fatal("control character in region accepted")
	}
}
