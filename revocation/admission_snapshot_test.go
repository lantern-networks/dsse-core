package revocation

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
)

type admissionRestorePersister struct {
	data    []byte
	loadErr error
	writes  int
}

func (p *admissionRestorePersister) Load() ([]byte, error) { return bytes.Clone(p.data), p.loadErr }
func (p *admissionRestorePersister) Save(b []byte) error {
	p.data = bytes.Clone(b)
	p.writes++
	return nil
}

const admissionValidSnapshot = `{"schema_version":"admission_revocations_state.v1","revoked":{"owned":"local","foreign":""},"mesh_received":{"peer":"mesh"}}`

func TestAdmissionSnapshotRejectsWholeInvalidStateAndRetainsWriter(t *testing.T) {
	cases := map[string][]byte{
		"empty-file": {}, "whitespace": []byte(" \n"), "null": []byte(`null`), "array": []byte(`[]`), "truncated": []byte(`{"revoked":{"owned":"PRIVATE_CONTENT"`),
		"missing-schema": []byte(`{"revoked":{}}`), "unknown-schema": []byte(strings.Replace(admissionValidSnapshot, "admission_revocations_state.v1", "PRIVATE_CONTENT", 1)),
		"null-schema": []byte(`{"schema_version":null,"revoked":{}}`), "schema-alias": []byte(strings.Replace(admissionValidSnapshot, "schema_version", "Schema_version", 1)),
		"duplicate-schema":   []byte(`{"schema_version":"admission_revocations_state.v1","schema_version":"admission_revocations_state.v1","revoked":{}}`),
		"missing-revoked":    []byte(`{"schema_version":"admission_revocations_state.v1"}`),
		"null-revoked":       []byte(`{"schema_version":"admission_revocations_state.v1","revoked":null}`),
		"array-revoked":      []byte(`{"schema_version":"admission_revocations_state.v1","revoked":[]}`),
		"duplicate-revoked":  []byte(`{"schema_version":"admission_revocations_state.v1","revoked":{"owned":"PRIVATE_CONTENT"},"revoked":{}}`),
		"revoked-alias":      []byte(strings.Replace(admissionValidSnapshot, "revoked", "Revoked", 1)),
		"duplicate-local":    []byte(strings.Replace(admissionValidSnapshot, `"owned":"local"`, `"owned":"local","owned":"PRIVATE_CONTENT"`, 1)),
		"uppercase-local":    []byte(strings.Replace(admissionValidSnapshot, `"owned":`, `"OWNED":`, 1)),
		"padded-local":       []byte(strings.Replace(admissionValidSnapshot, `"owned":`, `" owned ":`, 1)),
		"empty-local":        []byte(strings.Replace(admissionValidSnapshot, `"owned":`, `"":`, 1)),
		"null-reason":        []byte(strings.Replace(admissionValidSnapshot, `"local"`, `null`, 1)),
		"number-reason":      []byte(strings.Replace(admissionValidSnapshot, `"local"`, `123`, 1)),
		"nested-reason":      []byte(strings.Replace(admissionValidSnapshot, `"local"`, `{"nested":"PRIVATE_CONTENT"}`, 1)),
		"padded-reason":      []byte(strings.Replace(admissionValidSnapshot, `"local"`, `" local "`, 1)),
		"null-mesh":          []byte(strings.Replace(admissionValidSnapshot, `{"peer":"mesh"}`, `null`, 1)),
		"mesh-alias":         []byte(strings.Replace(admissionValidSnapshot, "mesh_received", "Mesh_received", 1)),
		"uppercase-mesh":     []byte(strings.Replace(admissionValidSnapshot, `"peer":`, `"PEER":`, 1)),
		"duplicate-mesh-key": []byte(strings.Replace(admissionValidSnapshot, `"peer":"mesh"`, `"peer":"mesh","peer":"PRIVATE_CONTENT"`, 1)),
		"unknown-field":      []byte(strings.Replace(admissionValidSnapshot, `"mesh_received"`, `"PRIVATE_CONTENT"`, 1)),
		"trailing":           []byte(admissionValidSnapshot + `{}`),
		"invalid-utf8":       append([]byte(`{"schema_version":"admission_revocations_state.v1","revoked":{"owned":"`), append([]byte{0xff}, []byte(`"}}`)...)...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			old := &admissionRestorePersister{}
			a := NewAdmissionRevocations()
			if err := a.SetPersister(old); err != nil {
				t.Fatal(err)
			}
			a.Revoke("existing", "old local")
			a.RevokeFromMesh("old-peer", "old mesh")
			a.ReplaceSynced(map[string]string{"synced": "CP"})
			local, feed, gen := a.Snapshot(), a.FeedSnapshot(), a.ConfigGeneration()
			oldBytes := bytes.Clone(old.data)
			callbacks := 0
			a.SetReporter(func(string, string) { callbacks++ })
			a.SetMeshReporter(func(string, string) { callbacks++ })
			a.SetOnRevoked(func(string, string) { callbacks++ })
			candidate := &admissionRestorePersister{data: data}
			err := a.SetPersister(candidate)
			if err != ErrInvalidAdmissionSnapshot || strings.Contains(err.Error(), "PRIVATE_CONTENT") {
				t.Fatalf("wrong/sensitive error: %v", err)
			}
			if !reflect.DeepEqual(local, a.Snapshot()) || !reflect.DeepEqual(feed, a.FeedSnapshot()) || a.ConfigGeneration() != gen || a.SyncedCount() != 1 || callbacks != 0 {
				t.Fatal("failed restore changed live state, generation or callbacks")
			}
			if !bytes.Equal(old.data, oldBytes) || !bytes.Equal(candidate.data, data) || candidate.writes != 0 {
				t.Fatal("load rewrote stored state")
			}
			if err := a.RevokeChecked("later", "write old target"); err != nil {
				t.Fatal(err)
			}
			if candidate.writes != 0 || !bytes.Contains(old.data, []byte(`"later"`)) {
				t.Fatal("rejected candidate took over writer")
			}
		})
	}
	t.Logf("%d invalid snapshots rejected as a whole", len(cases))
}

func TestAdmissionSnapshotValidReplacementAndMissingMesh(t *testing.T) {
	a := NewAdmissionRevocations()
	a.Revoke("old", "old")
	a.RevokeFromMesh("old-peer", "old")
	a.ReplaceSynced(map[string]string{"synced": "CP"})
	gen := a.ConfigGeneration()
	callbacks := 0
	a.SetReporter(func(string, string) { callbacks++ })
	a.SetMeshReporter(func(string, string) { callbacks++ })
	a.SetOnRevoked(func(string, string) { callbacks++ })
	p := &admissionRestorePersister{data: []byte(admissionValidSnapshot)}
	if err := a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if a.ConfigGeneration() != gen+1 || callbacks != 0 {
		t.Fatal("replacement version/callback contract")
	}
	for _, id := range []string{"owned", "foreign", "peer", "synced"} {
		if _, ok := a.IsRevoked(id); !ok {
			t.Fatal("lost layer", id)
		}
	}
	if _, ok := a.IsRevoked("old"); ok {
		t.Fatal("replacement merged stale local")
	}
	if _, ok := a.IsRevoked("old-peer"); ok {
		t.Fatal("replacement merged stale mesh")
	}
	gen = a.ConfigGeneration()
	if err := a.SetPersister(p); err != nil || a.ConfigGeneration() != gen {
		t.Fatal("same snapshot churn")
	}
	// The original v1 writer omitted mesh_received. Absence means an empty layer,
	// not retention of whatever mesh was in this process before the load.
	legacy := &admissionRestorePersister{data: []byte(`{"schema_version":"admission_revocations_state.v1","revoked":{"owned":"legacy"}}`)}
	if err := a.SetPersister(legacy); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.IsRevoked("peer"); ok {
		t.Fatal("legacy snapshot retained stale mesh")
	}
	if _, ok := a.IsRevoked("synced"); !ok {
		t.Fatal("restoration replaced runtime synced layer")
	}
	if err := a.RestoreChecked("owned"); err != nil {
		t.Fatal(err)
	}
	reopened := NewAdmissionRevocations()
	if err := reopened.SetPersister(legacy); err != nil {
		t.Fatal(err)
	}
	if len(reopened.FeedSnapshot()) != 0 || p.writes != 0 || legacy.writes != 1 {
		t.Fatal("accepted writer not used")
	}
}

func TestAdmissionSnapshotReadFailureAndFileBoundary(t *testing.T) {
	a := NewAdmissionRevocations()
	old := &admissionRestorePersister{}
	if err := a.SetPersister(old); err != nil {
		t.Fatal(err)
	}
	a.Revoke("owned", "block")
	candidate := &admissionRestorePersister{data: []byte(admissionValidSnapshot), loadErr: errors.New("PRIVATE_CONTENT")}
	if err := a.SetPersister(candidate); err != ErrAdmissionLoad {
		t.Fatal("read failure ignored or exposed", err)
	}
	if err := a.RevokeChecked("later", "block"); err != nil {
		t.Fatal(err)
	}
	if candidate.writes != 0 || old.writes != 2 {
		t.Fatal("read failure replaced writer")
	}
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.json")
	fresh := NewAdmissionRevocations()
	if err := fresh.SetStatePath(missing); err != nil {
		t.Fatal("missing first boot refused", err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("read created snapshot")
	}
	if err := fresh.RevokeChecked("owned", "block"); err != nil {
		t.Fatal(err)
	}
	restored := NewAdmissionRevocations()
	if err := restored.SetStatePath(missing); err != nil {
		t.Fatal(err)
	}
	if _, ok := restored.IsRevoked("owned"); !ok {
		t.Fatal("valid file did not restore")
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := restored.SetStatePath(empty); err != ErrInvalidAdmissionSnapshot {
		t.Fatal("empty file treated as first boot", err)
	}
	if err := restored.SetPersister(blobstore.FilePersister{Path: dir}); err != ErrAdmissionLoad {
		t.Fatal("directory treated as empty", err)
	}
	if _, ok := restored.IsRevoked("owned"); !ok {
		t.Fatal("failed file load cleared block")
	}
	if err := restored.SetPersister(nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := restored.IsRevoked("owned"); !ok {
		t.Fatal("volatile mode cleared state")
	}
}
