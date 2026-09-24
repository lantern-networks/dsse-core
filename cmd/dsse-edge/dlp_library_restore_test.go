package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/dlp"
)

type libraryRestoreFixture struct {
	load       func(blobstore.Persister) error
	commit     func(string) error
	stage      func(string)
	flush      func() error
	state      func() any
	generation func() uint64
	dirty      func() bool
	writer     func() blobstore.Persister
	active     func(string) bool
}

func libraryRestoreForTest(kind string) libraryRestoreFixture {
	if kind == "classifiers" {
		s := newDLPClassifierRuntimeStore()
		specs := func(value string) []dlp.ClassifierSpec {
			return []dlp.ClassifierSpec{{Name: "project_code", Kind: dlp.ClassifierKeyword, Keywords: []string{value}}}
		}
		return libraryRestoreFixture{s.SetPersister, func(v string) error { return s.SetSpecsDurable("own", specs(v)) }, func(v string) { s.SetSpecs("own", specs(v)) }, s.PersistIfDirty, func() any { return s.specs }, func() uint64 { return s.generation }, func() bool { return s.dirty }, func() blobstore.Persister { return s.persister }, func(v string) bool {
			return len(dlp.DetectWith([]byte(v), "text/plain", s.ClassifierSetForTenant("own"))) > 0
		}}
	}
	s := newDLPAllowlistRuntimeStore("salt")
	return libraryRestoreFixture{s.SetPersister, func(v string) error { return s.SetValuesDurable("own", []string{v}) }, func(v string) { s.SetValues("own", []string{v}) }, s.PersistIfDirty, func() any { return s.values }, func() uint64 { return s.generation }, func() bool { return s.dirty }, func() blobstore.Persister { return s.persister }, func(v string) bool {
		return len(dlp.DetectWithOptions([]byte(v), "text/plain", dlp.Options{Classifiers: mustRestoreClassifiers(), Allowlist: s.AllowlistForTenant("own")})) == 0
	}}
}
func mustRestoreClassifiers() *dlp.ClassifierSet {
	s, _ := dlp.NewClassifierSet([]dlp.ClassifierSpec{{Name: "project_code", Kind: dlp.ClassifierKeyword, Keywords: []string{"BLUEFIN", "REDCEDAR"}}})
	return s
}

func TestDLPLibraryRestoreRejectsInvalidCandidateAndRetainsWriter(t *testing.T) {
	for _, kind := range []string{"classifiers", "allowlist"} {
		t.Run(kind, func(t *testing.T) {
			key := "specs"
			if kind == "allowlist" {
				key = "values"
			}
			invalid := []string{"", " ", "null", "{}", "{bad", `{"` + key + `":null}`, `{"` + key + `":{ " ":[]}}`, `{"` + key + `":{},"unexpected":"PRIVATE-VALUE"}`, `{"` + key + `":[]}`, `{"` + key + `":{},"` + strings.ToUpper(key) + `":null}`}
			if kind == "classifiers" {
				for _, spec := range []string{`{"name":"bad_regex","kind":"regex","pattern":"("}`, `{"name":"empty_match","kind":"regex","pattern":"a*"}`, `{"name":"credit_card","kind":"keyword","keywords":["PRIVATE-VALUE"]}`, `{"name":"bad_keyword","kind":"keyword","keywords":[]}`, `{"name":"bad_kind","kind":"other"}`, `null`, `{"name":"project_code","kind":"keyword","keywords":["PRIVATE-VALUE"],"unexpected":true}`} {
					invalid = append(invalid, `{"specs":{"own":[{"name":"project_code","kind":"keyword","keywords":["BLUEFIN"]},`+spec+`],"foreign":[{"name":"foreign_code","kind":"keyword","keywords":["REDCEDAR"]}]}}`)
				}
				many := make([]dlp.ClassifierSpec, dlp.MaxClassifiers+1)
				for i := range many {
					many[i] = dlp.ClassifierSpec{Name: "project_code", Kind: dlp.ClassifierKeyword, Keywords: []string{"BLUEFIN"}}
				}
				data, _ := json.Marshal(classifierStoreSnapshot{Specs: map[string][]dlp.ClassifierSpec{"own": many}})
				invalid = append(invalid, string(data))
			} else {
				invalid = append(invalid, `{"values":{"own":["BLUEFIN"," "]}}`, `{"values":{"own":[null]}}`, `{"values":{"own":[42]}}`)
				many := make([]string, maxDLPAllowlistValues+1)
				for i := range many {
					many[i] = "BLUEFIN"
				}
				data, _ := json.Marshal(allowlistStoreSnapshot{Values: map[string][]string{"own": many}})
				invalid = append(invalid, string(data))
			}
			for i, data := range invalid {
				s := libraryRestoreForTest(kind)
				p := &edmRestorePersister{}
				if err := s.load(p); err != nil {
					t.Fatal(err)
				}
				if err := s.commit("BLUEFIN"); err != nil {
					t.Fatal(err)
				}
				before, gen, writes := string(p.data), s.generation(), p.writes
				bad := &edmRestorePersister{data: []byte(data)}
				err := s.load(bad)
				if err == nil {
					t.Errorf("case %d: accepted invalid candidate", i)
					continue
				}
				if strings.Contains(err.Error(), "PRIVATE-VALUE") {
					t.Fatal("load error revealed contents")
				}
				if s.writer() != p || s.generation() != gen || s.dirty() || !s.active("BLUEFIN") || s.active("REDCEDAR") || string(p.data) != before || p.writes != writes || bad.writes != 0 {
					t.Fatalf("case %d: failed load changed state or writer", i)
				}
				if err := s.commit("REDCEDAR"); err != nil {
					t.Fatal(err)
				}
				if bad.writes != 0 || p.writes != writes+1 {
					t.Fatal("failed load stole subsequent saves")
				}
			}
		})
	}
}

func TestDLPLibraryRestoreReplacementAndWriterLifecycle(t *testing.T) {
	for _, kind := range []string{"classifiers", "allowlist"} {
		t.Run(kind, func(t *testing.T) {
			s := libraryRestoreForTest(kind)
			p := &edmRestorePersister{}
			if err := s.load(p); err != nil {
				t.Fatal(err)
			}
			s.stage("BLUEFIN")
			for _, writer := range []blobstore.Persister{nil, p, &edmRestorePersister{}} {
				if err := s.load(writer); err == nil || s.writer() != p || !s.dirty() {
					t.Fatal("discarded pending state")
				}
			}
			if err := s.flush(); err != nil {
				t.Fatal(err)
			}
			original := append([]byte(nil), p.data...)
			gen := s.generation()
			if err := s.load(&edmRestorePersister{loadErr: errors.New("read failure")}); err == nil || s.writer() != p || s.generation() != gen || !s.active("BLUEFIN") {
				t.Fatal("read failure changed state")
			}
			key := "specs"
			if kind == "allowlist" {
				key = "values"
			}
			for _, empty := range []string{`{"` + key + `":{}}`, `{"` + key + `":{"own":[]}}`, `{"` + key + `":{"own":null}}`} {
				if err := s.load(&edmRestorePersister{data: []byte(empty)}); err != nil {
					t.Fatal(err)
				}
				if s.active("BLUEFIN") || s.generation() <= gen {
					t.Fatal("explicit clear merged prior library")
				}
				if err := s.load(&edmRestorePersister{data: original}); err != nil {
					t.Fatal(err)
				}
				if !s.active("BLUEFIN") {
					t.Fatal("valid restoration lost detection/suppression")
				}
			}
			missing := &edmRestorePersister{}
			if err := s.load(missing); err != nil {
				t.Fatal(err)
			}
			if !s.dirty() || !s.active("BLUEFIN") {
				t.Fatal("missing new store discarded live library")
			}
			if err := s.flush(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(missing.data, original) {
				t.Fatal("new writer did not save retained library")
			}
			if err := s.load(nil); err != nil || s.writer() != nil || !s.active("BLUEFIN") {
				t.Fatal("clean detach changed live library")
			}
		})
	}
}

func TestDLPAllowlistRestoreNormalizesAndUsesLocalSalt(t *testing.T) {
	p := &edmRestorePersister{data: []byte(`{"values":{"own":[" BLUEFIN ","BLUEFIN"],"foreign":["REDCEDAR"]}}`)}
	s := newDLPAllowlistRuntimeStore("different-local-salt")
	if err := s.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.ValuesForTenant("own"), []string{"BLUEFIN"}) || p.writes != 0 {
		t.Fatal("normalization or read-only loading differs")
	}
	for _, tenant := range []string{"own", "foreign"} {
		for _, value := range []string{"BLUEFIN", "REDCEDAR"} {
			got := dlp.DetectWithOptions([]byte(value), "text/plain", dlp.Options{Classifiers: mustRestoreClassifiers(), Allowlist: s.AllowlistForTenant(tenant)})
			wantSuppressed := (tenant == "own" && value == "BLUEFIN") || (tenant == "foreign" && value == "REDCEDAR")
			if (len(got) == 0) != wantSuppressed {
				t.Fatalf("suppression lost local salt or tenant scope: %s %s %v", tenant, value, got)
			}
		}
	}
}

func TestDLPLibraryRestoreProductionStartup(t *testing.T) {
	if path := os.Getenv("DSSE_LIBRARY_RESTORE_CHILD"); path != "" {
		config := serverConfig{}
		if os.Getenv("DSSE_LIBRARY_RESTORE_KIND") == "classifiers" {
			config.DLPClassifierStorePath = path
		} else {
			config.DLPAllowlistStorePath = path
		}
		rt := buildDLPRuntime(config)
		if os.Getenv("DSSE_LIBRARY_RESTORE_VALID") == "1" {
			if os.Getenv("DSSE_LIBRARY_RESTORE_KIND") == "classifiers" && len(dlp.DetectWith([]byte("BLUEFIN"), "text/plain", rt.classifiers.ClassifierSetForTenant("own"))) == 1 {
				os.Exit(0)
			}
			if os.Getenv("DSSE_LIBRARY_RESTORE_KIND") == "allowlist" && len(dlp.DetectWithOptions([]byte("BLUEFIN"), "text/plain", dlp.Options{Classifiers: mustRestoreClassifiers(), Allowlist: rt.allowlist.AllowlistForTenant("own")})) == 0 {
				os.Exit(0)
			}
		}
		os.Exit(9)
	}
	for _, kind := range []string{"classifiers", "allowlist"} {
		t.Run(kind, func(t *testing.T) {
			s := libraryRestoreForTest(kind)
			p := &edmRestorePersister{}
			if err := s.load(p); err != nil {
				t.Fatal(err)
			}
			if err := s.commit("BLUEFIN"); err != nil {
				t.Fatal(err)
			}
			for i, data := range [][]byte{p.data, {}, []byte("null"), []byte("{bad"), []byte("{}")} {
				path := filepath.Join(t.TempDir(), "library.json")
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDLPLibraryRestoreProductionStartup$")
				cmd.Env = append(os.Environ(), "DSSE_LIBRARY_RESTORE_CHILD="+path, "DSSE_LIBRARY_RESTORE_KIND="+kind)
				if i == 0 {
					cmd.Env = append(cmd.Env, "DSSE_LIBRARY_RESTORE_VALID=1")
				}
				out, err := cmd.CombinedOutput()
				if i == 0 {
					if err != nil {
						t.Fatalf("valid startup: %v %s", err, out)
					}
				} else {
					exit, ok := err.(*exec.ExitError)
					if !ok || exit.ExitCode() != 1 || !bytes.Contains(out, []byte("load dlp ")) {
						t.Fatalf("invalid startup: %v %s", err, out)
					}
				}
				if ctx.Err() != nil {
					t.Fatal(ctx.Err())
				}
				after, e := os.ReadFile(path)
				if e != nil || !bytes.Equal(after, data) {
					t.Fatal("startup modified snapshot")
				}
			}
		})
	}
}
