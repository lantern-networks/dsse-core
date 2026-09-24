package idpregistry

import (
	"errors"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/lantern-networks/dsse-core/blobstore"
)

type gatePersister struct {
	blobstore.FilePersister
	fail bool
}

func (p *gatePersister) Save(b []byte) error {
	if p.fail {
		return errors.New("private path rejected")
	}
	return p.FilePersister.Save(b)
}
func TestAdminWritesSaveBeforePublication(t *testing.T) {
	for _, action := range []string{"create", "edit", "default", "delete", "last-delete"} {
		t.Run(action, func(t *testing.T) {
			p := &gatePersister{FilePersister: blobstore.FilePersister{Path: filepath.Join(t.TempDir(), "idp.json")}}
			s := NewStore()
			if e := s.SetPersister(p); e != nil {
				t.Fatal(e)
			}
			for _, c := range []Connection{sampleConn("tenant", "a"), sampleConn("tenant", "b"), sampleConn("other", "a")} {
				c.ClientSecret = "private-test-secret"
				if _, e := s.Upsert(c); e != nil {
					t.Fatal(e)
				}
			}
			before := s.ListAll()
			defaults := s.DefaultsAll()
			disk, e := p.Load()
			if e != nil {
				t.Fatal(e)
			}
			generation := s.ConfigGeneration()
			change := func() error {
				switch action {
				case "create":
					_, e := s.Upsert(sampleConn("tenant", "new"))
					return e
				case "edit":
					c := sampleConn("tenant", "a")
					c.DisplayName = "changed"
					_, e := s.Upsert(c)
					return e
				case "default":
					return s.SetDefault("tenant", "b")
				case "delete":
					_, e := s.Delete("tenant", "b")
					return e
				default:
					_, e := s.Delete("other", "a")
					return e
				}
			}
			p.fail = true
			if e := change(); !errors.Is(e, ErrPersistence) {
				t.Fatalf("error: %v", e)
			}
			after, _ := p.Load()
			if !reflect.DeepEqual(before, s.ListAll()) || !reflect.DeepEqual(defaults, s.DefaultsAll()) || string(disk) != string(after) || s.ConfigGeneration() != generation {
				t.Fatal("rejected write changed live/defaults/disk/generation")
			}
			// A different subsequent save cannot resurrect a failed candidate.
			p.fail = false
			if _, e := s.Upsert(sampleConn("tenant", "unrelated")); e != nil {
				t.Fatal(e)
			}
			restart := NewStore()
			if e := restart.SetStatePath(p.Path); e != nil {
				t.Fatal(e)
			}
			for _, c := range before {
				got, ok := restart.Get(c.TenantID, c.IdPID)
				if !ok || !reflect.DeepEqual(c, got) {
					t.Fatalf("prior connection lost: %+v %+v", c, got)
				}
			}
			if _, ok := restart.Get("tenant", "new"); ok {
				t.Fatal("failed create mixed into later save")
			}
			if !reflect.DeepEqual(defaults, restart.DefaultsAll()) {
				t.Fatal("failed default persisted later")
			}
			if e := change(); e != nil {
				t.Fatal(e)
			}
			restart = NewStore()
			if e := restart.SetStatePath(p.Path); e != nil {
				t.Fatal(e)
			}
			if !reflect.DeepEqual(s.ListAll(), restart.ListAll()) || !reflect.DeepEqual(s.DefaultsAll(), restart.DefaultsAll()) {
				t.Fatal("accepted state missing at restart")
			}
			if action == "edit" {
				c, _ := restart.Get("tenant", "a")
				if c.ClientSecret != "private-test-secret" {
					t.Fatal("blank edit cleared write-only secret")
				}
			}
		})
	}
}
