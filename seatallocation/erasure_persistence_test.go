package seatallocation

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestErasureRequiresConfirmedStorage(t *testing.T) {
	for _, kind := range []string{"refused", "unconfirmed", "confirmed-nonatomic"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "seats.json")
			s := NewStore()
			s.SetStateFile(path)
			for _, id := range []string{"Customer", "other"} {
				if _, err := s.Allocate(Policy{PoolSeats: 20}, id, 5, "operator", "", "now"); err != nil {
					t.Fatal(err)
				}
			}
			before, gen := s.List(), s.Generation()
			if s.CountForTenant("CUSTOMER") != 1 {
				t.Fatal("mixed-case tenant footprint missing")
			}
			var p *allocationFaultStore
			switch kind {
			case "refused":
				if err := os.Rename(path, path+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "unconfirmed", "confirmed-nonatomic":
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				p = &allocationFaultStore{raw: raw}
				if kind == "unconfirmed" {
					s.SetPersister(unconfirmedAllocationSave{p})
				} else {
					s.SetPersister(&allocationSavedWarning{*p})
				}
			}
			n, err := s.RemoveTenant(" CUSTOMER ")
			if kind != "confirmed-nonatomic" {
				if n != 0 || !errors.Is(err, ErrPersistence) || !reflect.DeepEqual(s.List(), before) || s.Generation() != gen {
					t.Fatalf("unconfirmed erasure accepted: %d %v", n, err)
				}
				if kind == "refused" {
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(path+".saved", path); err != nil {
						t.Fatal(err)
					}
				} else {
					s.persister = p
				}
				if n, err := s.RemoveTenant("customer"); n != 1 || err != nil {
					t.Fatalf("retry: %d %v", n, err)
				}
			} else if n != 1 || err != nil {
				t.Fatalf("confirmed save refused %d %v", n, err)
			}
			if s.Generation() != gen+1 || s.CountForTenant("customer") != 0 || s.SeatsFor("other") != 5 {
				t.Fatal("erasure state wrong")
			}
			reload := NewStore()
			reload.SetPersister(s.persister)
			if !reflect.DeepEqual(reload.List(), s.List()) {
				t.Fatal("erasure not durable")
			}
			if n, err := s.RemoveTenant("customer"); n != 0 || err != nil || s.Generation() != gen+1 {
				t.Fatal("absent erasure changed generation")
			}
		})
	}
}
