package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestTenantAuthoringFailurePreservesStateAndGeneration(t *testing.T) {
	for _, method := range []string{"put-existing", "put-new", "update"} {
		t.Run(method, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now()
			path := filepath.Join(t.TempDir(), "tenants.json")
			s := newDurableAdminTenantModelStore(testEvaluator().PolicyBundle, now, path)
			before, _ := s.List(ctx)
			generation := s.ConfigGeneration()
			disk, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			// Both the old fixed staging path and the destination are unwritable directories.
			if err := os.Rename(path, path+".saved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path+".tmp", 0700); err != nil {
				t.Fatal(err)
			}
			target := before[0]
			target.DisplayName = "rejected name"
			if method == "put-new" {
				target.TenantID = "new-tenant"
			}
			if method == "update" {
				_, err = s.Update(ctx, target, target.TenantID, now)
			} else {
				_, err = s.Put(ctx, target, now)
			}
			if err == nil {
				t.Fatal("unconfirmed save reported success")
			}
			after, _ := s.List(ctx)
			if !reflect.DeepEqual(before, after) || s.ConfigGeneration() != generation {
				t.Fatal("failed save changed state or generation")
			}
			os.Remove(path)
			os.Remove(path + ".tmp")
			if err := os.Rename(path+".saved", path); err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(path)
			if string(got) != string(disk) {
				t.Fatal("pre-write failure changed disk")
			}
			if method == "update" {
				_, err = s.Update(ctx, target, target.TenantID, now)
			} else {
				_, err = s.Put(ctx, target, now)
			}
			if err != nil {
				t.Fatal(err)
			}
			restored := newDurableAdminTenantModelStore(testEvaluator().PolicyBundle, now, path)
			saved, _ := restored.Get(ctx, target.TenantID)
			if saved.DisplayName != target.DisplayName || s.ConfigGeneration() != generation+1 {
				t.Fatal("retry did not persist or generation wrong")
			}
		})
	}
}

func TestTenantAuthoringDoesNotAliasElevationDecisions(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	s := newAdminTenantModelStore(testEvaluator().PolicyBundle, now)
	approved := "original"
	input := adminTenantModel{TenantID: "isolated", DisplayName: "Isolated", AllowedRegions: []string{"region-a"}, OperatorElevations: []operatorElevation{{ID: "elevation", ApprovedAt: &approved}}}
	saved, err := s.Put(ctx, input, now)
	if err != nil {
		t.Fatal(err)
	}
	input.OperatorElevations[0].ApprovalRequired = true
	*input.OperatorElevations[0].ApprovedAt = "input changed"
	saved.OperatorElevations[0].EndedAt = &approved
	saved.AllowedRegions[0] = "other"
	got, _ := s.Get(ctx, "isolated")
	got.OperatorElevations[0].GrantedTo = "changed reader"
	*got.OperatorElevations[0].ApprovedAt = "read changed"
	rows, _ := s.List(ctx)
	for i := range rows {
		if rows[i].TenantID == "isolated" {
			rows[i].OperatorElevations[0].ApprovedBy = &approved
		}
	}
	final, _ := s.Get(ctx, "isolated")
	e := final.OperatorElevations[0]
	if e.ApprovalRequired || e.EndedAt != nil || e.ApprovedBy != nil || e.GrantedTo != "" || *e.ApprovedAt != "original" || final.AllowedRegions[0] != "region-a" {
		t.Fatal("caller changed live authorization without a save")
	}
}
