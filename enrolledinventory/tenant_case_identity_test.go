package enrolledinventory

import (
	"context"
	"reflect"
	"testing"
)

func TestCaseDistinctTenantCannotMutateInventory(t *testing.T) {
	for _, shared := range []bool{false, true} {
		for _, operation := range []string{"disable", "rearm", "assign", "kind", "remove", "report", "enroll", "rename-group", "delete-group"} {
			t.Run(map[bool]string{false: "local", true: "shared"}[shared]+"/"+operation, func(t *testing.T) {
				l := NewLedger()
				if shared {
					if err := l.SetPersisterChecked(&erasureContextStore{}); err != nil {
						t.Fatal(err)
					}
				}
				if _, err := l.Enroll("owned", "Acme", "", "now"); err != nil {
					t.Fatal(err)
				}
				g, err := l.CreateGroup("Staff", "Acme", "", "high", "now")
				if err != nil {
					t.Fatal(err)
				}
				before, groups := l.Authoritative(), l.ListGroups()
				ctx := context.Background()
				name := "Changed"
				switch operation {
				case "disable":
					_, err = l.SetEnabledContext(ctx, "owned", "acme", false, "now")
				case "rearm":
					_, _, err = l.AllowReenrolmentContext(ctx, "owned", "acme", "now")
				case "assign":
					_, _, err = l.SetGroupContext(ctx, "owned", "acme", "Changed", "now")
				case "kind":
					_, _, err = l.SetKindContext(ctx, "owned", "acme", KindService, "now")
				case "remove":
					_, err = l.RemoveCheckedContext(ctx, "owned", "acme", "now")
				case "report":
					_, err = l.RecordEnrolmentReportContext(ctx, "owned", "acme", "", "", "", "now")
				case "enroll":
					_, err = l.EnrollGroupForTenantContext(ctx, "owned", "acme", "acme", "", "", "now", false)
				case "rename-group":
					_, _, err = l.UpdateGroupContext(ctx, g.ID, "acme", &name, nil, nil, "now")
				case "delete-group":
					_, _, err = l.DeleteGroupContext(ctx, g.ID, "acme", true)
				}
				if err == nil {
					t.Fatal("case-distinct tenant mutation was accepted")
				}
				if !reflect.DeepEqual(before, l.Authoritative()) || !reflect.DeepEqual(groups, l.ListGroups()) {
					t.Fatal("refused mutation changed the other tenant's inventory")
				}
			})
		}
	}
}

func TestCaseDistinctTenantRetirementAndErasure(t *testing.T) {
	const stamp = "2026-10-23T00:00:00Z"
	for _, shared := range []bool{false, true} {
		for _, action := range []string{"retire", "erase"} {
			t.Run(map[bool]string{false: "local", true: "shared"}[shared]+"/"+action, func(t *testing.T) {
				l := NewLedger()
				if shared {
					if err := l.SetPersisterChecked(&erasureContextStore{}); err != nil {
						t.Fatal(err)
					}
				}
				for _, e := range []Entry{{Identity: "upper", TenantID: "Acme"}, {Identity: "lower", TenantID: "acme"}} {
					if _, err := l.Enroll(e.Identity, e.TenantID, "", stamp); err != nil {
						t.Fatal(err)
					}
				}
				if l.CountAdmitted("Acme") != 1 || l.CountTenantRecords("acme") != 1 {
					t.Error("tenant counts include another tenant")
				}
				upper, _ := l.EntryFor("upper")
				if action == "retire" {
					n, err := l.RetireTenantContext(context.Background(), "acme", stamp)
					if err != nil || n != 1 {
						t.Fatalf("retired=%d error=%v", n, err)
					}
				} else {
					ids, err := l.RemoveTenantContext(context.Background(), "acme")
					if err != nil || !reflect.DeepEqual(ids, []string{"lower"}) {
						t.Fatalf("erased unexpected identities: count=%d error=%v", len(ids), err)
					}
				}
				after, ok := l.EntryFor("upper")
				if !ok || !reflect.DeepEqual(upper, after) {
					t.Fatal("retirement/erasure changed a different tenant")
				}
			})
		}
	}
}

func TestCaseDistinctTenantGroupRiskIsIndependent(t *testing.T) {
	l := NewLedger()
	if _, err := l.CreateGroup("Staff", "Acme", "", "high", "now"); err != nil {
		t.Fatal(err)
	}
	if _, err := l.CreateGroup("staff", "acme", "", "critical", "now"); err != nil {
		t.Fatal("another tenant's group caused a name collision")
	}
	if l.GroupRiskByName("Acme", "staff") != "high" || l.GroupRiskByName("acme", "STAFF") != "critical" {
		t.Fatal("group risk crossed tenant boundary")
	}
}
