package packaging

import (
	"encoding/xml"
	"io"
	"os"
	"strings"
	"testing"
)

func TestUninstallSequenceOwnsFailureAndRollback(t *testing.T) {
	b, err := os.ReadFile("DsseAgent.wxs")
	if err != nil {
		t.Fatal(err)
	}
	defs, sequence := map[string]map[string]string{}, map[string]map[string]string{}
	d := xml.NewDecoder(strings.NewReader(string(b)))
	for {
		tok, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		el, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		attrs := map[string]string{}
		for _, a := range el.Attr {
			attrs[a.Name.Local] = a.Value
		}
		switch el.Name.Local {
		case "CustomAction":
			defs[attrs["Id"]] = attrs
		case "Custom":
			sequence[attrs["Action"]] = attrs
		case "RemoveExistingProducts":
			if attrs["After"] != "InstallInitialize" {
				t.Fatal("old product removal is outside rollback transaction")
			}
		}
	}
	for _, id := range []string{"UninstallMachineState", "HoldIncompleteRemoval", "HoldFailedInstall", "RollbackWfpDriver", "PrepareDriverReplacement"} {
		if defs[id]["Return"] != "check" || defs[id]["Impersonate"] != "no" {
			t.Fatalf("unchecked/unprivileged %s: %v", id, defs[id])
		}
	}
	if sequence["UninstallMachineState"]["Before"] != "DeleteServices" || sequence["UninstallMachineState"]["Condition"] != `REMOVE~="ALL" AND NOT UPGRADINGPRODUCTCODE` {
		t.Fatal(sequence["UninstallMachineState"])
	}
	if sequence["HoldIncompleteRemoval"]["Before"] != "StopServices" || sequence["HoldIncompleteRemoval"]["Condition"] != `REMOVE~="ALL"` {
		t.Fatal("rollback hold must follow native service restoration, including old-product rollback")
	}
	for _, id := range []string{"HoldIncompleteRemoval", "HoldFailedInstall", "RollbackWfpDriver"} {
		if defs[id]["BinaryRef"] != "ProfileApplyBin" || defs[id]["Execute"] != "rollback" {
			t.Fatal("rollback helper unavailable after file rollback", id)
		}
	}
	for _, detected := range []string{"WIX_UPGRADE_DETECTED", "WIX_DOWNGRADE_DETECTED", "DSSE_SAMEVERSION_DETECTED"} {
		if !strings.Contains(sequence["RollbackWfpDriver"]["Condition"], "NOT "+detected) {
			t.Fatal("fresh rollback may delete upgrade driver", detected)
		}
	}
	for _, obsolete := range []string{"ClearProfile", "ClearRollbackStore", "RecoverNetwork", "RemoveProvisionedAnchors", "RemoveInterceptionRoot", "UninstallWfpDriver"} {
		if defs[obsolete] != nil || sequence[obsolete] != nil {
			t.Fatal("unordered standalone cleanup remains", obsolete)
		}
	}
	if !strings.Contains(defs["RollbackWfpDriver"]["ExeCommand"], "--rollback-fresh-install") {
		t.Fatal("fresh rollback bypasses stop/recovery gate")
	}
	if sequence["InstallWfpDriver"]["After"] != "PrepareDriverReplacement" || sequence["PrepareDriverReplacement"]["After"] != "HoldFailedInstall" {
		t.Fatal("upgrade driver unload must follow checked explicit recovery with rollback already registered")
	}
}
