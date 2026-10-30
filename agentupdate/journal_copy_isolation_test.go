package agentupdate

import "testing"

func TestJournalCopyDoesNotSharePendingOrHistory(t *testing.T) {
	original := NewJournal()
	original.RestoreMaterial = []string{"original-installer"}
	original.PendingReport = &PendingReport{Report: Report{ID: "original-report"}}
	original.Quarantined = []QuarantinedReport{{ID: "original-quarantine"}}

	copy := original.Copy()
	copy.RestoreMaterial[0] = "changed-installer"
	copy.PendingReport.ID = "changed-report"
	copy.Quarantined[0].ID = "changed-quarantine"
	if original.RestoreMaterial[0] != "original-installer" ||
		original.PendingReport.ID != "original-report" ||
		original.Quarantined[0].ID != "original-quarantine" {
		t.Fatalf("journal rehearsal mutated source: %+v", original)
	}
}
