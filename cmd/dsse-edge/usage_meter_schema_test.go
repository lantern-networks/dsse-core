package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	usagemeter "github.com/lantern-networks/dsse-core/usagemeter"

	"github.com/lantern-networks/dsse-core/model"
	schemavalidator "github.com/lantern-networks/dsse-core/schema"
)

func TestUsageMeterSamplesMatchSchema(t *testing.T) {
	schemaData := readUsageMeterSchemaForTest(t)
	for _, sample := range []string{
		"usage_meter_automation_concurrency_lab.json",
		"usage_meter_nhi_decision_lab.json",
		"usage_meter_nhi_seat_lab.json",
	} {
		sampleData, err := os.ReadFile(filepath.Join("..", "..", "samples", "phase1", sample))
		if err != nil {
			t.Fatalf("read usage meter sample %s: %v", sample, err)
		}
		if err := schemavalidator.ValidateRequired(schemaData, sampleData); err != nil {
			t.Fatalf("%s does not match usage meter schema: %v", sample, err)
		}
	}
}

func TestUsageMeterSchemaCoversNHIAndAutomationMeters(t *testing.T) {
	var schema struct {
		Properties map[string]struct {
			Enum []string `json:"enum"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(readUsageMeterSchemaForTest(t), &schema); err != nil {
		t.Fatalf("decode usage meter schema: %v", err)
	}
	assertSchemaEnumIncludes(t, schema.Properties["meter_type"].Enum, "nhi_seat", "decision", "automation_concurrency", "decision_burst", "event_stream")
	assertSchemaEnumIncludes(t, schema.Properties["subject_type"].Enum, "tenant", "nhi")
	assertSchemaEnumIncludes(t, schema.Properties["unit"].Enum, "seat", "decision", "concurrent_execution", "decision_per_minute", "event", "byte")
}

func TestUsageMeterSummaryAggregatesNHIAndAutomationSamples(t *testing.T) {
	records := []usagemeter.UsageMeterRecord{
		readUsageMeterSampleForTest(t, "usage_meter_automation_concurrency_lab.json"),
		readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json"),
		readUsageMeterSampleForTest(t, "usage_meter_nhi_seat_lab.json"),
	}
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)

	summary := usagemeter.SummarizeUsageMeterRecords(records, "tenant_lab_001", periodStart, periodEnd)
	if summary.TenantID != "tenant_lab_001" || summary.PeriodStart != periodStart.Format(time.RFC3339) || summary.PeriodEnd != periodEnd.Format(time.RFC3339) {
		t.Fatalf("summary period = %#v", summary)
	}
	if summary.Records != 3 {
		t.Fatalf("summary records = %d, want 3", summary.Records)
	}
	assertUsageMeterSummary(t, summary.Meters["decision"], "decision", "decision", "sum", 125000, 1)
	assertUsageMeterSummary(t, summary.Meters["nhi_seat"], "nhi_seat", "seat", "sum", 12, 1)
	automation := summary.Meters["automation_concurrency"]
	assertUsageMeterSummary(t, automation, "automation_concurrency", "concurrent_execution", "peak_max", 18, 1)
	if automation.Quota == nil {
		t.Fatal("automation quota is nil")
	}
	if automation.Quota.IncludedQuantity != 10 || automation.Quota.OverageQuantity != 8 || !automation.Quota.SoftCapExceeded || automation.Quota.HardCapExceeded {
		t.Fatalf("automation quota = %#v", automation.Quota)
	}
}

func TestUsageMeterSummaryFiltersTenantAndPeriod(t *testing.T) {
	base := readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json")
	otherTenant := base
	otherTenant.ID = "usage_other_tenant"
	otherTenant.TenantID = "tenant_other_001"
	otherTenant.Quantity = 999
	outsidePeriod := base
	outsidePeriod.ID = "usage_outside_period"
	outsidePeriod.PeriodStart = time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	outsidePeriod.PeriodEnd = time.Date(2026, 4, 30, 0, 0, 0, 0, time.UTC)
	outsidePeriod.Quantity = 777

	summary := usagemeter.SummarizeUsageMeterRecords([]usagemeter.UsageMeterRecord{base, otherTenant, outsidePeriod}, "tenant_lab_001", time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC))
	if summary.Records != 1 {
		t.Fatalf("summary records = %d, want 1", summary.Records)
	}
	assertUsageMeterSummary(t, summary.Meters["decision"], "decision", "decision", "sum", 125000, 1)
}

func TestUsageMeterSummaryDeduplicatesTenantRecordID(t *testing.T) {
	first := readUsageMeterSampleForTest(t, "usage_meter_nhi_decision_lab.json")
	second := first
	second.Quantity = 3
	second.Metadata = map[string]any{"source": "spool_replay_latest"}
	otherTenant := first
	otherTenant.TenantID = "tenant_other_001"
	otherTenant.Quantity = 99

	summary := usagemeter.SummarizeUsageMeterRecords([]usagemeter.UsageMeterRecord{first, second, otherTenant}, "tenant_lab_001", first.PeriodStart, first.PeriodEnd)

	if summary.Records != 1 {
		t.Fatalf("summary records = %d, want 1 after duplicate tenant/id collapse", summary.Records)
	}
	assertUsageMeterSummary(t, summary.Meters["decision"], "decision", "decision", "sum", 3, 1)
}

func TestUsageMeterSummaryUsesPeakForAutomationAndDecisionBurst(t *testing.T) {
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	records := []usagemeter.UsageMeterRecord{
		{TenantID: "tenant_lab_001", PeriodStart: periodStart, PeriodEnd: periodEnd, MeterType: "automation_concurrency", SubjectType: "tenant", Quantity: 7, Unit: "concurrent_execution"},
		{TenantID: "tenant_lab_001", PeriodStart: periodStart, PeriodEnd: periodEnd, MeterType: "automation_concurrency", SubjectType: "tenant", Quantity: 18, Unit: "concurrent_execution"},
		{TenantID: "tenant_lab_001", PeriodStart: periodStart, PeriodEnd: periodEnd, MeterType: "decision_burst", SubjectType: "tenant", Quantity: 4000, Unit: "decision_per_minute"},
		{TenantID: "tenant_lab_001", PeriodStart: periodStart, PeriodEnd: periodEnd, MeterType: "decision_burst", SubjectType: "tenant", Quantity: 12000, Unit: "decision_per_minute"},
	}

	summary := usagemeter.SummarizeUsageMeterRecords(records, "tenant_lab_001", periodStart, periodEnd)
	assertUsageMeterSummary(t, summary.Meters["automation_concurrency"], "automation_concurrency", "concurrent_execution", "peak_max", 18, 1)
	assertUsageMeterSummary(t, summary.Meters["decision_burst"], "decision_burst", "decision_per_minute", "peak_max", 12000, 1)
}

func TestUsageMeterRecordFromAccessDecisionKeepsAutomationAttribution(t *testing.T) {
	subjectUserID := "user_owner_001"
	actorNHIID := "nhi_soc_agent_001"
	grantID := "dag_automation_001"
	decision := model.AccessDecision{
		ID:                     "dec_test",
		TenantID:               "tenant_lab_001",
		ApplicationID:          "app_dummy_https",
		ActorType:              "delegated_agent",
		SubjectUserID:          &subjectUserID,
		ActorNHIID:             &actorNHIID,
		DelegatedAccessGrantID: &grantID,
	}
	record := usagemeter.UsageMeterRecordFromAccessDecision(decision, time.Date(2026, 5, 24, 1, 2, 3, 0, time.UTC))

	if record.MeterType != "decision" || record.SubjectType != "nhi" || record.SubjectID == nil || *record.SubjectID != actorNHIID {
		t.Fatalf("record subject = %#v", record)
	}
	if record.Dimensions["subject_user_id"] != subjectUserID || record.Dimensions["actor_nhi_id"] != actorNHIID || record.Dimensions["delegated_access_grant_id"] != grantID {
		t.Fatalf("record dimensions = %#v", record.Dimensions)
	}
	if record.PeriodStart.Format(time.RFC3339) != "2026-05-01T00:00:00Z" || record.PeriodEnd.Format(time.RFC3339) != "2026-06-01T00:00:00Z" {
		t.Fatalf("record period = %s - %s", record.PeriodStart.Format(time.RFC3339), record.PeriodEnd.Format(time.RFC3339))
	}

	decision.ActorNHIID = nil
	record = usagemeter.UsageMeterRecordFromAccessDecision(decision, time.Date(2026, 5, 24, 1, 2, 3, 0, time.UTC))
	if record.SubjectType != "system" || record.SubjectID == nil || *record.SubjectID != "tenant_lab_001" {
		t.Fatalf("delegated agent without NHI ID subject = %#v", record)
	}
	if record.Dimensions["subject_user_id"] != subjectUserID {
		t.Fatalf("delegated agent subject_user_id dimension = %#v", record.Dimensions)
	}
}

func TestUsageMeterGovernanceSnapshotRecordsHumanAndObservedNHI(t *testing.T) {
	periodStart := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	periodEnd := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 5, 24, 1, 2, 3, 0, time.UTC)
	actorNHIID := "nhi_soc_agent_001"
	store := usagemeter.NewUsageMeterStore(usagemeter.UsageMeterRecordFromAccessDecision(model.AccessDecision{
		TenantID:      "tenant_lab_001",
		ApplicationID: "app_dummy_https",
		ActorType:     "delegated_agent",
		ActorNHIID:    &actorNHIID,
	}, now))

	usagemeter.RecordUsageMeterGovernanceSnapshot(store, "tenant_lab_001", 3, "", 0, periodStart, periodEnd, now)
	summary := store.Summary("tenant_lab_001", periodStart, periodEnd)

	assertUsageMeterSummary(t, summary.Meters["human_seat"], "human_seat", "seat", "sum", 3, 1)
	assertUsageMeterSummary(t, summary.Meters["nhi_seat"], "nhi_seat", "seat", "sum", 1, 1)
	if summary.Meters["nhi_seat"].Quantity != 1 {
		t.Fatalf("nhi governance quantity = %#v", summary.Meters["nhi_seat"])
	}

	usagemeter.RecordUsageMeterGovernanceSnapshot(store, "tenant_lab_001", 3, "", 0, periodStart, periodEnd, now.Add(time.Minute))
	summary = store.Summary("tenant_lab_001", periodStart, periodEnd)
	if summary.Meters["human_seat"].Quantity != 3 || summary.Meters["nhi_seat"].Quantity != 1 {
		t.Fatalf("snapshot duplicated meters: %#v", summary.Meters)
	}
}

func assertSchemaEnumIncludes(t *testing.T, values []string, wants ...string) {
	t.Helper()
	have := make(map[string]bool, len(values))
	for _, value := range values {
		have[value] = true
	}
	for _, want := range wants {
		if !have[want] {
			t.Fatalf("schema enum %v is missing %q", values, want)
		}
	}
}

func assertUsageMeterSummary(t *testing.T, summary usagemeter.UsageMeterMeterSummary, meterType, unit, aggregation string, quantity float64, subjects int) {
	t.Helper()
	if summary.MeterType != meterType || summary.Unit != unit || summary.Aggregation != aggregation || summary.Quantity != quantity || summary.Subjects != subjects {
		t.Fatalf("summary = %#v, want meter=%s unit=%s aggregation=%s quantity=%v subjects=%d", summary, meterType, unit, aggregation, quantity, subjects)
	}
}

func readUsageMeterSchemaForTest(t *testing.T) []byte {
	t.Helper()
	schemaData, err := os.ReadFile(filepath.Join("..", "..", "schemas", "usage_meter.schema.json"))
	if err != nil {
		t.Fatalf("read usage meter schema: %v", err)
	}
	return schemaData
}

func readUsageMeterSampleForTest(t *testing.T, name string) usagemeter.UsageMeterRecord {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "samples", "phase1", name))
	if err != nil {
		t.Fatalf("read usage meter sample %s: %v", name, err)
	}
	var record usagemeter.UsageMeterRecord
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("decode usage meter sample %s: %v", name, err)
	}
	return record
}
