package aiops

import (
	"fmt"
	"strings"

	"github.com/lantern-networks/dsse-core/model"
)

// AI Operations Assistant — narrative report. This is the pluggable narrative layer that
// turns the DETERMINISTIC facts (access-trends + incident-timeline) into a customer
// report. The renderer is an interface with two intended implementations:
//
//   - TemplateNarrativeRenderer (default): deterministic, offline, no LLM, no external call.
//   - (later) a self-hosted OSS-LLM renderer (OpenAI-compatible LOCAL endpoint, opt-in, never an AI
//     SaaS) that renders prose from the SAME structured facts — the facts remain the source of truth.
//
// Whichever renderer is used, the structured facts are always returned alongside the prose so the
// narrative can be checked against them (grounded; no fabrication).

type NarrativeReportInput struct {
	TenantID    string
	GeneratedAt string
	Trends      accessTrendsReport
	Timeline    incidentTimeline
}

type NarrativeReportFacts struct {
	Trends   accessTrendsReport `json:"trends"`
	Timeline incidentTimeline   `json:"timeline"`
}

type NarrativeReport struct {
	SchemaVersion       string               `json:"schema_version"`
	TenantID            string               `json:"tenant_id"`
	GeneratedAt         string               `json:"generated_at"`
	Renderer            string               `json:"renderer"`
	GenerationMethod    string               `json:"generation_method"`
	Title               string               `json:"title"`
	BodyEN              string               `json:"body_en"`
	Facts               NarrativeReportFacts `json:"facts"`
	NoSecretAttestation bool                 `json:"no_secret_attestation"`
}

// NarrativeRenderer renders the structured facts into a human-readable report. Implementations must be
// grounded: they may rephrase the facts but must not introduce information absent from the input.
type NarrativeRenderer interface {
	Name() string
	Render(input NarrativeReportInput) (NarrativeReport, error)
}

// BuildNarrativeReportInput assembles the deterministic facts (trends + timeline) for the tenant.
func BuildNarrativeReportInput(decisions []model.AccessDecision, tenantID, generatedAt string, incidentLimit int) NarrativeReportInput {
	return NarrativeReportInput{
		TenantID:    tenantID,
		GeneratedAt: generatedAt,
		Trends:      BuildAccessTrendsReport(decisions, tenantID, generatedAt),
		Timeline:    BuildIncidentTimeline(decisions, tenantID, generatedAt, incidentLimit),
	}
}

// TemplateNarrativeRenderer is the default, deterministic, offline renderer. No LLM, no external call.
type TemplateNarrativeRenderer struct{}

func (TemplateNarrativeRenderer) Name() string { return "template" }

func (TemplateNarrativeRenderer) Render(in NarrativeReportInput) (NarrativeReport, error) {
	t := in.Trends
	title := "Access Operations Report"

	var en strings.Builder
	fmt.Fprintf(&en, "[%s]\n", "Access Operations Report")
	fmt.Fprintf(&en, "Tenant: %s\n", ValueOrUnknown(in.TenantID))
	fmt.Fprintf(&en, "Generated at: %s\n\n", in.GeneratedAt)
	en.WriteString("# Summary\n")
	fmt.Fprintf(&en, "Of %d decisions, %d allowed, %d denied (deny rate %d%%), %d step-up requests.\n\n",
		t.WindowDecisions, t.ByDecision["allow"], t.DenyCount, t.DenyRatePercent, t.StepUpCount)
	en.WriteString("# Top deny reasons\n")
	if len(t.TopDenyReasonCodes) == 0 {
		en.WriteString("(no denials)\n")
	} else {
		for _, row := range t.TopDenyReasonCodes {
			fmt.Fprintf(&en, "- %s: %d\n", ExplainReasonCode(row.Key).EN, row.Count)
		}
	}
	en.WriteString("\n# Notable incidents\n")
	if in.Timeline.EntryCount == 0 {
		en.WriteString("(none)\n")
	} else {
		for _, e := range in.Timeline.Entries {
			fmt.Fprintf(&en, "- [%s] %s: %s\n", e.Timestamp, e.Decision, e.SummaryEN)
		}
	}
	en.WriteString("\nNote: this report is generated deterministically inside the Edge; no data is sent to any external AI service.\n")

	return NarrativeReport{
		SchemaVersion:       "ai_ops_narrative_report.v1",
		TenantID:            in.TenantID,
		GeneratedAt:         in.GeneratedAt,
		Renderer:            "template",
		GenerationMethod:    "deterministic_template",
		Title:               title,
		BodyEN:              en.String(),
		Facts:               NarrativeReportFacts{Trends: in.Trends, Timeline: in.Timeline},
		NoSecretAttestation: true,
	}, nil
}

// NarrativeRendererRegistry holds the available renderers by name. The OSS-LLM renderer registers here
// when configured (opt-in); until then only the deterministic template renderer is present.
type NarrativeRendererRegistry struct {
	renderers map[string]NarrativeRenderer
}

func NewNarrativeRendererRegistry(extra ...NarrativeRenderer) *NarrativeRendererRegistry {
	reg := &NarrativeRendererRegistry{renderers: map[string]NarrativeRenderer{}}
	reg.Register(TemplateNarrativeRenderer{})
	for _, r := range extra {
		if r != nil {
			reg.Register(r)
		}
	}
	return reg
}

func (reg *NarrativeRendererRegistry) Register(r NarrativeRenderer) {
	reg.renderers[r.Name()] = r
}

// Resolve returns the renderer for the requested name, defaulting to "template" when empty. ok=false
// when a non-empty name is requested but not registered (e.g. "llm" before the OSS-LLM renderer is
// deployed) so the caller can return a clear error instead of silently substituting.
func (reg *NarrativeRendererRegistry) Resolve(name string) (NarrativeRenderer, bool) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "template"
	}
	r, ok := reg.renderers[name]
	return r, ok
}
