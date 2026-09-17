package main

import (
	"sort"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/hotstore"
	"github.com/lantern-networks/dsse-core/model"
)

// AI Security Visibility: visualization-first. Identify known generative-AI service
// usage from access logs, classify each as approved | tolerated | prohibited, and produce a usage
// report. Classification is an org policy choice: the SaaS catalog's AIGovernance overrides the
// built-in default; unknown-but-known-AI defaults to "tolerated". Non-secret: counts + enums only.

const (
	aiGovernanceApproved   = "approved"
	aiGovernanceTolerated  = "tolerated"
	aiGovernanceProhibited = "prohibited"
)

// knownAIServiceDefaults maps a SaaS application id to a default AI-governance classification for the
// known generative-AI services. Admins override per-entry via the catalog (AIGovernance).
var knownAIServiceDefaults = map[string]string{
	"saas_anthropic_claude":  aiGovernanceApproved,
	"saas_openai_chatgpt":    aiGovernanceTolerated,
	"saas_google_gemini":     aiGovernanceTolerated,
	"saas_microsoft_copilot": aiGovernanceTolerated,
	"saas_perplexity":        aiGovernanceTolerated,
	"saas_github_copilot":    aiGovernanceTolerated,
	"saas_mistral":           aiGovernanceTolerated,
	"saas_deepseek":          aiGovernanceTolerated,
	"saas_xai_grok":          aiGovernanceTolerated,
	"saas_poe":               aiGovernanceTolerated,
	"saas_meta_ai":           aiGovernanceTolerated,
	"saas_alibaba_qwen":      aiGovernanceTolerated,
	"saas_moonshot_kimi":     aiGovernanceTolerated,
	"saas_bytedance_doubao":  aiGovernanceTolerated,
	"saas_felo":              aiGovernanceTolerated,
}

// aiServiceGovernance reports whether a SaaS application is a known generative-AI service and its
// governance classification. The catalog entry (AIService / AIGovernance) takes precedence over the
// built-in defaults so admins can classify per tenant.
func aiServiceGovernance(saasAppID string, catalog []model.SaaSCatalogEntry) (string, bool) {
	id := strings.TrimSpace(saasAppID)
	if id == "" {
		return "", false
	}
	for _, e := range catalog {
		if e.SaaSApplicationID != id {
			continue
		}
		if e.AIService || strings.TrimSpace(e.AIGovernance) != "" || hasTag(e.Tags, "generative_ai") {
			gov := strings.TrimSpace(strings.ToLower(e.AIGovernance))
			if gov == "" {
				if def, ok := knownAIServiceDefaults[id]; ok {
					gov = def
				} else {
					gov = aiGovernanceTolerated
				}
			}
			return gov, true
		}
	}
	if def, ok := knownAIServiceDefaults[id]; ok {
		return def, true
	}
	return "", false
}

func hasTag(tags []string, want string) bool {
	for _, t := range tags {
		if strings.EqualFold(strings.TrimSpace(t), want) {
			return true
		}
	}
	return false
}

type aiUsageReportEntry struct {
	SaaSApplicationID string `json:"saas_application_id"`
	Name              string `json:"name"`
	AIGovernance      string `json:"ai_governance"`
	AccessCount       int    `json:"access_count"`
	Sessions          int    `json:"sessions"`
	Messages          int    `json:"messages"`
	BytesSent         int64  `json:"bytes_sent"`
	BytesReceived     int64  `json:"bytes_received"`
}

type aiUsageServiceCount struct {
	Name        string `json:"name"`
	AccessCount int    `json:"access_count"`
	Sessions    int    `json:"sessions"`
	Messages    int    `json:"messages"`
}

// isAIMessage reports whether an access-log row is a "message" — a POST to the assistant (a prompt / action),
// as opposed to a GET page load or poll. Read from the non-secret http_method stamped on the row's metadata.
func isAIMessage(row map[string]any) bool {
	if md, ok := row["metadata"].(map[string]any); ok {
		if m, ok := md["http_method"].(string); ok {
			return strings.EqualFold(strings.TrimSpace(m), "POST")
		}
	}
	return false
}

// sessionBucket collapses a burst of requests into one "session": the 30-minute wall-clock window the access
// fell in. Raw request count overstates usage — one chat interaction is many polling / telemetry / asset
// requests — so "how much" is better read as distinct sessions (interactions) than as request count. Returns
// false when the row has no parseable timestamp (those rows still count toward access_count, just not sessions).
func sessionBucket(row map[string]any) (int64, bool) {
	ts := stringFromRow(row, "timestamp")
	if ts == "" {
		return 0, false
	}
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		if t, err = time.Parse(time.RFC3339Nano, ts); err != nil {
			return 0, false
		}
	}
	return t.Unix() / 1800, true // 30-minute windows
}

// aiUsageIdentityEntry answers "WHO used which AI": one row per identity (best available attribution) with a
// per-service breakdown. IdentityType degrades user > ai_agent (NHI) > device > source_ip > unattributed as the
// dataplane end-user identity is (partially) wired — so the view is meaningful today (device / source IP) and
// gets sharper as end-user identity lands on the flow.
type aiUsageIdentityEntry struct {
	Identity      string                `json:"identity"`
	IdentityType  string                `json:"identity_type"`
	CorporateUser string                `json:"corporate_user"`
	AIAccounts    []string              `json:"ai_accounts"`
	Devices       []string              `json:"devices"`
	Apps          []string              `json:"apps"`
	TotalAccesses int                   `json:"total_accesses"`
	Sessions      int                   `json:"sessions"`
	Messages      int                   `json:"messages"`
	BytesSent     int64                 `json:"bytes_sent"`
	BytesReceived int64                 `json:"bytes_received"`
	Services      []aiUsageServiceCount `json:"services"`
}

// aiUsageActivityEntry is ONE (user × device × app × AI-service) combination — the un-aggregated "who did what"
// row. by_identity lumps a user's apps and services into cells; this keeps each distinct combination its own row
// so you can read WHICH app reached WHICH AI.
type aiUsageActivityEntry struct {
	Identity      string `json:"identity"`
	IdentityType  string `json:"identity_type"`
	CorporateUser string `json:"corporate_user"`
	Device        string `json:"device"`
	App           string `json:"app"`
	AIAccount     string `json:"ai_account"`
	AIEmail       string `json:"ai_email"`
	AIName        string `json:"ai_name"`
	Service       string `json:"service"`
	Sessions      int    `json:"sessions"`
	Accesses      int    `json:"accesses"`
	Messages      int    `json:"messages"`
	BytesSent     int64  `json:"bytes_sent"`
	BytesReceived int64  `json:"bytes_received"`
}

// aiUsageWindow is the range the caller ASKED for. Requested is the preset name ("24h"/"7d"/"30d") or "custom"
// for an absolute from/to. Always populated — a report that does not say what window it covers is the defect
// this exists to remove, and "7d" was previously implied by nothing but a constant.
type aiUsageWindow struct {
	Requested string `json:"requested"`
	From      string `json:"from"`
	To        string `json:"to"`
}

// aiUsageCoverage is the range the report ACTUALLY covers, which is not always the window asked for. The read is
// capped (aiUsageReportRowCap) and returns newest-first, so a tenant busy enough to hit the cap gets a report
// over a SHORTER span than requested. When Truncated, From is the earliest event that made it in and the window
// start is meaningless — the UI must show From, not the window's. Rows/RowCap are the store read, before the
// tenant and AI-service filters, because it is the store read the cap applies to.
type aiUsageCoverage struct {
	// Source names the path that answered: "rows" loaded and grouped in Go, "aggregate" had the store GROUP BY.
	// Both run the same aggregation, but a serving path that changes without saying so is one nobody can rule
	// out when a number is questioned later.
	Source string `json:"source"`
	// RetainedFrom is the earliest access record still held for this tenant, whatever window was asked for.
	// When it is later than the window start, the earlier part of the window is empty — and this field says so
	// WITHOUT claiming why: a quiet tenant and one whose old records rotated away look identical from here, and
	// asserting "data loss" on the first would cry wolf. Distinct from Truncated, which is only ever the row
	// cap. Empty when the backend cannot answer cheaply.
	RetainedFrom string `json:"retained_from,omitempty"`
	From         string `json:"from"`
	To           string `json:"to"`
	Rows         int    `json:"rows"`
	RowCap       int    `json:"row_cap"`
	Truncated    bool   `json:"truncated"`
}

type aiUsageReport struct {
	SchemaVersion string `json:"schema_version"`
	GeneratedAt   string `json:"generated_at"`
	// Set by the handler from the authenticated context, never from log input.
	TenantID string `json:"tenant_id"`
	// Window / Coverage are set by the handler after aggregation (this file's builder is pure over rows and has
	// no knowledge of the query that selected them). Zero on a report built directly in a test.
	Window             aiUsageWindow          `json:"window"`
	Coverage           aiUsageCoverage        `json:"coverage"`
	TotalAIAccesses    int                    `json:"total_ai_accesses"`
	TotalAISessions    int                    `json:"total_ai_sessions"`
	TotalAIMessages    int                    `json:"total_ai_messages"`
	TotalBytesSent     int64                  `json:"total_bytes_sent"`
	TotalBytesReceived int64                  `json:"total_bytes_received"`
	ByGovernance       map[string]int         `json:"by_governance"`
	Services           []aiUsageReportEntry   `json:"services"`
	ByIdentity         []aiUsageIdentityEntry `json:"by_identity"`
	// ByActivity is the un-aggregated view: one row per (user × device × app × AI-service), so the UI does not
	// lump a user's apps and services into single cells.
	ByActivity []aiUsageActivityEntry `json:"by_activity"`
	// ShadowAI is the subset of by_identity using a PERSONAL account on an assistant (identity_type
	// user_personal) — a corporate user routing around the company tenant. The governance risk list an admin
	// acts on (restrict-to-corporate / block). Observe only; no enforcement here.
	ShadowAI            []aiUsageIdentityEntry `json:"shadow_ai"`
	NoSecretAttestation bool                   `json:"no_secret_attestation"`
}

// aiIdentityFor picks the best available attribution for an access-log row: an AI agent (NHI) first, then the
// end-user, then the device, then the source IP, else unattributed. Returns (identity, identity_type).
// aiAccountFromRow reads the account the user was signed into the assistant with (from the request JWT), stamped
// on the row metadata by the SWG egress path. This is SEPARATE from the corporate identity (user_id).
func aiAccountFromRow(row map[string]any) string {
	if md, ok := row["metadata"].(map[string]any); ok {
		return stringFromRow(md, "ai_account")
	}
	return ""
}

// aiEmailFromRow / aiNameFromRow read the AI-account identity as SEPARATE fields (the SWG egress path stamps both
// when the service exposes them; either is "" when it does not — e.g. Claude gives a name but no email).
func aiEmailFromRow(row map[string]any) string {
	if md, ok := row["metadata"].(map[string]any); ok {
		return stringFromRow(md, "ai_email")
	}
	return ""
}

func aiNameFromRow(row map[string]any) string {
	if md, ok := row["metadata"].(map[string]any); ok {
		return stringFromRow(md, "ai_name")
	}
	return ""
}

// aiUsageReportRowCap bounds the rows the report loads (the Postgres hot store requires a positive limit, and
// loading an unbounded, growing table would be slow). A live "current usage" cap; the raw rows stay in Postgres
// for future SQL-aggregated graphing that does not row-load. Recent-first, so this is the latest activity.
// A var, not a const, so a test can lower it and exercise the truncation path without writing 100k rows.
var aiUsageReportRowCap = 100000

// aiUsageReportGroupCap bounds the aggregate path the way aiUsageReportRowCap bounds the row-loading one. Groups
// are users x devices x apps x services, so this is far out of reach in normal use — it exists so a pathological
// tenant degrades into a reported truncation rather than an unbounded result set.
const aiUsageReportGroupCap = 20000

// aiUsageSessionBucketSeconds is sessionBucket's 30 minutes, named so the SQL that has to reproduce it cannot
// drift from the Go that defines it.
const aiUsageSessionBucketSeconds = 1800

// aiUsageRowTime reads a row's event time, accepting the same field spellings as the logs query path
// (adminLogRowWithinTimeRange) because the hot-store backends do not agree on one.
func aiUsageRowTime(row map[string]any) (time.Time, bool) {
	raw := firstNonEmptyString(row["timestamp"], row["occurred_at"], row["created_at"])
	if raw == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t, true
	}
	t, err := time.Parse(time.RFC3339Nano, raw)
	return t, err == nil
}

// appFromRow reads the app/process that originated the flow (endpoint agent, "what tool"), from row metadata.
func appFromRow(row map[string]any) string {
	if md, ok := row["metadata"].(map[string]any); ok {
		return stringFromRow(md, "ai_app")
	}
	return ""
}

// bytesFromRow reads a byte counter (bytes_sent / bytes_received) from row metadata. JSON numbers decode to
// float64, so accept that too. 0 when absent — the "how much" metric that replaces raw request/POST counts.
func bytesFromRow(row map[string]any, key string) int64 {
	md, ok := row["metadata"].(map[string]any)
	if !ok {
		return 0
	}
	switch v := md[key].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	}
	return 0
}

// aiIdentityFor resolves the two identities of an AI access-log row, keeping them distinct:
//   - corp:    the CORPORATE IdP identity (user_id / subject_user_id, from the authenticated session) — WHO the
//     person is. Authoritative.
//   - aiAcct:  the AI-SERVICE account they signed in as (from the JWT) — WHAT account they used. The two often
//     differ; a personal aiAcct on a corporate person is the shadow-AI signal.
//
// It returns the grouping key (corporate if known, else the AI account, else device / source IP) and its type,
// plus corp and aiAcct so the report can show BOTH.
func aiIdentityFor(row map[string]any) (key, itype, corp, aiAcct string) {
	corp = stringFromRow(row, "user_id")
	if corp == "" {
		corp = stringFromRow(row, "subject_user_id")
	}
	aiAcct = aiAccountFromRow(row)
	nhi := stringFromRow(row, "actor_nhi_id")
	at := stringFromRow(row, "actor_type")
	switch {
	case nhi != "" || at == "delegated_agent" || at == "nhi" || at == "non_human":
		if nhi == "" {
			nhi = "(AI agent)"
		}
		return nhi, "ai_agent", "", aiAcct
	case corp != "":
		return corp, "user", corp, aiAcct // corporate IdP identity — authoritative "who"
	case aiAcct != "":
		return aiAcct, classifyUserIdentity(aiAcct), "", aiAcct
	}
	if d := stringFromRow(row, "device_id"); d != "" {
		return d, "device", "", aiAcct
	}
	if ip := stringFromRow(row, "source_ip"); ip != "" {
		return ip, "source_ip", "", aiAcct
	}
	return "(unattributed)", "unattributed", "", aiAcct
}

// sortedStringSet returns the set's keys, sorted (deterministic output).
func sortedStringSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// entryIsShadowAI reports whether an identity is using a PERSONAL account at an assistant — either the identity
// itself is a personal account (no corporate identity known) or a corporate person signed into the assistant
// with a personal account. Both are the shadow-AI / data-exfiltration risk.
func entryIsShadowAI(u aiUsageIdentityEntry) bool {
	if u.IdentityType == "user_personal" {
		return true
	}
	for _, a := range u.AIAccounts {
		if classifyUserIdentity(a) == "user_personal" {
			return true
		}
	}
	return false
}

// personalEmailDomains are consumer providers. AI usage on a personal account through the corporate network is a
// shadow-AI signal (a corporate user avoiding the company tenant), not a corporate user — label it honestly.
var personalEmailDomains = map[string]bool{
	"gmail.com": true, "googlemail.com": true, "outlook.com": true, "hotmail.com": true,
	"live.com": true, "yahoo.com": true, "ymail.com": true, "icloud.com": true, "me.com": true,
	"mac.com": true, "proton.me": true, "protonmail.com": true, "aol.com": true, "gmx.com": true,
}

// classifyUserIdentity refines a raw extracted identity so the report is honest about how strong it is:
//   - "user"          a corporate email (has @, non-personal domain) — the strongest, human-meaningful id
//   - "user_personal" a personal-provider email — shadow-AI signal, NOT a corporate user
//   - "user_opaque"   an opaque token subject (e.g. "google-oauth2|123…") — stable-per-user but unresolved;
//     it needs the Edge IdP session to map to a corporate identity (see docs/ai_usage_attribution_design.md).
//
// Never silently present an opaque/personal id as a corporate user.
func classifyUserIdentity(u string) string {
	u = strings.TrimSpace(u)
	at := strings.LastIndex(u, "@")
	if at <= 0 || at == len(u)-1 {
		return "user_opaque"
	}
	domain := strings.ToLower(u[at+1:])
	if personalEmailDomains[domain] {
		return "user_personal"
	}
	return "user"
}

// accessRowsForTenant returns only the access-log rows belonging to tenantID. The access log is shared
// storage (one access.log.jsonl across tenants), so any report/visibility built from it MUST be scoped to
// the requesting tenant first — never aggregate across tenants (tenant isolation). Empty tenantID
// yields no rows (fail-closed: do not leak all tenants).
func accessRowsForTenant(rows []map[string]any, tenantID string) []map[string]any {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return nil
	}
	out := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		if stringValue(row["tenant_id"]) == tenantID {
			out = append(out, row)
		}
	}
	return out
}

// buildAIUsageReport aggregates access-log rows into an AI usage report using the catalog for
// classification. Pure function over decoded rows so it is unit-testable. generatedAt is passed in
// (the runtime has no clock in pure code paths). Callers MUST pass tenant-scoped rows
// (see accessRowsForTenant) — this function does not filter by tenant.
// aiUsageAggregateEnabled lets the hot store group when it can. A var, set from -ai-usage-aggregate, so an
// operator who distrusts a number has a way back to row-loading without a rebuild.
var aiUsageAggregateEnabled = true

// aiUsageGroupFields are the RAW fields the report's classification reads, each declared at the depth ITS OWN
// reader looks at — and those depths differ. aiIdentityFor reads user_id / device_id / source_ip at the top
// level only; aiAccountFromRow and appFromRow read under metadata only; the service id is top-level with a
// metadata fallback. Declaring them here rather than letting the store guess is the point: a store that
// COALESCEd both depths for everything would attribute rows the row-loading path never attributes, silently.
//
// Grouping by these RAW fields rather than by the derived identity is what lets the unchanged Go logic run over
// a grouped result: identity is a pure function of them, so grouping by the inputs preserves the outcome.
var aiUsageGroupFields = []hotstore.FieldSpec{
	{Name: "tenant_id", Paths: []string{"tenant_id"}},
	{Name: "destination", Paths: []string{"destination"}},
	{Name: "saas_application_id", Paths: []string{"saas_application_id", "metadata.saas_application_id"}},
	{Name: "saas_name", Paths: []string{"saas_name", "metadata.saas_name"}},
	{Name: "user_id", Paths: []string{"user_id"}},
	{Name: "subject_user_id", Paths: []string{"subject_user_id"}},
	{Name: "actor_nhi_id", Paths: []string{"actor_nhi_id"}},
	{Name: "actor_type", Paths: []string{"actor_type"}},
	{Name: "device_id", Paths: []string{"device_id"}},
	{Name: "source_ip", Paths: []string{"source_ip"}},
	{Name: "ai_account", Paths: []string{"metadata.ai_account"}},
	{Name: "ai_email", Paths: []string{"metadata.ai_email"}},
	{Name: "ai_name", Paths: []string{"metadata.ai_name"}},
	{Name: "ai_app", Paths: []string{"metadata.ai_app"}},
}

// aiUsageGroupFieldsAtMetadata are the subset the row-reading helpers look for under "metadata". The
// reconstructed row must put each value where its reader looks, or the aggregate path would see fields the row
// path does not.
var aiUsageGroupFieldsAtMetadata = map[string]bool{
	"ai_account": true, "ai_email": true, "ai_name": true, "ai_app": true,
}

// aiUsageGroupQuery is the ONE definition of the grouping the report asks a capable store for. The handler and
// the parity tests all build it here, so a test can never pass against a query shape the handler does not use.
func aiUsageGroupQuery(tenantID string, from, to time.Time) hotstore.FieldGroupQuery {
	return hotstore.FieldGroupQuery{
		TenantID: tenantID, Stream: "access", From: &from, To: &to,
		Fields:        aiUsageGroupFields,
		BytesSent:     hotstore.FieldSpec{Name: "bytes_sent", Paths: []string{"metadata.bytes_sent"}},
		BytesReceived: hotstore.FieldSpec{Name: "bytes_received", Paths: []string{"metadata.bytes_received"}},
		MatchCount:    hotstore.FieldSpec{Name: "http_method", Paths: []string{"metadata.http_method"}},
		MatchValue:    "POST",
		BucketSeconds: aiUsageSessionBucketSeconds,
		MaxGroups:     aiUsageReportGroupCap,
		// The report states how far its records reach on the row-loading path; it has to state it here too, or
		// the fact quietly disappears the day a deployment switches backend.
		IncludeOldestMatched: true,
	}
}

// aiUsageInputsFromGroups turns a hot-store grouping back into the shape the aggregation consumes. The row it
// rebuilds carries only the grouped fields — which is exactly the set the aggregation reads, and nothing else,
// so a field someone starts reading without adding it to aiUsageGroupFields shows up as empty on this path and
// is caught by the parity test rather than by an operator.
func aiUsageInputsFromGroups(groups []hotstore.FieldGroup) []aiUsageInput {
	inputs := make([]aiUsageInput, 0, len(groups))
	for _, g := range groups {
		row := map[string]any{}
		metadata := map[string]any{}
		for _, spec := range aiUsageGroupFields {
			value := g.Fields[spec.Name]
			if value == "" {
				continue
			}
			if aiUsageGroupFieldsAtMetadata[spec.Name] {
				metadata[spec.Name] = value
			} else {
				row[spec.Name] = value
			}
		}
		if len(metadata) > 0 {
			row["metadata"] = metadata
		}
		inputs = append(inputs, aiUsageInput{
			Row:       row,
			Accesses:  g.Rows,
			Messages:  g.MatchedRows,
			BytesSent: g.BytesSent,
			BytesRecv: g.BytesReceived,
			Buckets:   g.Buckets,
		})
	}
	return inputs
}

// aiUsageInput is one PRE-GROUPED bundle of access activity: the raw row whose fields the classification ladder
// reads, plus the measures for everything that grouped into it. A row-loading caller passes one input per row
// (Accesses 1, one session bucket); a store that can GROUP BY passes one input per distinct combination of the
// raw fields, with the measures already summed and the distinct session buckets listed.
//
// Buckets is a LIST, not a count, and that is the whole reason this type exists. The report counts sessions at
// four granularities (service, identity, identity×service, activity row) by unioning bucket sets — so a bucket
// that spans two groups is ONE session at the coarser level. Pre-counting per group and summing would count it
// twice. See
type aiUsageInput struct {
	Row       map[string]any
	Accesses  int
	Messages  int
	BytesSent int64
	BytesRecv int64
	Buckets   []int64
}

// buildAIUsageReport aggregates raw access-log rows. A thin wrapper over the grouped form: every row becomes a
// group of one, so the row-loading path and any GROUP BY path run the SAME aggregation rather than two
// implementations that agree until someone edits one of them.
func buildAIUsageReport(rows []map[string]any, catalog []model.SaaSCatalogEntry, generatedAt string) aiUsageReport {
	inputs := make([]aiUsageInput, 0, len(rows))
	for _, row := range rows {
		in := aiUsageInput{Row: row, Accesses: 1, BytesSent: bytesFromRow(row, "bytes_sent"), BytesRecv: bytesFromRow(row, "bytes_received")}
		if isAIMessage(row) {
			in.Messages = 1
		}
		if bkt, ok := sessionBucket(row); ok {
			in.Buckets = []int64{bkt}
		}
		inputs = append(inputs, in)
	}
	return buildAIUsageReportFromInputs(inputs, catalog, generatedAt)
}

// actAgg is one un-aggregated (identity × device × app × service) activity row. Package-level so
// mergeUnattributedActivity can fold the rows whose app or account could not be attributed.
type actAgg struct {
	identity, itype, corp, device, app, account, service string
	email, name                                          string
	sessions                                             map[int64]bool
	accesses, messages                                   int
	bytesSent, bytesRecv                                 int64
}

func buildAIUsageReportFromInputs(inputs []aiUsageInput, catalog []model.SaaSCatalogEntry, generatedAt string) aiUsageReport {
	type agg struct {
		name      string
		gov       string
		count     int
		messages  int
		bytesSent int64
		bytesRecv int64
		sessions  map[int64]bool
	}
	type idAgg struct {
		idType      string
		corp        string
		aiAccts     map[string]bool
		devices     map[string]bool
		apps        map[string]bool
		total       int
		messages    int
		bytesSent   int64
		bytesRecv   int64
		svc         map[string]int
		svcMsg      map[string]int
		sessions    map[int64]bool
		svcSessions map[string]map[int64]bool
	}
	byApp := map[string]*agg{}
	byGov := map[string]int{}
	byID := map[string]*idAgg{}
	byActivity := map[string]*actAgg{}
	total := 0
	var totalBytesSent, totalBytesRecv int64
	for _, in := range inputs {
		row := in.Row
		appID := stringFromRow(row, "saas_application_id")
		if appID == "" {
			if md, ok := row["metadata"].(map[string]any); ok {
				appID = stringFromRow(md, "saas_application_id")
			}
		}
		inferredName := ""
		if appID == "" {
			appID, inferredName = aiUsageServiceFromDestination(row, catalog)
		}
		if appID == "" {
			continue
		}
		gov, isAI := aiServiceGovernance(appID, aiUsageCatalogForTenant(stringFromRow(row, "tenant_id"), catalog))
		if !isAI {
			continue
		}
		name := stringFromRow(row, "saas_name")
		if name == "" {
			if md, ok := row["metadata"].(map[string]any); ok {
				name = stringFromRow(md, "saas_name")
			}
		}
		if name == "" {
			name = inferredName
		}
		a := byApp[appID]
		if a == nil {
			a = &agg{name: name, gov: gov, sessions: map[int64]bool{}}
			byApp[appID] = a
		}
		if a.name == "" {
			a.name = name
		}
		a.count += in.Accesses
		byGov[gov] += in.Accesses
		total += in.Accesses
		rbSent := in.BytesSent
		rbRecv := in.BytesRecv
		a.bytesSent += rbSent
		a.bytesRecv += rbRecv
		totalBytesSent += rbSent
		totalBytesRecv += rbRecv
		for _, bkt := range in.Buckets {
			a.sessions[bkt] = true
		}
		a.messages += in.Messages
		// per-identity breakdown: WHO used which AI — keyed by corporate identity when known, else AI account.
		ident, itype, corp, aiAcct := aiIdentityFor(row)
		ia := byID[ident]
		if ia == nil {
			ia = &idAgg{idType: itype, aiAccts: map[string]bool{}, devices: map[string]bool{}, apps: map[string]bool{}, svc: map[string]int{}, svcMsg: map[string]int{}, sessions: map[int64]bool{}, svcSessions: map[string]map[int64]bool{}}
			byID[ident] = ia
		}
		if corp != "" && ia.corp == "" {
			ia.corp = corp
		}
		if aiAcct != "" {
			ia.aiAccts[aiAcct] = true
		}
		dvID := stringFromRow(row, "device_id")
		appName := appFromRow(row)
		if dvID != "" {
			ia.devices[dvID] = true
		}
		if appName != "" {
			ia.apps[appName] = true
		}
		ia.total += in.Accesses
		ia.bytesSent += rbSent
		ia.bytesRecv += rbRecv
		svcName := name
		if svcName == "" {
			svcName = appID
		}
		ia.svc[svcName] += in.Accesses
		ia.messages += in.Messages
		ia.svcMsg[svcName] += in.Messages
		for _, bkt := range in.Buckets {
			ia.sessions[bkt] = true
			if ia.svcSessions[svcName] == nil {
				ia.svcSessions[svcName] = map[int64]bool{}
			}
			ia.svcSessions[svcName][bkt] = true
		}
		// un-aggregated activity row: this exact (identity, device, app, service, account) combination, so the UI
		// shows one row per app→AI rather than lumping a user's apps and services together.
		actKey := ident + "\x1f" + dvID + "\x1f" + appName + "\x1f" + svcName + "\x1f" + aiAcct
		act := byActivity[actKey]
		if act == nil {
			act = &actAgg{identity: ident, itype: itype, corp: corp, device: dvID, app: appName, account: aiAcct, service: svcName, sessions: map[int64]bool{}}
			byActivity[actKey] = act
		}
		if corp != "" && act.corp == "" {
			act.corp = corp
		}
		if act.email == "" {
			act.email = aiEmailFromRow(row)
		}
		if act.name == "" {
			act.name = aiNameFromRow(row)
		}
		act.accesses += in.Accesses
		act.bytesSent += rbSent
		act.bytesRecv += rbRecv
		act.messages += in.Messages
		for _, bkt := range in.Buckets {
			act.sessions[bkt] = true
		}
	}
	services := make([]aiUsageReportEntry, 0, len(byApp))
	totalSessions := 0
	totalMessages := 0
	for id, a := range byApp {
		s := len(a.sessions)
		totalSessions += s
		totalMessages += a.messages
		services = append(services, aiUsageReportEntry{SaaSApplicationID: id, Name: a.name, AIGovernance: a.gov, AccessCount: a.count, Sessions: s, Messages: a.messages, BytesSent: a.bytesSent, BytesReceived: a.bytesRecv})
	}
	sort.Slice(services, func(i, j int) bool {
		if services[i].AccessCount != services[j].AccessCount {
			return services[i].AccessCount > services[j].AccessCount
		}
		return services[i].SaaSApplicationID < services[j].SaaSApplicationID
	})
	byIdentity := make([]aiUsageIdentityEntry, 0, len(byID))
	for id, ia := range byID {
		svcs := make([]aiUsageServiceCount, 0, len(ia.svc))
		for n, c := range ia.svc {
			svcs = append(svcs, aiUsageServiceCount{Name: n, AccessCount: c, Sessions: len(ia.svcSessions[n]), Messages: ia.svcMsg[n]})
		}
		sort.Slice(svcs, func(i, j int) bool {
			if svcs[i].AccessCount != svcs[j].AccessCount {
				return svcs[i].AccessCount > svcs[j].AccessCount
			}
			return svcs[i].Name < svcs[j].Name
		})
		byIdentity = append(byIdentity, aiUsageIdentityEntry{Identity: id, IdentityType: ia.idType, CorporateUser: ia.corp, AIAccounts: sortedStringSet(ia.aiAccts), Devices: sortedStringSet(ia.devices), Apps: sortedStringSet(ia.apps), TotalAccesses: ia.total, Sessions: len(ia.sessions), Messages: ia.messages, BytesSent: ia.bytesSent, BytesReceived: ia.bytesRecv, Services: svcs})
	}
	sort.Slice(byIdentity, func(i, j int) bool {
		if byIdentity[i].TotalAccesses != byIdentity[j].TotalAccesses {
			return byIdentity[i].TotalAccesses > byIdentity[j].TotalAccesses
		}
		return byIdentity[i].Identity < byIdentity[j].Identity
	})
	byActivity = mergeUnattributedActivity(byActivity)
	byActivityList := make([]aiUsageActivityEntry, 0, len(byActivity))
	for _, a := range byActivity {
		byActivityList = append(byActivityList, aiUsageActivityEntry{Identity: a.identity, IdentityType: a.itype, CorporateUser: a.corp, Device: a.device, App: a.app, AIAccount: a.account, AIEmail: a.email, AIName: a.name, Service: a.service, Sessions: len(a.sessions), Accesses: a.accesses, Messages: a.messages, BytesSent: a.bytesSent, BytesReceived: a.bytesRecv})
	}
	sort.Slice(byActivityList, func(i, j int) bool {
		ai, aj := byActivityList[i], byActivityList[j]
		ki, kj := ai.CorporateUser, aj.CorporateUser
		if ki == "" {
			ki = ai.Identity
		}
		if kj == "" {
			kj = aj.Identity
		}
		if ki != kj {
			return ki < kj
		}
		if ai.Device != aj.Device {
			return ai.Device < aj.Device
		}
		if ai.Service != aj.Service {
			return ai.Service < aj.Service
		}
		return ai.App < aj.App
	})
	shadowAI := make([]aiUsageIdentityEntry, 0)
	for _, u := range byIdentity {
		if entryIsShadowAI(u) {
			shadowAI = append(shadowAI, u)
		}
	}
	return aiUsageReport{
		// v2: the window is now caller-selectable, so "these numbers are the last 7 days" — which a v1 consumer
		// could only assume — is no longer true. window/coverage carry it explicitly.
		SchemaVersion: "admin_ai_usage_report.v2", GeneratedAt: generatedAt,
		TotalAIAccesses: total, TotalAISessions: totalSessions, TotalAIMessages: totalMessages, TotalBytesSent: totalBytesSent, TotalBytesReceived: totalBytesRecv, ByGovernance: byGov, Services: services, ByIdentity: byIdentity, ByActivity: byActivityList, ShadowAI: shadowAI, NoSecretAttestation: true,
	}
}

func stringFromRow(row map[string]any, key string) string {
	if v, ok := row[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// mergeUnattributedActivity folds "we could not tell" rows into the one answer that IS known.
//
// The activity table keys on (identity, device, app, service, AI account), and two of those are not stable
// across a single browsing session. An account is only visible on the requests that happened to carry its token
// — a chat is hundreds of requests and most of them are assets and polling, which carry nothing — and the
// endpoint agent omits the app entirely when it cannot resolve the originating process (windows-wfp
// muxAuthority appends "a=" only for a non-empty value). So one person, on one browser, in one session,
// produced three rows: an unattributed one, an "app known, account not seen" one, and an "app and account
// known" one. Reported as three different activities, which is not what happened.
//
// The rule is one rule, applied to both fields: an EMPTY value is unknown, not a category of its own. It merges
// into the known value when the surrounding (identity, device, service) has exactly one — and stays separate
// when there are two, because then merging would be a guess about which. That keeps the case this table exists
// for: a person signed into BOTH a corporate and a personal account on the same browser still gets two rows,
// which is the shadow-AI signal and must not be collapsed.
func mergeUnattributedActivity(byActivity map[string]*actAgg) map[string]*actAgg {
	// What is known per (identity, device, service): the distinct non-empty apps and accounts seen there.
	type known struct{ apps, accounts map[string]bool }
	groups := map[string]*known{}
	groupKey := func(a *actAgg) string { return a.identity + "\x1f" + a.device + "\x1f" + a.service }
	for _, a := range byActivity {
		g := groups[groupKey(a)]
		if g == nil {
			g = &known{apps: map[string]bool{}, accounts: map[string]bool{}}
			groups[groupKey(a)] = g
		}
		if a.app != "" {
			g.apps[a.app] = true
		}
		if a.account != "" {
			g.accounts[a.account] = true
		}
	}
	only := func(set map[string]bool) (string, bool) {
		if len(set) != 1 {
			return "", false
		}
		for v := range set {
			return v, true
		}
		return "", false
	}

	merged := make(map[string]*actAgg, len(byActivity))
	for _, a := range byActivity {
		g := groups[groupKey(a)]
		if a.app == "" {
			if v, ok := only(g.apps); ok {
				a.app = v
			}
		}
		if a.account == "" {
			if v, ok := only(g.accounts); ok {
				a.account = v
			}
		}
		key := a.identity + "\x1f" + a.device + "\x1f" + a.app + "\x1f" + a.service + "\x1f" + a.account
		into := merged[key]
		if into == nil {
			merged[key] = a
			continue
		}
		into.accesses += a.accesses
		into.messages += a.messages
		into.bytesSent += a.bytesSent
		into.bytesRecv += a.bytesRecv
		for bkt := range a.sessions {
			into.sessions[bkt] = true // a set: a 30-minute bucket both rows touched is ONE session
		}
		// Keep whichever row actually carried the identity detail; an empty field never overwrites a known one.
		if into.corp == "" {
			into.corp = a.corp
		}
		if into.email == "" {
			into.email = a.email
		}
		if into.name == "" {
			into.name = a.name
		}
	}
	return merged
}
