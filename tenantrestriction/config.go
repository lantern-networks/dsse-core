// Package tenantrestriction defines tenant-owned SaaS sign-in restrictions.
// Values are configuration (allowed tenant IDs/domains), never credentials.
package tenantrestriction

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/lantern-networks/dsse-core/model"
)

type Setting struct {
	AllowedValue    string `json:"allowed_value,omitempty"`
	ContextTenantID string `json:"context_tenant_id,omitempty"`
	Enabled         bool   `json:"enabled"`
}

type Provider struct {
	ID, AppID, Name, Header, Kind string
	Hosts                         []string
}

// Only provider sign-in/API hosts are included; matching never uses a substring.
func Providers() []Provider {
	return []Provider{
		{"google_workspace", "saas_google_workspace", "Google Workspace", "X-GoogApps-Allowed-Domains", "allowed_domains", []string{"google.com", "*.google.com", "googleapis.com", "*.googleapis.com", "googleusercontent.com", "*.googleusercontent.com"}},
		{"microsoft_365", "saas_microsoft_365", "Microsoft 365", "Restrict-Access-To-Tenants", "allowed_tenant_ids", []string{"login.microsoftonline.com", "login.microsoft.com", "login.windows.net"}},
		{"anthropic_claude", "saas_anthropic_claude", "Anthropic Claude", "anthropic-allowed-org-ids", "allowed_org_ids", []string{"claude.ai", "*.claude.ai", "claude.com", "*.claude.com", "anthropic.com", "*.anthropic.com"}},
		{"openai_chatgpt", "saas_openai_chatgpt", "OpenAI ChatGPT", "chatgpt-allowed-workspace-id", "allowed_workspace_id", []string{"chatgpt.com", "*.chatgpt.com", "chat.openai.com"}},
	}
}
func Lookup(id string) (Provider, bool) {
	for _, p := range Providers() {
		if p.ID == id {
			return p, true
		}
	}
	return Provider{}, false
}
func Ref(tenant, provider string) string {
	return "operator_config_ref:tenant_restriction/" + url.PathEscape(tenant) + "/" + provider
}
func Rule(tenant string, p Provider, s Setting) model.SWGTenantRestrictionRule {
	status := "inactive"
	if s.Enabled {
		status = "active"
	}
	r := model.SWGTenantRestrictionRule{ID: "tr/" + url.PathEscape(tenant) + "/" + p.ID, TenantID: tenant, SaaSApplicationID: p.AppID, Provider: p.ID, HeaderName: p.Header, HeaderValueRef: Ref(tenant, p.ID), HeaderValueKind: p.Kind, EnforcementMode: "header_injection", Status: status}
	if p.ID == "microsoft_365" {
		r.Metadata = map[string]any{"restriction_context_ref": Ref(tenant, p.ID) + "/context"}
	}
	return r
}
func Catalog(tenant string, p Provider) model.SaaSCatalogEntry {
	return model.SaaSCatalogEntry{TenantID: tenant, SaaSApplicationID: p.AppID, Name: p.Name, Provider: p.ID, Category: "saas", DomainPatterns: append([]string(nil), p.Hosts...)}
}

var guid = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var workspace = regexp.MustCompile(`^[A-Za-z0-9_-]{1,256}$`)
var domain = regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func Validate(provider string, s Setting) (Setting, error) {
	_, ok := Lookup(provider)
	if !ok {
		return s, fmt.Errorf("unknown SaaS provider")
	}
	if len(s.AllowedValue) > 8192 || strings.ContainsAny(s.AllowedValue, "\r\n\x00") {
		return s, fmt.Errorf("invalid allowed value")
	}
	var values []string
	seen := map[string]bool{}
	for _, raw := range strings.Split(s.AllowedValue, ",") {
		v := strings.TrimSpace(raw)
		if provider != "openai_chatgpt" {
			v = strings.ToLower(v)
		}
		if v == "" {
			if strings.TrimSpace(s.AllowedValue) != "" {
				return s, fmt.Errorf("empty item in allowed list")
			}
			continue
		}
		valid := false
		switch provider {
		case "google_workspace":
			valid = len(v) <= 253 && domain.MatchString(v)
		case "microsoft_365":
			valid = guid.MatchString(v) || (len(v) <= 253 && domain.MatchString(v))
		case "anthropic_claude":
			valid = guid.MatchString(v)
		case "openai_chatgpt":
			valid = workspace.MatchString(v) && !strings.Contains(s.AllowedValue, ",")
		}
		if !valid {
			return s, fmt.Errorf("invalid allowed value for %s", provider)
		}
		if !seen[v] {
			values = append(values, v)
			seen[v] = true
		}
	}
	s.AllowedValue = strings.Join(values, ",")
	s.ContextTenantID = strings.ToLower(strings.TrimSpace(s.ContextTenantID))
	if s.ContextTenantID != "" && (provider != "microsoft_365" || !guid.MatchString(s.ContextTenantID)) {
		return s, fmt.Errorf("context tenant must be a Microsoft Entra directory ID")
	}
	if s.Enabled && (s.AllowedValue == "" || (provider == "microsoft_365" && s.ContextTenantID == "")) {
		return s, fmt.Errorf("configure allowed values and the required context tenant before enabling")
	}
	return s, nil
}
func Copy(in map[string]Setting) map[string]Setting {
	out := map[string]Setting{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
