// Package inspectionposture holds the durable default inspection posture: whether the Edge decrypts every
// steered HTTPS flow (decrypt-all) or only a decrypt allowlist (bypass-default), plus the known-bypass toggle.
// It is the data-plane state behind docs/invisible_effective_configuration.md — making the formerly-invisible,
// hardcoded decrypt-all default a visible, editable, persisted choice. Steer-all is unaffected: a bypassed
// flow is still steered and policy-gated; the Edge merely declines to terminate its TLS.
package inspectionposture

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"sync"

	"github.com/lantern-networks/dsse-core/durablefile"
)

// Modes.
const (
	ModeDecryptAll    = "decrypt_all"    // intercept "*": decrypt everything except the bypass set.
	ModeBypassDefault = "bypass_default" // decrypt ONLY the allowlist; bypass (raw-forward) everything else.
)

// AuthDecryptGroup is a curated set of SaaS authentication hostnames that must be DECRYPTED to enforce tenant
// restriction (the Edge injects the tenant-restriction header into the decrypted sign-in request). In
// bypass-default mode an operator allowlists these so a flip to bypass-default does NOT silently disable tenant
// restriction — the per-endpoint-group preset (auth=Inspect) from the design docs.
type AuthDecryptGroup struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"` // sign_in | ai | collaboration (decrypt catalog) | optimize (bypass catalog)
	Description string   `json:"description"`
	Patterns    []string `json:"patterns"`
}

// Decrypt-catalog categories.
const (
	CategorySignIn        = "sign_in"       // SaaS sign-in — decrypt to enforce tenant restriction / session controls.
	CategoryAI            = "ai"            // AI assistants/APIs — decrypt for DLP / NHI-AI governance / prompt inspection.
	CategoryCollaboration = "collaboration" // collaboration suites — decrypt for DLP.
	CategoryOptimize      = "optimize"      // (bypass catalog) high-volume bulk/media — raw-forward.
)

// AuthDecryptGroups is the built-in catalog of SaaS host groups worth DECRYPTING even under bypass-default —
// sign-in (tenant restriction), AI assistants (DLP / AI-agent governance), and collaboration suites (DLP).
// Mirrors knownbypass.Groups but for the decrypt allowlist (the opposite axis). Operators extend it with hosts.
var AuthDecryptGroups = []AuthDecryptGroup{
	// --- Sign-in (tenant restriction) ---
	{Name: "m365_auth", Category: CategorySignIn, Description: "Microsoft 365 / Entra ID sign-in — decrypt to inject Restrict-Access-To-Tenants.",
		Patterns: []string{"login.microsoftonline.com", "login.microsoft.com", "login.windows.net", "login.live.com"}},
	{Name: "google_auth", Category: CategorySignIn, Description: "Google Workspace sign-in — decrypt to inject X-GoogApps-Allowed-Domains.",
		Patterns: []string{"accounts.google.com", "accounts.youtube.com"}},
	{Name: "okta_auth", Category: CategorySignIn, Description: "Okta sign-in — decrypt to enforce session / tenant controls.",
		Patterns: []string{"*.okta.com", "*.oktapreview.com", "*.okta-emea.com"}},
	{Name: "salesforce_auth", Category: CategorySignIn, Description: "Salesforce sign-in — decrypt to enforce login / session controls.",
		Patterns: []string{"login.salesforce.com", "test.salesforce.com", "*.my.salesforce.com"}},
	{Name: "onelogin_auth", Category: CategorySignIn, Description: "OneLogin sign-in (IdP).",
		Patterns: []string{"*.onelogin.com"}},
	{Name: "ping_auth", Category: CategorySignIn, Description: "Ping Identity (PingOne / PingFederate) sign-in.",
		Patterns: []string{"*.pingone.com", "*.pingidentity.com"}},
	{Name: "github_auth", Category: CategorySignIn, Description: "GitHub sign-in / org SSO.",
		Patterns: []string{"github.com"}},

	// --- AI assistants / APIs (DLP, NHI-AI governance, prompt inspection) ---
	{Name: "openai", Category: CategoryAI, Description: "OpenAI ChatGPT + API — decrypt for DLP / agent governance.",
		Patterns: []string{"chatgpt.com", "chat.openai.com", "api.openai.com", "platform.openai.com"}},
	{Name: "anthropic", Category: CategoryAI, Description: "Anthropic Claude + API. Covers ALL domains Anthropic's tenant restriction (anthropic-allowed-org-ids) targets: claude.ai, claude.com, api.anthropic.com, anthropic.com.",
		Patterns: []string{"claude.ai", "*.claude.ai", "claude.com", "*.claude.com", "anthropic.com", "*.anthropic.com"}},
	{Name: "google_gemini", Category: CategoryAI, Description: "Google Gemini / AI Studio / Generative Language API.",
		Patterns: []string{"gemini.google.com", "aistudio.google.com", "generativelanguage.googleapis.com"}},
	{Name: "microsoft_copilot", Category: CategoryAI, Description: "Microsoft Copilot.",
		Patterns: []string{"copilot.microsoft.com", "*.copilot.microsoft.com"}},
	{Name: "github_copilot", Category: CategoryAI, Description: "GitHub Copilot (IDE/agent traffic).",
		Patterns: []string{"api.githubcopilot.com", "*.githubcopilot.com", "copilot-proxy.githubusercontent.com"}},
	{Name: "perplexity", Category: CategoryAI, Description: "Perplexity AI.",
		Patterns: []string{"www.perplexity.ai", "*.perplexity.ai"}},
	{Name: "mistral", Category: CategoryAI, Description: "Mistral AI (Le Chat / API).",
		Patterns: []string{"chat.mistral.ai", "*.mistral.ai"}},
	{Name: "cohere", Category: CategoryAI, Description: "Cohere API / dashboard.",
		Patterns: []string{"api.cohere.ai", "api.cohere.com", "dashboard.cohere.com"}},
	{Name: "huggingface", Category: CategoryAI, Description: "Hugging Face (models / inference).",
		Patterns: []string{"huggingface.co", "*.huggingface.co", "*.hf.co"}},
	{Name: "deepseek", Category: CategoryAI, Description: "DeepSeek (chat / API) — high usage incl. Japan.",
		Patterns: []string{"deepseek.com", "chat.deepseek.com", "*.deepseek.com"}},
	{Name: "xai_grok", Category: CategoryAI, Description: "Grok (xAI).",
		Patterns: []string{"grok.com", "*.grok.com", "x.ai", "api.x.ai"}},
	{Name: "poe", Category: CategoryAI, Description: "Poe (Quora) — multi-model AI.",
		Patterns: []string{"poe.com", "*.poe.com"}},
	{Name: "meta_ai", Category: CategoryAI, Description: "Meta AI.",
		Patterns: []string{"meta.ai", "*.meta.ai"}},
	{Name: "alibaba_qwen", Category: CategoryAI, Description: "Alibaba Qwen / Tongyi (Chinese).",
		Patterns: []string{"chat.qwen.ai", "qwen.ai", "tongyi.aliyun.com", "*.tongyi.aliyun.com"}},
	{Name: "moonshot_kimi", Category: CategoryAI, Description: "Kimi (Moonshot AI, Chinese).",
		Patterns: []string{"kimi.com", "www.kimi.com", "kimi.moonshot.cn", "*.moonshot.cn"}},
	{Name: "bytedance_doubao", Category: CategoryAI, Description: "Doubao (ByteDance, Chinese).",
		Patterns: []string{"doubao.com", "www.doubao.com", "*.doubao.com"}},
	{Name: "felo", Category: CategoryAI, Description: "Felo AI search (popular in Japan).",
		Patterns: []string{"felo.ai", "*.felo.ai"}},

	// --- Collaboration suites (DLP) ---
	{Name: "slack", Category: CategoryCollaboration, Description: "Slack (messaging / files).",
		Patterns: []string{"app.slack.com", "*.slack.com"}},
	{Name: "zoom", Category: CategoryCollaboration, Description: "Zoom (web / sign-in).",
		Patterns: []string{"*.zoom.us"}},
	{Name: "atlassian", Category: CategoryCollaboration, Description: "Atlassian (Jira / Confluence).",
		Patterns: []string{"*.atlassian.net", "id.atlassian.com"}},
	{Name: "box", Category: CategoryCollaboration, Description: "Box (content).",
		Patterns: []string{"*.box.com", "account.box.com"}},
	{Name: "dropbox", Category: CategoryCollaboration, Description: "Dropbox (content).",
		Patterns: []string{"www.dropbox.com", "*.dropbox.com"}},
	{Name: "notion", Category: CategoryCollaboration, Description: "Notion.",
		Patterns: []string{"www.notion.so", "*.notion.so"}},
}

// AuthDecryptPatterns is the flattened set of SIGN-IN patterns (category sign_in only) — used to detect whether
// a posture still decrypts SOME sign-in path so tenant restriction can work. AI/collaboration groups are NOT
// counted here: selecting only an AI group must NOT silence the "tenant restriction at risk" warning.
func AuthDecryptPatterns() []string {
	out := []string{}
	for _, g := range AuthDecryptGroups {
		if g.Category == CategorySignIn {
			out = append(out, g.Patterns...)
		}
	}
	return out
}

// SaaSBypassGroup is a curated set of high-volume SaaS endpoints that are typically NOT worth decrypting and
// that the vendor recommends NOT to TLS-intercept (large opaque/pinned uploads, real-time media). Enabling a
// group raw-forwards those hosts even under decrypt-all — the Optimize=Bypass half of the per-endpoint-group
// preset (docs/default_inspection_posture_problem_and_design.md). Distinct from the always-on known-bypass list
// (OS/cert infra): these are SaaS bulk paths an operator opts into bypassing.
type SaaSBypassGroup = AuthDecryptGroup

// SaaSBypassGroups is the built-in catalog of SaaS Optimize/bulk host groups recommended for raw-forward.
var SaaSBypassGroups = []SaaSBypassGroup{
	{Name: "m365_optimize", Category: CategoryOptimize, Description: "Microsoft 365 Optimize — Teams media, OneDrive/SharePoint sync (Microsoft: do not proxy).",
		Patterns: []string{"*.teams.microsoft.com", "*.sharepoint.com", "*.sharepointonline.com", "*.svc.ms", "*.onedrive.com"}},
	{Name: "google_optimize", Category: CategoryOptimize, Description: "Google bulk content — Drive/Docs content, YouTube media (large, often pinned).",
		Patterns: []string{"*.googlevideo.com", "*.googleusercontent.com", "*.drive.google.com", "*.docs.google.com"}},
	{Name: "slack_media", Category: CategoryOptimize, Description: "Slack file/CDN bulk paths (not the app/sign-in).",
		Patterns: []string{"files.slack.com", "*.slack-edge.com", "*.slack-files.com"}},
	{Name: "zoom_media", Category: CategoryOptimize, Description: "Zoom real-time media CDN.",
		Patterns: []string{"*.zoom.us.cdn.cloudflare.net", "*.cloudfront.zoom.us"}},
}

// Posture is the persisted inspection posture. For bypass-default, DecryptAllowlistHosts are explicit host
// patterns ("*.suffix" allowed) and DecryptAllowlistGroups names entries from AuthDecryptGroups.
type Posture struct {
	Mode                   string   `json:"mode"`
	DecryptAllowlistHosts  []string `json:"decrypt_allowlist_hosts"`
	DecryptAllowlistGroups []string `json:"decrypt_allowlist_groups"`
	// BypassGroups retains legacy deployment-wide selections for operator cleanup.
	// Current runtimes use tenant-authored rules; these selections do not grant bypass.
	BypassGroups       []string `json:"bypass_groups"`
	KnownBypassEnabled bool     `json:"known_bypass_enabled"`
}

// DefaultPosture is decrypt-all with the curated known-bypass list on — the historical default, now explicit.
func DefaultPosture() Posture {
	return Posture{Mode: ModeDecryptAll, KnownBypassEnabled: true}
}

// Normalized returns a copy with a valid mode (unknown -> decrypt_all) and trimmed/deduped allowlists.
func (p Posture) Normalized() Posture {
	out := Posture{Mode: p.Mode, KnownBypassEnabled: p.KnownBypassEnabled}
	if out.Mode != ModeBypassDefault {
		out.Mode = ModeDecryptAll
	}
	out.DecryptAllowlistHosts = dedupeLower(p.DecryptAllowlistHosts)
	out.DecryptAllowlistGroups = filterKnownGroups(p.DecryptAllowlistGroups, AuthDecryptGroups)
	out.BypassGroups = filterKnownGroups(p.BypassGroups, SaaSBypassGroups)
	return out
}

// EffectiveInterceptHosts returns the intercept (decrypt) host set for the posture: ["*"] under decrypt-all,
// otherwise the allowlist (explicit hosts + every named group's patterns), so ONLY those are decrypted and
// everything else is raw-forwarded. An empty bypass-default allowlist decrypts nothing.
func EffectiveInterceptHosts(p Posture) []string {
	if p.Mode != ModeBypassDefault {
		return []string{"*"}
	}
	seen := map[string]bool{}
	out := []string{}
	add := func(h string) {
		h = strings.TrimSpace(strings.ToLower(h))
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, h := range p.DecryptAllowlistHosts {
		add(h)
	}
	for _, name := range p.DecryptAllowlistGroups {
		for _, g := range AuthDecryptGroups {
			if g.Name == name {
				for _, pat := range g.Patterns {
					add(pat)
				}
			}
		}
	}
	return out
}

// EffectiveBypassGroupHosts returns the host patterns of every enabled SaaS Optimize bypass group — folded into
// the engine's raw-forward set in any mode (the Optimize=Bypass preset).
func EffectiveBypassGroupHosts(p Posture) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, name := range p.BypassGroups {
		for _, g := range SaaSBypassGroups {
			if g.Name == name {
				for _, pat := range g.Patterns {
					pat = strings.TrimSpace(strings.ToLower(pat))
					if pat != "" && !seen[pat] {
						seen[pat] = true
						out = append(out, pat)
					}
				}
			}
		}
	}
	return out
}

// filterKnownGroups keeps only catalog group names, trimmed and deduped (preserving order).
func filterKnownGroups(names []string, catalog []AuthDecryptGroup) []string {
	known := map[string]bool{}
	for _, g := range catalog {
		known[g.Name] = true
	}
	seen := map[string]bool{}
	out := []string{}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] || !known[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

func dedupeLower(in []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, s := range in {
		s = strings.TrimSpace(strings.ToLower(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// Store persists the posture across restarts (a posture change survives an Edge restart, unlike the previous
// runtime-only known-bypass toggle).
type Store struct {
	writeMu   sync.Mutex
	mu        sync.RWMutex
	posture   Posture
	statePath string
	// persister is the fleet-shared backend, when the deployment has one.
	//
	// ★★ THIS POSTURE IS ENFORCEMENT, AND IT DIFFERED BETWEEN TWO EDGES OF ONE FLEET (2026-08-21, measured).
	// Read by the same customer administrator from two Edges seconds apart, /admin/inspection-posture answered
	// decrypt_allowlist_hosts=["accounts.google.com"] on one and [] on the other, because the store was a file
	// and only one node had been given a path for it. Which Edge a flow lands on then decides whether it is
	// decrypted. A file path stays supported and still wins when it is set explicitly; a deployment with
	// shared state and no explicit path shares this too.
	persister persister
	// generation advances on every change, so the control plane's config bundle can carry this posture and an
	// Edge can tell a new one from the one it already applied.
	//
	// ★★★ A SECTION THAT DOES NOT MOVE THIS NUMBER NEVER TRAVELS (2026-08-23). An Edge applies a bundle only
	// when the aggregate generation is newer, so a posture change would alter the bundle's CONTENTS and not its
	// VERSION, and no Edge would re-pull for it. Measured on the Site catalogue the day before: published
	// correctly in every bundle, applied by nobody.
	generation uint64
}

// ConfigGeneration is this store's contribution to the config bundle's aggregate generation. Monotonic within a
// process; a restart resets it, which the bundle's epoch already covers.
func (s *Store) ConfigGeneration() uint64 {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.generation
}

// persister is blobstore.Persister, declared here so this package keeps no dependency it does not need. Go
// interfaces are structural, so the shared implementation satisfies it as it is.
type persister interface {
	Load() ([]byte, error)
	Save(data []byte) error
}

func NewStore() *Store { return &Store{posture: DefaultPosture()} }

// Get returns an independent snapshot; callers cannot mutate enforcement through a returned slice.
func (s *Store) Get() Posture {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return clonePosture(s.posture)
}

var ErrPersistence = errors.New("inspection posture persistence is unconfirmed")

// Set validates and saves a candidate before exposing it to enforcement or bundle readers.
func (s *Store) Set(p Posture) (Posture, error) {
	next, err := Validate(p)
	if err != nil {
		return Posture{}, err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if err := s.persist(next); err != nil {
		return Posture{}, fmt.Errorf("%w: %v", ErrPersistence, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !reflect.DeepEqual(s.posture, next) {
		s.posture = next
		s.generation++
	}
	return clonePosture(s.posture), nil
}

// Configure a writer only after its existing snapshot has been validated.
func (s *Store) SetPersister(p persister) (bool, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	var data []byte
	var err error
	if p != nil {
		data, err = p.Load()
		if err != nil {
			return false, err
		}
	}
	loaded, next, err := decodeSnapshot(data, data != nil)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.persister = p
	s.statePath = ""
	if loaded && !reflect.DeepEqual(s.posture, next) {
		s.posture = next
		s.generation++
	}
	return loaded, nil
}
func (s *Store) SetStatePath(path string) (bool, error) {
	path = strings.TrimSpace(path)
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	var data []byte
	exists := false
	if path != "" {
		var err error
		data, err = os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return false, err
		}
		exists = err == nil
	}
	loaded, next, err := decodeSnapshot(data, exists)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.statePath = path
	s.persister = nil
	if loaded && !reflect.DeepEqual(s.posture, next) {
		s.posture = next
		s.generation++
	}
	return loaded, nil
}
func decodeSnapshot(data []byte, exists bool) (bool, Posture, error) {
	if !exists {
		return false, Posture{}, nil
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return false, Posture{}, fmt.Errorf("empty inspection posture snapshot")
	}
	var shape map[string]json.RawMessage
	if err := json.Unmarshal(data, &shape); err != nil {
		return false, Posture{}, err
	}
	if shape == nil || shape["mode"] == nil || shape["known_bypass_enabled"] == nil || string(shape["known_bypass_enabled"]) == "null" {
		return false, Posture{}, fmt.Errorf("incomplete inspection posture snapshot")
	}
	var p Posture
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&p); err != nil {
		return false, Posture{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return false, Posture{}, fmt.Errorf("unexpected trailing posture data")
	}
	next, err := Validate(p)
	return err == nil, next, err
}
func clonePosture(p Posture) Posture {
	p.DecryptAllowlistHosts = append([]string{}, p.DecryptAllowlistHosts...)
	p.DecryptAllowlistGroups = append([]string{}, p.DecryptAllowlistGroups...)
	p.BypassGroups = append([]string{}, p.BypassGroups...)
	return p
}

// Validate refuses settings that normalization would silently discard or that never match a host.
func Validate(p Posture) (Posture, error) {
	if p.Mode != ModeDecryptAll && p.Mode != ModeBypassDefault {
		return Posture{}, fmt.Errorf("invalid inspection mode")
	}
	for _, set := range []struct {
		values  []string
		catalog []AuthDecryptGroup
	}{{p.DecryptAllowlistGroups, AuthDecryptGroups}, {p.BypassGroups, SaaSBypassGroups}} {
		for _, name := range set.values {
			found := false
			for _, g := range set.catalog {
				if strings.TrimSpace(name) == g.Name {
					found = true
					break
				}
			}
			if !found {
				return Posture{}, fmt.Errorf("unknown inspection preset")
			}
		}
	}
	for _, host := range p.DecryptAllowlistHosts {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			continue
		}
		if host == "*" {
			continue
		}
		if ip := net.ParseIP(host); ip != nil {
			if strings.Contains(host, ":") {
				return Posture{}, fmt.Errorf("IPv6 literal inspection patterns are not supported; use a DNS hostname")
			}
			continue
		}
		host = strings.TrimPrefix(host, "*.")
		host = strings.TrimSuffix(host, ".")
		if len(host) == 0 || len(host) > 253 {
			return Posture{}, fmt.Errorf("invalid inspection host pattern")
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return Posture{}, fmt.Errorf("invalid inspection host pattern")
			}
			for _, r := range label {
				if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
					return Posture{}, fmt.Errorf("use a hostname or *.suffix, without a URL, path or port")
				}
			}
		}
	}
	return p.Normalized(), nil
}
func (s *Store) persist(next Posture) error {
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return err
	}
	if s.persister != nil {
		return s.persister.Save(data)
	}
	if s.statePath == "" {
		return nil
	}
	return durablefile.Write(s.statePath, data, 0o600)
}
