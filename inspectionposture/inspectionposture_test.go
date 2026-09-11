package inspectionposture

import (
	"path/filepath"
	"reflect"
	"testing"
)

func TestEffectiveInterceptHostsDecryptAll(t *testing.T) {
	if got := EffectiveInterceptHosts(DefaultPosture()); !reflect.DeepEqual(got, []string{"*"}) {
		t.Fatalf("decrypt-all intercept hosts = %v, want [*]", got)
	}
}

func TestEffectiveInterceptHostsBypassDefault(t *testing.T) {
	p := Posture{
		Mode:                   ModeBypassDefault,
		DecryptAllowlistHosts:  []string{"wiki.corp", "WIKI.corp", " "},
		DecryptAllowlistGroups: []string{"m365_auth", "nonexistent_group", "m365_auth"},
	}
	got := EffectiveInterceptHosts(p)
	// explicit host (deduped/lowercased) + the m365 group's patterns; unknown group ignored.
	want := []string{"wiki.corp", "login.microsoftonline.com", "login.microsoft.com", "login.windows.net", "login.live.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("bypass-default intercept hosts = %v, want %v", got, want)
	}
}

func TestEffectiveInterceptHostsEmptyBypassDefault(t *testing.T) {
	if got := EffectiveInterceptHosts(Posture{Mode: ModeBypassDefault}); len(got) != 0 {
		t.Fatalf("empty bypass-default allowlist should decrypt nothing, got %v", got)
	}
}

func TestNormalizedDropsUnknownGroupAndBadMode(t *testing.T) {
	p := Posture{
		Mode:                   "garbage",
		DecryptAllowlistGroups: []string{"google_auth", "bogus"},
		BypassGroups:           []string{"m365_optimize", "m365_auth", "nope"}, // m365_auth is an auth group, not a bypass group
	}.Normalized()
	if p.Mode != ModeDecryptAll {
		t.Fatalf("unknown mode should normalize to decrypt_all, got %q", p.Mode)
	}
	if !reflect.DeepEqual(p.DecryptAllowlistGroups, []string{"google_auth"}) {
		t.Fatalf("unknown allowlist group should be dropped, got %v", p.DecryptAllowlistGroups)
	}
	if !reflect.DeepEqual(p.BypassGroups, []string{"m365_optimize"}) {
		t.Fatalf("only known SaaS bypass groups should remain, got %v", p.BypassGroups)
	}
}

func TestEffectiveBypassGroupHosts(t *testing.T) {
	got := EffectiveBypassGroupHosts(Posture{BypassGroups: []string{"m365_optimize", "unknown"}})
	if len(got) == 0 || !contains(got, "*.sharepoint.com") {
		t.Fatalf("m365_optimize should expand to its patterns, got %v", got)
	}
	if n := len(EffectiveBypassGroupHosts(Posture{})); n != 0 {
		t.Fatalf("no bypass groups => no hosts, got %d", n)
	}
}

func TestCatalogCategoriesAndAIPresence(t *testing.T) {
	// AuthDecryptPatterns must be sign-in ONLY (so selecting an AI group does not silence the tenant-restriction
	// warning) — it must include a sign-in host and exclude an AI host.
	pats := AuthDecryptPatterns()
	if !contains(pats, "login.microsoftonline.com") {
		t.Fatalf("sign-in patterns should include login.microsoftonline.com")
	}
	if contains(pats, "api.openai.com") {
		t.Fatalf("AuthDecryptPatterns must NOT include AI hosts (they don't count for tenant restriction)")
	}
	// The catalog must carry AI groups, categorized.
	var haveOpenAI, haveAnthropic bool
	for _, g := range AuthDecryptGroups {
		if g.Category == "" {
			t.Fatalf("every decrypt group must have a category: %s", g.Name)
		}
		if g.Name == "openai" {
			haveOpenAI = g.Category == CategoryAI
		}
		if g.Name == "anthropic" {
			haveAnthropic = g.Category == CategoryAI
		}
	}
	if !haveOpenAI || !haveAnthropic {
		t.Fatalf("AI catalog must include openai + anthropic in category ai")
	}
	for _, g := range SaaSBypassGroups {
		if g.Category != CategoryOptimize {
			t.Fatalf("bypass group %s should be category optimize, got %q", g.Name, g.Category)
		}
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestStorePersistsAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inspection_posture.json")
	s1 := NewStore()
	if loaded, err := s1.SetStatePath(path); err != nil || loaded {
		t.Fatalf("fresh store: loaded=%v err=%v, want false/nil", loaded, err)
	}
	if _, err := s1.Set(Posture{Mode: ModeBypassDefault, DecryptAllowlistGroups: []string{"m365_auth"}, KnownBypassEnabled: false}); err != nil {
		t.Fatalf("set posture: %v", err)
	}

	s2 := NewStore()
	loaded, err := s2.SetStatePath(path)
	if err != nil || !loaded {
		t.Fatalf("reload: loaded=%v err=%v, want true/nil", loaded, err)
	}
	got := s2.Get()
	if got.Mode != ModeBypassDefault || got.KnownBypassEnabled || !reflect.DeepEqual(got.DecryptAllowlistGroups, []string{"m365_auth"}) {
		t.Fatalf("reloaded posture = %#v, want bypass_default / known-bypass off / [m365_auth]", got)
	}
}
