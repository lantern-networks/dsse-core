package idpregistry

import (
	"path/filepath"
	"testing"
)

func sampleConn(tenant, id string) Connection {
	return Connection{
		IdPID: id, TenantID: tenant, Type: "oidc",
		Issuer: "https://" + id + ".example.com", AuthorizationEndpoint: "https://" + id + ".example.com/authorize",
		ClientID: "client-" + id, VerifiedDomains: []string{"example.com"},
	}
}

func TestUpsertValidationAndDefaults(t *testing.T) {
	s := NewStore()
	if _, err := s.Upsert(Connection{TenantID: "t1", Issuer: "x", AuthorizationEndpoint: "y", ClientID: "z"}); err == nil {
		t.Fatal("missing idp_id must fail")
	}
	if _, err := s.Upsert(Connection{IdPID: "idp_a", TenantID: "t1", AuthorizationEndpoint: "y", ClientID: "z"}); err == nil {
		t.Fatal("missing issuer must fail")
	}
	c, err := s.Upsert(sampleConn("t1", "idp_a"))
	if err != nil {
		t.Fatalf("valid upsert: %v", err)
	}
	if c.DomainMode != "email_domain" {
		t.Fatalf("domain_mode default = %q, want email_domain", c.DomainMode)
	}
	// first connection becomes the default
	def, ok := s.Default("t1")
	if !ok || def.IdPID != "idp_a" {
		t.Fatalf("first connection should be the default, got ok=%v id=%q", ok, def.IdPID)
	}
}

func TestResolveDefaultAndPerPolicyAndFailClosed(t *testing.T) {
	s := NewStore()
	_, _ = s.Upsert(sampleConn("t1", "idp_default"))
	_, _ = s.Upsert(sampleConn("t1", "idp_partner"))

	// no required id -> tenant default
	c, ok := s.Resolve("t1", "")
	if !ok || c.IdPID != "idp_default" {
		t.Fatalf("empty resolve should give the default, got ok=%v id=%q", ok, c.IdPID)
	}
	// explicit registered id -> that one
	c, ok = s.Resolve("t1", "idp_partner")
	if !ok || c.IdPID != "idp_partner" {
		t.Fatalf("explicit resolve should give the named idp, got ok=%v id=%q", ok, c.IdPID)
	}
	// explicit UNREGISTERED id -> fail closed (not the default)
	if _, ok := s.Resolve("t1", "idp_unknown"); ok {
		t.Fatal("an unregistered required IdP must resolve to not-found (fail closed), not the default")
	}
}

func TestSetDefaultAndDeleteGuards(t *testing.T) {
	s := NewStore()
	_, _ = s.Upsert(sampleConn("t1", "idp_a"))
	_, _ = s.Upsert(sampleConn("t1", "idp_b"))
	if err := s.SetDefault("t1", "idp_unknown"); err == nil {
		t.Fatal("setting an unregistered default must fail")
	}
	if err := s.SetDefault("t1", "idp_b"); err != nil {
		t.Fatalf("set default: %v", err)
	}
	// idp_b is now default and others exist -> cannot delete it
	if _, err := s.Delete("t1", "idp_b"); err == nil {
		t.Fatal("deleting the default while others exist must fail")
	}
	// non-default deletes fine
	if ok, err := s.Delete("t1", "idp_a"); err != nil || !ok {
		t.Fatalf("delete non-default: ok=%v err=%v", ok, err)
	}
	// now idp_b is the last one -> deletable
	if ok, err := s.Delete("t1", "idp_b"); err != nil || !ok {
		t.Fatalf("delete last: ok=%v err=%v", ok, err)
	}
}

func TestRedactDropsSecret(t *testing.T) {
	c := sampleConn("t1", "idp_a")
	c.ClientSecret = "super-secret"
	if c.Redacted().ClientSecret != "" {
		t.Fatal("Redacted must drop the client secret")
	}
	if c.ClientSecret != "super-secret" {
		t.Fatal("Redacted must not mutate the original")
	}
}

func TestPersistAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "idp.json")
	s1 := NewStore()
	if err := s1.SetStatePath(path); err != nil {
		t.Fatalf("SetStatePath: %v", err)
	}
	_, _ = s1.Upsert(sampleConn("t1", "idp_a"))
	_, _ = s1.Upsert(sampleConn("t1", "idp_b"))
	_ = s1.SetDefault("t1", "idp_b")

	s2 := NewStore()
	if err := s2.SetStatePath(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got := len(s2.List("t1")); got != 2 {
		t.Fatalf("connections did not survive restart: %d", got)
	}
	if def, ok := s2.Default("t1"); !ok || def.IdPID != "idp_b" {
		t.Fatalf("default did not survive restart: ok=%v id=%q", ok, def.IdPID)
	}
}

// ★ A BLANK WRITE-ONLY SECRET MEANS "UNCHANGED" (2026-09-03, measured: an edit through the Console erased it
// and the next sign-in failed at the token exchange).
func TestEditingAConnectionKeepsAWriteOnlySecret(t *testing.T) {
	s := NewStore()
	if _, err := s.Upsert(Connection{IdPID: "kc", TenantID: "t1", Type: "oidc",
		Issuer: "https://idp.example/realms/x", AuthorizationEndpoint: "https://idp.example/authorize",
		ClientID: "dsse-edge", ClientSecret: "local-secret"}); err != nil {
		t.Fatal(err)
	}
	// The shape the Console sends when an operator edits an endpoint and leaves the secret field blank.
	if _, err := s.Upsert(Connection{IdPID: "kc", TenantID: "t1", Type: "oidc",
		Issuer: "https://idp.example/realms/x", AuthorizationEndpoint: "https://idp.example/authorize",
		ClientID: "dsse-edge"}); err != nil {
		t.Fatal(err)
	}
	got, ok := s.Get("t1", "kc")
	if !ok {
		t.Fatal("the connection vanished")
	}
	if got.ClientSecret != "local-secret" {
		t.Errorf("the secret did not survive an edit that left it blank: %q — the screen promises it does, "+
			"and a sign-in fails at the token exchange when it does not", got.ClientSecret)
	}
	// Setting it explicitly still replaces it.
	if _, err := s.Upsert(Connection{IdPID: "kc", TenantID: "t1", Type: "oidc",
		Issuer: "https://idp.example/realms/x", AuthorizationEndpoint: "https://idp.example/authorize",
		ClientID: "dsse-edge", ClientSecret: "rotated"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get("t1", "kc"); got.ClientSecret != "rotated" {
		t.Errorf("an explicit secret no longer replaces the old one: %q", got.ClientSecret)
	}
}
