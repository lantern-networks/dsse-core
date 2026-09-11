package policyrule

import (
	"errors"
	"testing"
)

func ewRule() Rule {
	return Rule{
		TenantID: "acme", Plane: PlaneEastWest, Priority: 100,
		Source: []string{"grp-clients"}, Destination: []string{"grp-servers"}, ServiceID: "svc-smb",
		Action: Action{Access: AccessAuthenticate},
	}
}

func TestUpsertDefaultsAndIDGeneration(t *testing.T) {
	s := NewStore()
	got, err := s.Upsert(ewRule())
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if got.ID == "" {
		t.Fatalf("expected a generated id")
	}
	if got.Direction != DirectionOutbound {
		t.Errorf("default direction = %q, want outbound", got.Direction)
	}
	if got.Action.Inspection != InspectionInspect {
		t.Errorf("default inspection = %q, want inspect", got.Action.Inspection)
	}
	if got.Status != StatusActive {
		t.Errorf("default status = %q, want active", got.Status)
	}
	if got.Stage != StageEnforce {
		t.Errorf("default stage = %q, want enforce", got.Stage)
	}

	// Upsert with the same id updates in place (no new id).
	got.Priority = 50
	updated, err := s.Upsert(got)
	if err != nil {
		t.Fatalf("update Upsert: %v", err)
	}
	if updated.ID != got.ID {
		t.Errorf("update changed id %q -> %q", got.ID, updated.ID)
	}
	if again, _ := s.Get("acme", got.ID); again.Priority != 50 {
		t.Errorf("update not persisted: priority = %d", again.Priority)
	}
}

func TestUpsertValidation(t *testing.T) {
	cases := map[string]func(r *Rule){
		"missing tenant":        func(r *Rule) { r.TenantID = "" },
		"bad plane":             func(r *Rule) { r.Plane = "north" },
		"egress with direction": func(r *Rule) { r.Plane = PlaneEgress; r.Direction = DirectionInbound },
		"bad east-west dir":     func(r *Rule) { r.Direction = "sideways" },
		"bad access":            func(r *Rule) { r.Action.Access = "permit" },
		"bad inspection":        func(r *Rule) { r.Action.Inspection = "peek" },
		"deny cannot bypass":    func(r *Rule) { r.Action = Action{Access: AccessDeny, Inspection: InspectionBypass} },
		"negative ttl":          func(r *Rule) { r.Action.GrantTTLSeconds = -1 },
		"no source":             func(r *Rule) { r.Source = nil },
		"no destination":        func(r *Rule) { r.Destination = nil },
		"bad status":            func(r *Rule) { r.Status = "paused" },
		"bad stage":             func(r *Rule) { r.Stage = "shadow" },
		"warn on egress":        func(r *Rule) { r.Plane = PlaneEgress; r.Direction = ""; r.Stage = StageWarn },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := NewStore()
			r := ewRule()
			mutate(&r)
			if _, err := s.Upsert(r); err == nil {
				t.Fatalf("expected validation error for %q", name)
			}
		})
	}
}

func TestAnySubjectAndBlankIDValidation(t *testing.T) {
	s := NewStore()
	// Explicit Any is accepted and canonicalized to ["*"].
	got, err := s.Upsert(Rule{TenantID: "acme", Plane: PlaneEgress, Source: []string{SubjectAny}, Destination: []string{"ep-1"}, Action: Action{Access: AccessDeny}})
	if err != nil {
		t.Fatalf("Any source Upsert: %v", err)
	}
	if len(got.Source) != 1 || got.Source[0] != SubjectAny {
		t.Fatalf("Any source = %v, want [*]", got.Source)
	}
	// A blank id is rejected (so an unresolved/empty selection can't slip through as a phantom subject).
	if _, err := s.Upsert(Rule{TenantID: "acme", Plane: PlaneEgress, Source: []string{""}, Destination: []string{"ep-1"}, Action: Action{Access: AccessDeny}}); err == nil {
		t.Fatalf("blank source id should be rejected")
	}
}

func TestEgressNoDirectionDefaults(t *testing.T) {
	s := NewStore()
	got, err := s.Upsert(Rule{
		TenantID: "acme", Plane: PlaneEgress, Priority: 10,
		Source: []string{"grp-macs"}, Destination: []string{"ep-saas"},
		Action: Action{Access: AccessAllow, Inspection: InspectionBypass},
	})
	if err != nil {
		t.Fatalf("egress Upsert: %v", err)
	}
	if got.Direction != "" {
		t.Errorf("egress direction = %q, want empty", got.Direction)
	}
	if got.Action.Inspection != InspectionBypass {
		t.Errorf("inspection = %q, want bypass", got.Action.Inspection)
	}
}

func TestListOrdersByPriorityAndFiltersPlane(t *testing.T) {
	s := NewStore()
	mustUpsert(t, s, Rule{TenantID: "acme", Plane: PlaneEastWest, Priority: 200, Source: []string{"a"}, Destination: []string{"b"}, Action: Action{Access: AccessDeny}})
	mustUpsert(t, s, Rule{TenantID: "acme", Plane: PlaneEastWest, Priority: 100, Source: []string{"a"}, Destination: []string{"b"}, Action: Action{Access: AccessAllow}})
	mustUpsert(t, s, Rule{TenantID: "acme", Plane: PlaneEgress, Priority: 50, Source: []string{"a"}, Destination: []string{"b"}, Action: Action{Access: AccessAllow}})

	ew := s.List("acme", PlaneEastWest)
	if len(ew) != 2 || ew[0].Priority != 100 || ew[1].Priority != 200 {
		t.Fatalf("east-west list = %#v, want 2 ordered by priority", ew)
	}
	eg := s.List("acme", PlaneEgress)
	if len(eg) != 1 || eg[0].Plane != PlaneEgress {
		t.Fatalf("egress list = %#v, want 1 egress rule", eg)
	}
	if all := s.List("acme", ""); len(all) != 3 {
		t.Fatalf("all-planes list = %d, want 3", len(all))
	}
	// Tenants are isolated.
	if other := s.List("other", ""); len(other) != 0 {
		t.Fatalf("other tenant list = %d, want 0", len(other))
	}
}

func TestDelete(t *testing.T) {
	s := NewStore()
	r := mustUpsert(t, s, ewRule())
	if ok, err := s.Delete("acme", r.ID); !ok || err != nil {
		t.Fatalf("Delete returned false for existing rule")
	}
	if ok, _ := s.Delete("acme", r.ID); ok {
		t.Fatalf("Delete returned true for already-deleted rule")
	}
	if _, ok := s.Get("acme", r.ID); ok {
		t.Fatalf("rule still present after delete")
	}
}

func TestInboundReceiverPlatformValidation(t *testing.T) {
	inbound := Rule{
		TenantID: "acme", Plane: PlaneEastWest, Direction: DirectionInbound, Priority: 10,
		Source: []string{"grp-servers"}, Destination: []string{"ep-win", "ep-mac"},
		Action: Action{Access: AccessAllow},
	}
	if got := InboundReceiversNeedingPlatform(inbound); len(got) != 2 {
		t.Fatalf("InboundReceiversNeedingPlatform = %#v, want both destinations", got)
	}
	if got := InboundReceiversNeedingPlatform(ewRule()); got != nil {
		t.Fatalf("outbound rule should need no platform resolution, got %#v", got)
	}

	// macOS-only receivers -> hard error.
	if _, err := ValidateInboundReceiverPlatforms(inbound, []string{"macos"}, []string{"ep-mac"}); !errors.Is(err, ErrMacOSInboundUnsupported) {
		t.Fatalf("macOS-only inbound err = %v, want ErrMacOSInboundUnsupported", err)
	}
	// Mixed -> warning naming the macOS receivers, no error.
	warn, err := ValidateInboundReceiverPlatforms(inbound, []string{"windows", "macos"}, []string{"ep-mac"})
	if err != nil || warn == "" {
		t.Fatalf("mixed inbound = (warn=%q, err=%v), want a warning and no error", warn, err)
	}
	// Windows-only -> clean.
	if warn, err := ValidateInboundReceiverPlatforms(inbound, []string{"windows"}, nil); err != nil || warn != "" {
		t.Fatalf("windows-only inbound = (warn=%q, err=%v), want clean", warn, err)
	}
	// Outbound rule is never platform-gated.
	if warn, err := ValidateInboundReceiverPlatforms(ewRule(), []string{"macos"}, []string{"ep-mac"}); err != nil || warn != "" {
		t.Fatalf("outbound platform check = (warn=%q, err=%v), want no-op", warn, err)
	}
}

func mustUpsert(t *testing.T, s *Store, r Rule) Rule {
	t.Helper()
	got, err := s.Upsert(r)
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	return got
}
