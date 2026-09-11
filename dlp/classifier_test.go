package dlp

import (
	"strings"
	"testing"
)

func TestCompileClassifierValidation(t *testing.T) {
	cases := []struct {
		name    string
		spec    ClassifierSpec
		wantErr string // substring; "" = must succeed
	}{
		{"good regex", ClassifierSpec{Name: "employee_id", Kind: ClassifierRegex, Pattern: `EMP-[0-9]{6}`}, ""},
		{"good keyword", ClassifierSpec{Name: "project_codename", Kind: ClassifierKeyword, Keywords: []string{"BLUEFIN", "REDCEDAR"}}, ""},
		{"reserved name", ClassifierSpec{Name: "credit_card", Kind: ClassifierRegex, Pattern: `x`}, "reserved"},
		{"bad name upper", ClassifierSpec{Name: "EmployeeID", Kind: ClassifierRegex, Pattern: `x`}, "snake_case"},
		{"bad name short", ClassifierSpec{Name: "e", Kind: ClassifierRegex, Pattern: `x`}, "snake_case"},
		{"empty pattern", ClassifierSpec{Name: "foo_id", Kind: ClassifierRegex, Pattern: "  "}, "empty pattern"},
		{"pattern too long", ClassifierSpec{Name: "foo_id", Kind: ClassifierRegex, Pattern: strings.Repeat("a", MaxPatternLen+1)}, "exceeds"},
		{"uncompilable", ClassifierSpec{Name: "foo_id", Kind: ClassifierRegex, Pattern: `[a-`}, "error parsing"},
		{"empty-matching regex", ClassifierSpec{Name: "foo_id", Kind: ClassifierRegex, Pattern: `a*`}, "empty string"},
		{"no keywords", ClassifierSpec{Name: "foo_id", Kind: ClassifierKeyword, Keywords: []string{"", "  "}}, "no non-empty"},
		{"keyword too long", ClassifierSpec{Name: "foo_id", Kind: ClassifierKeyword, Keywords: []string{strings.Repeat("k", MaxKeywordLen+1)}}, "exceeds"},
		{"unknown kind", ClassifierSpec{Name: "foo_id", Kind: "fuzzy", Pattern: `x`}, "unknown kind"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CompileClassifier(tc.spec)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestClassifierSetScan(t *testing.T) {
	set, errs := NewClassifierSet([]ClassifierSpec{
		{Name: "employee_id", Kind: ClassifierRegex, Pattern: `EMP-[0-9]{6}`},
		{Name: "project_codename", Kind: ClassifierKeyword, Keywords: []string{"BLUEFIN", "REDCEDAR"}},
	})
	if len(errs) != 0 {
		t.Fatalf("compile errors: %v", errs)
	}
	body := "ticket for EMP-004217 on project BLUEFIN; also EMP-999001 and BLUEFIN again"
	got := DetectWith([]byte(body), "text/plain", set)
	counts := map[IdentifierType]int{}
	for _, f := range got {
		counts[f.Type] = f.Count
	}
	if counts["employee_id"] != 2 {
		t.Errorf("employee_id count = %d, want 2 (findings %v)", counts["employee_id"], got)
	}
	if counts["project_codename"] != 2 {
		t.Errorf("project_codename count = %d, want 2 (findings %v)", counts["project_codename"], got)
	}
}

// A custom classifier must not fire on a body that lacks its gate literal (cheap pre-check works + no false hit).
func TestClassifierGateSkipsBenign(t *testing.T) {
	set, _ := NewClassifierSet([]ClassifierSpec{{Name: "employee_id", Kind: ClassifierRegex, Pattern: `EMP-[0-9]{6}`}})
	if got := DetectWith([]byte("nothing sensitive here, just prose"), "text/plain", set); len(got) != 0 {
		t.Fatalf("expected no findings, got %v", got)
	}
}

// Streaming must count a custom match that straddles a Write boundary exactly once.
func TestClassifierStreamingBoundary(t *testing.T) {
	set, _ := NewClassifierSet([]ClassifierSpec{{Name: "employee_id", Kind: ClassifierRegex, Pattern: `EMP-[0-9]{6}`}})
	sc := NewScannerWith(set)
	full := strings.Repeat("x", windowSize-4) + "EMP-123456" + strings.Repeat("y", 100)
	// Feed in two writes that split the identifier across the boundary.
	mid := windowSize - 1
	sc.Write([]byte(full[:mid]))
	sc.Write([]byte(full[mid:]))
	counts := map[IdentifierType]int{}
	for _, f := range sc.Findings() {
		counts[f.Type] = f.Count
	}
	if counts["employee_id"] != 1 {
		t.Fatalf("straddling employee_id counted %d times, want exactly 1", counts["employee_id"])
	}
}

// A custom identifier can trip a GuardReader block hold.
func TestClassifierGuardBlocks(t *testing.T) {
	set, _ := NewClassifierSet([]ClassifierSpec{{Name: "secret_tag", Kind: ClassifierKeyword, Keywords: []string{"TOPSECRET"}}})
	body := strings.Repeat("z", 100) + "TOPSECRET" + strings.Repeat("z", 100)
	g := NewGuardReaderWith(strings.NewReader(body), map[IdentifierType]int{"secret_tag": 1}, set)
	buf := make([]byte, 4096)
	var blocked bool
	for {
		_, err := g.Read(buf)
		if err == ErrBlocked {
			blocked = true
			break
		}
		if err != nil {
			break
		}
	}
	if !blocked {
		t.Fatal("GuardReader did not block on the custom identifier")
	}
	if !g.Tripped() {
		t.Fatal("Tripped() = false, want true")
	}
}

func TestNewClassifierSetDedupAndCap(t *testing.T) {
	specs := []ClassifierSpec{
		{Name: "dup_id", Kind: ClassifierRegex, Pattern: `A[0-9]{3}`},
		{Name: "dup_id", Kind: ClassifierRegex, Pattern: `B[0-9]{3}`}, // duplicate name -> dropped
		{Name: "bad", Kind: ClassifierRegex, Pattern: `[a-`},          // invalid -> error, set survives
	}
	set, errs := NewClassifierSet(specs)
	if len(set.Names()) != 1 || set.Names()[0] != "dup_id" {
		t.Fatalf("names = %v, want [dup_id]", set.Names())
	}
	if len(errs) != 2 {
		t.Fatalf("errs = %d, want 2 (duplicate + invalid)", len(errs))
	}
	if !set.Has("dup_id") || set.Has("nope") {
		t.Fatalf("Has() wrong")
	}
}
