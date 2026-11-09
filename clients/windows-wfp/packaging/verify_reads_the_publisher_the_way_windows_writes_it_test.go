package packaging

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Found 2026-11-05: the publisher check (section 4b) of verify-windows-install.ps1 recognised only a quoted --update-publisher, so a
// valid unquoted one — subject:Lantern, thumbprint:<hex>, and every value after the pins are restored, which
// rewrites the service arguments without quotes where none are needed — was reported missing and failed the
// script. The script's own patterns are run here against command lines written the way Windows writes them
// (a value is quoted only when it contains a space).
func scriptPattern(t *testing.T, script, flag string) *regexp.Regexp {
	t.Helper()
	marker := "[regex]::Matches($updArgs, '" + flag
	i := strings.Index(script, marker)
	if i < 0 {
		t.Fatalf("the script no longer matches %s with [regex]::Matches", flag)
	}
	rest := script[i+len("[regex]::Matches($updArgs, '"):]
	end := strings.Index(rest, "')")
	if end < 0 {
		t.Fatalf("the %s pattern is not closed", flag)
	}
	return regexp.MustCompile(rest[:end])
}

func captured(re *regexp.Regexp, line string) []string {
	out := []string{}
	for _, m := range re.FindAllStringSubmatch(line, -1) {
		v := ""
		for _, g := range m[1:] {
			if g != "" {
				v = g
				break
			}
		}
		out = append(out, v)
	}
	return out
}

func TestVerifyReadsThePublisherTheWayWindowsWritesIt(t *testing.T) {
	body, err := os.ReadFile("verify-windows-install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	pub := scriptPattern(t, script, "--update-publisher")
	pin := scriptPattern(t, script, "--update-pin")
	const exe = `"C:\Program Files\DSSE\dsse-updater.exe" --service-run `
	hex := strings.Repeat("ab", 32)
	thumb := strings.Repeat("0e", 32)

	for _, c := range []struct {
		line string
		pubs []string
		pins int
	}{
		{exe + `--update-publisher "subject:LANTERN NETWORKS, INC." --update-pin ` + hex, []string{"subject:LANTERN NETWORKS, INC."}, 1},
		{exe + `--update-publisher subject:Lantern --update-pin ` + hex, []string{"subject:Lantern"}, 1},
		{exe + `--update-publisher thumbprint:` + thumb + ` --update-pin ` + hex + ` --update-pin ` + strings.Repeat("cd", 32), []string{"thumbprint:" + thumb}, 2},
		{exe + `--update-publisher=subject:Lantern --update-pin=` + hex, []string{"subject:Lantern"}, 1},
		{exe + `--update-pin ` + hex, []string{}, 1},
		{exe + `--update-publisher subject:A --update-publisher "subject:B C"`, []string{"subject:A", "subject:B C"}, 0},
		{exe + `--update-publisher "" --update-pin ` + hex, []string{""}, 1},
	} {
		got := captured(pub, c.line)
		if strings.Join(got, "|") != strings.Join(c.pubs, "|") {
			t.Errorf("%s\n  publishers %q, want %q", c.line, got, c.pubs)
		}
		if n := len(pin.FindAllString(c.line, -1)); n != c.pins {
			t.Errorf("%s\n  %d pins, want %d", c.line, n, c.pins)
		}
	}
	// And the missing-publisher line says what the updater does, not that it refuses everything: with no
	// --update-publisher it installs on the signed manifest alone (updater/main_windows.go).
	if strings.Contains(script, "it refuses every update package") {
		t.Fatal("the script still says a device without a publisher refuses every update")
	}
}

// With --update-publisher "" the pattern reads one value, an empty one, and the
// updater reads that as no publisher (updateplatform.ParsePublisherRequirement). The script must not report it as
// a publisher that is checked.
func TestVerifyDoesNotPassAnEmptyPublisher(t *testing.T) {
	body, err := os.ReadFile("verify-windows-install.ps1")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.Contains(line, `ok "DsseUpdater accepts update packages signed by`) && !strings.Contains(line, `"$($pubs[0])".Trim()`) {
			t.Fatalf("the publisher passes without being checked for emptiness:\n%s", line)
		}
	}
	if !strings.Contains(string(body), "--update-publisher is empty") {
		t.Fatal("the script does not say when the publisher is empty")
	}
}
