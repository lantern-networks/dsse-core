package packaging

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// An uninstall that succeeded left C:\Program Files\DSSE behind holding the
// agent's logs and the DNS backup lock (measured 2026-10-30). The agent
// writes these beside its own executable; MSI removes only files it
// installed, so each one needs a RemoveFile row, or a stated reason to stay.
//
// This reads the agent sources rather than a list kept here, so a new file
// written beside the executable fails this test until someone decides.
func TestEveryRuntimeFileBesideTheAgentIsRemovedOrKeptOnPurpose(t *testing.T) {
	// The backups hold the user's original DNS and NCSI settings. One that is
	// still present after a successful recover is evidence, not clutter.
	keep := map[string]string{
		"dsse_dns_resolver_backup.json": "original DNS servers, restored by recover",
		"dsse_ncsi_probe_backup.txt":    "original NCSI probe settings, restored by recover",
	}
	besideExe := regexp.MustCompile(`filepath\.Join\(filepath\.Dir\(exe\), "([^"]+)"\)`)
	lockOf := regexp.MustCompile(`os\.OpenFile\(backup\+"\.lock"`)
	written := map[string]bool{}
	for _, dir := range []string{"../steer", "../watchdog", "../updater"} {
		paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range paths {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range besideExe.FindAllStringSubmatch(string(raw), -1) {
				if !strings.HasSuffix(m[1], ".exe") {
					written[m[1]] = true
				}
			}
			if lockOf.Match(raw) {
				written["dsse_dns_resolver_backup.json.lock"] = true
			}
		}
	}
	if len(written) < 4 {
		t.Fatalf("found only %v beside the executable; the source pattern this test reads has changed", written)
	}
	wxs, err := os.ReadFile("DsseAgent.wxs")
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for name := range written {
		if _, ok := keep[name]; ok {
			continue
		}
		row := regexp.MustCompile(`<RemoveFile Id="[A-Za-z0-9_]+" Name="` + regexp.QuoteMeta(name) + `" On="uninstall" />`)
		if !row.Match(wxs) {
			missing = append(missing, name)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("written beside the agent but neither removed on uninstall nor kept on purpose: %v", missing)
	}
	for name := range keep {
		if strings.Contains(string(wxs), `Name="`+name+`"`) {
			t.Fatalf("%s is kept on purpose (%s) but the MSI removes it", name, keep[name])
		}
	}
}
