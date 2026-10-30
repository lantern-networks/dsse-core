package packaging

import (
	"os"
	"strings"
	"testing"
)

// The 2026-10-13 lab MSI installed literal &quot; around a multiword publisher: the entity had been
// expanded into a preprocessor variable after XML decoding, so the service parsed it as several argv values.
// A Go-only package test cannot compile WiX here, but it can keep that exact authoring error from returning.
func TestUpdaterPublisherQuotesAreDecodedByFinalServiceAttribute(t *testing.T) {
	wxs, err := os.ReadFile("DsseAgent.wxs")
	if err != nil {
		t.Fatal(err)
	}
	source := string(wxs)
	if !strings.Contains(source, `Arguments="$(var.UpdaterArgs) --update-publisher &quot;$(var.UpdatePublisher)&quot;"`) {
		t.Fatal("publisher quotes must be entities in the final ServiceInstall Arguments attribute")
	}
	for _, line := range strings.Split(source, "\n") {
		if strings.Contains(line, "<?define UpdaterArgs") && strings.Contains(line, "&quot;") {
			t.Fatal("a quote entity in UpdaterArgs would be installed literally in the service ImagePath")
		}
	}
}
