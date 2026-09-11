package fileextract

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"

	"github.com/lantern-networks/dsse-core/dlp"
)

// buildZip makes an in-memory ZIP (an OOXML file is a ZIP) from name->content parts. Synthetic; no real file.
func buildZip(t *testing.T, parts map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range parts {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("zip create %s: %v", name, err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatalf("zip write %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

const syntheticMyNumber = "123456789018" // valid mod-11 check digit; corresponds to no real person
const syntheticCard = "4111111111111111"

func TestExtractDocx(t *testing.T) {
	docx := buildZip(t, map[string]string{
		"word/document.xml": `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">` +
			`<w:body><w:p><w:r><w:t>My number is ` + syntheticMyNumber + `</w:t></w:r></w:p></w:body></w:document>`,
	})
	text, err := ExtractOOXMLText(docx)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !strings.Contains(text, syntheticMyNumber) {
		t.Errorf("docx text missing the My Number; got %q", text)
	}
}

func TestExtractXlsx(t *testing.T) {
	// A number stored as a cell value (<v>) and a string in shared strings (<t>) — both must surface.
	xlsx := buildZip(t, map[string]string{
		"xl/worksheets/sheet1.xml": `<worksheet><sheetData><row><c><v>` + syntheticMyNumber + `</v></c></row></sheetData></worksheet>`,
		"xl/sharedStrings.xml":     `<sst><si><t>card ` + syntheticCard + `</t></si></sst>`,
	})
	text, err := ExtractOOXMLText(xlsx)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if !strings.Contains(text, syntheticMyNumber) {
		t.Errorf("xlsx cell value not extracted; got %q", text)
	}
	if !strings.Contains(text, syntheticCard) {
		t.Errorf("xlsx shared string not extracted; got %q", text)
	}
}

func TestExtractSkipsNonXMLParts(t *testing.T) {
	f := buildZip(t, map[string]string{
		"word/document.xml":  `<w:t>` + syntheticMyNumber + `</w:t>`,
		"word/media/img.png": "\x89PNG\r\n\x1a\n" + syntheticCard, // binary part: must NOT be scanned
	})
	text, err := ExtractOOXMLText(f)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if strings.Contains(text, syntheticCard) {
		t.Errorf("binary (.png) part was extracted; got %q", text)
	}
	if !strings.Contains(text, syntheticMyNumber) {
		t.Errorf("xml part not extracted; got %q", text)
	}
}

func TestExtractCap(t *testing.T) {
	big := strings.Repeat("A", 1<<20) // 1 MiB of text in one node
	f := buildZip(t, map[string]string{"word/document.xml": "<w:t>" + big + "</w:t>"})
	text, err := extractOOXMLText(f, 4096) // small cap
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(text) > 4096+64 { // allow a little slack for the last node
		t.Errorf("extraction exceeded the cap: %d bytes", len(text))
	}
}

// Review #13: the cap must bound bytes READ from the archive (decompression), not just text produced. A
// whitespace bomb yields no text, so a produced-text cap alone never trips and decompression runs
// unbounded. Proof of the read-side budget: with whitespace ahead of a secret, the budget exhausts before
// the secret is ever decompressed — before the fix the whitespace cost nothing and the secret surfaced.
func TestExtractReadBudgetBoundsDecompression(t *testing.T) {
	whitespace := strings.Repeat(" ", 1<<20) // 1 MiB of decompressed whitespace, ~1 KiB compressed
	f := buildZip(t, map[string]string{
		// One part (map iteration order is random): whitespace ahead of the secret in the same XML stream.
		"word/document.xml": "<w:body>" + whitespace + "<w:t>" + syntheticMyNumber + "</w:t></w:body>",
	})
	text, err := extractOOXMLText(f, 4096)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if strings.Contains(text, syntheticMyNumber) {
		t.Errorf("read budget not enforced: 1 MiB of whitespace was decompressed for free and the trailing text surfaced")
	}
	// And a benign small doc is unaffected by the budget.
	small := buildZip(t, map[string]string{"word/document.xml": "<w:t>" + syntheticMyNumber + "</w:t>"})
	text, err = extractOOXMLText(small, 4096)
	if err != nil || !strings.Contains(text, syntheticMyNumber) {
		t.Fatalf("small doc must still extract: %q err=%v", text, err)
	}
}

func TestExtractTextRouter(t *testing.T) {
	docx := buildZip(t, map[string]string{"word/document.xml": "<w:t>" + syntheticMyNumber + "</w:t>"})
	text, handled, err := ExtractText("report.docx", docxContentType, docx)
	if err != nil || !handled {
		t.Fatalf("docx not handled: handled=%v err=%v", handled, err)
	}
	if !strings.Contains(text, syntheticMyNumber) {
		t.Errorf("router did not extract docx text")
	}
	if _, handled, _ := ExtractText("photo.png", "image/png", []byte("binarydata")); handled {
		t.Errorf("image/png should not be handled by the OOXML extractor")
	}
}

// F2 end-to-end: an uploaded Office file's extracted text feeds the DLP engine, which finds the identifiers.
func TestExtractThenDetect(t *testing.T) {
	docx := buildZip(t, map[string]string{
		"word/document.xml": "<w:t>invoice for " + syntheticMyNumber + " and card " + syntheticCard + "</w:t>",
	})
	text, handled, err := ExtractText("invoice.docx", docxContentType, docx)
	if err != nil || !handled {
		t.Fatalf("extract: handled=%v err=%v", handled, err)
	}
	findings := dlp.Detect([]byte(text), "text/plain")
	var gotMyNumber, gotCard bool
	for _, f := range findings {
		if f.Type == dlp.MyNumber {
			gotMyNumber = true
		}
		if f.Type == dlp.CreditCard {
			gotCard = true
		}
	}
	if !gotMyNumber || !gotCard {
		t.Errorf("extract->detect missed identifiers in the Office file: %+v", findings)
	}
}
