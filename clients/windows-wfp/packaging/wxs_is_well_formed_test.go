package packaging

import (
	"encoding/xml"
	"os"
	"strings"
	"testing"
)

// ★★★ THE TESTS IN THIS PACKAGE READ THE .wxs AS TEXT, AND TEXT CANNOT SEE THIS (2026-08-29).
//
// A comment added here carried the flag it documents — and an XML comment may not contain a double hyphen. Every
// string-matching test in this package passed; `wix build` refused with
//
//	error WIX0104: An XML comment cannot contain '--', and '-' cannot be the last character
//
// which is a good error, arriving at the worst moment: after nine executables have been compiled, and — on a
// signing round — after the operator has been standing by to type a token PIN. The parse is free and belongs
// with the other checks that run in seconds.
//
// It asserts well-formedness only. WiX's own schema validation is WiX's job; this is the class of mistake a
// person editing prose makes, caught where prose is edited.
func TestTheAgentWxsIsWellFormedXML(t *testing.T) {
	for _, name := range []string{"DsseAgent.wxs", "DsseBundle.wxs"} {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		d := xml.NewDecoder(strings.NewReader(string(raw)))
		for {
			_, err := d.Token()
			if err != nil {
				if err.Error() == "EOF" {
					break
				}
				t.Fatalf("%s is not well-formed XML, so `wix build` will refuse it after compiling everything "+
					"else — and on a signing round that is a PIN entry the operator was standing by for: %v", name, err)
			}
		}
	}
}
