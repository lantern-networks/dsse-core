package main

import (
	"os"
	"strings"
	"testing"
)

// The IdP must open in the user's external browser. Repackaging the retired
// WebView2 window would silently reintroduce an embedded OAuth user-agent.
func TestStepUpInstallerDoesNotShipEmbeddedIdPWindow(t *testing.T) {
	for _, file := range []string{"../packaging/DsseAgent.wxs", "../packaging/build-msi.ps1"} {
		b, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(strings.ToLower(string(b)), "dsse-stepup-window.exe") {
			t.Errorf("%s still packages the embedded IdP window", file)
		}
	}
	b, err := os.ReadFile("../packaging/DsseBundle.wxs")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(b)), "webview2runtime") {
		t.Fatal("bundle still installs the unused WebView2 authentication prerequisite")
	}
}
