package main

import (
	"net/http"
	"testing"
)

func TestStripQUICAdvertisement(t *testing.T) {
	h := http.Header{}
	h.Set("Alt-Svc", `h3=":443"; ma=2592000`)
	h.Set("Content-Type", "text/html")
	stripQUICAdvertisement(h)
	if h.Get("Alt-Svc") != "" {
		t.Fatalf("Alt-Svc must be stripped")
	}
	if h.Get("Content-Type") != "text/html" {
		t.Fatalf("unrelated headers must be preserved")
	}
}
