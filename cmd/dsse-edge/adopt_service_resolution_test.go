package main

import (
	"testing"

	assetcatalog "github.com/lantern-networks/dsse-core/assetcatalog"
)

// adoptServiceIDForObservation resolves the catalog service id an S2-adopted East-West rule carries for an
// observed lateral flow. Port match is preferred (unambiguous) over the family-string convention.
func TestAdoptServiceIDForObservation(t *testing.T) {
	assets := assetcatalog.NewStore()
	assets.SetBuiltInServices(assetcatalog.BuiltInServices())

	cases := []struct {
		name   string
		port   int
		family string
		want   string
	}{
		{"ssh by port", 22, "ssh", "builtin-svc-ssh"},
		{"smb by port", 445, "smb", "builtin-svc-smb"},
		{"rdp by port", 3389, "rdp", "builtin-svc-rdp"},
		// WinRM: the family "winrm" is NOT a catalog id (the catalog splits WinRM-HTTP / WinRM-HTTPS), so port
		// resolution is what makes this correct — 5985 → builtin-svc-winrm-http.
		{"winrm-http by port", 5985, "winrm", "builtin-svc-winrm-http"},
		// Unknown port, known family → family-string fallback (builtin-svc-<family>).
		{"unknown port falls back to family", 0, "customfam", "builtin-svc-customfam"},
		// Unknown port + blank family → no service constraint (destination-only allow rule).
		{"no port no family", 0, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := adoptServiceIDForObservation(assets, "tenant-1", tc.port, tc.family)
			if got != tc.want {
				t.Fatalf("port=%d family=%q: got %q, want %q", tc.port, tc.family, got, tc.want)
			}
		})
	}

	// A nil store must not panic and yields the family fallback / blank.
	if got := adoptServiceIDForObservation(nil, "t", 22, "ssh"); got != "builtin-svc-ssh" {
		t.Fatalf("nil store: got %q, want builtin-svc-ssh (family fallback)", got)
	}
}
