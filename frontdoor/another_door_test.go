package frontdoor

import (
	"context"
	"errors"
	"testing"
)

// TestADoorIsRecognisedByNameAsWellAsByAddress — review C3-R1: the transport hands over the URL's host
// unresolved, and the door is configured as an address.
func TestADoorIsRecognisedByNameAsWellAsByAddress(t *testing.T) {
	d, err := Parse("10.47.1.20:443", "TEST")
	if err != nil || d == nil {
		t.Fatal(err)
	}
	if err := d.OnlyFor("10.116.0.5:443", "TEST"); err != nil {
		t.Fatal(err)
	}
	d.Lookup = func(_ context.Context, host string) ([]string, error) {
		switch host {
		case "admin.region-a.c.example.test":
			return []string{"10.116.0.5"}, nil
		case "idp.example.test":
			return []string{"203.0.113.7"}, nil
		}
		return nil, errors.New("no such host")
	}
	ctx := context.Background()
	for address, want := range map[string]bool{
		"10.116.0.5:443":                    true,
		"admin.region-a.c.example.test:443": true,
		"admin.region-a.c.example.test:80":  false, // the door is 443
		"idp.example.test:443":              false,
		"unknown.example.test:443":          false,
		"203.0.113.7:443":                   false,
	} {
		if got := d.isLocalDoor(ctx, address); got != want {
			t.Errorf("isLocalDoor(%s) = %t, want %t", address, got, want)
		}
	}
}
