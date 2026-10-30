package main

import "testing"

func TestDeviceProjectionOrdersActualInstants(t *testing.T) {
	for _, tc := range []struct{ name, older, newer string }{
		{"fraction", "2026-10-23T00:00:00Z", "2026-10-23T00:00:00.5Z"},
		{"offset", "2026-10-23T09:00:00+09:00", "2026-10-23T00:00:01Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newFleetDeviceProjection()
			p.Fold(row("device", tc.older, "old-edge", tc.older))
			p.Fold(row("device", tc.newer, "new-edge", tc.newer))
			p.Fold(row("device", tc.older, "replayed-edge", tc.older))
			got, _ := p.Devices("acme")
			if len(got) != 1 || got[0].Edge != "new-edge" {
				t.Fatalf("newer device state lost to string ordering: %+v", got)
			}
		})
	}
}

func TestDeviceProjectionIgnoresInvalidTimestamp(t *testing.T) {
	p := newFleetDeviceProjection()
	p.Fold(row("device", "not-a-time", "invalid-edge", ""))
	p.Fold(row("device", "2026-10-23T00:00:01Z", "valid-edge", ""))
	got, _ := p.Devices("acme")
	if len(got) != 1 || got[0].Edge != "valid-edge" {
		t.Fatalf("malformed timestamp poisoned device state: %+v", got)
	}
}
