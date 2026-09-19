package eastwest

import (
	"bytes"
	"testing"

	"github.com/lantern-networks/dsse-core/policy"
)

type adminSaveCounter struct {
	raw   []byte
	saves int
}

func (p *adminSaveCounter) Load() ([]byte, error) { return p.raw, nil }
func (p *adminSaveCounter) Save(raw []byte) error {
	p.raw = append([]byte(nil), raw...)
	p.saves++
	return nil
}

func TestEastWestAdminValidatesEntireUpdateBeforeSaving(t *testing.T) {
	p := &adminSaveCounter{}
	s := policy.NewStore(nil)
	if err := s.SetRuntimeStatePersister(p); err != nil {
		t.Fatal(err)
	}
	partial := "partial"
	if _, err := ApplyAdminUpdate(s, "tenant", AdminUpdateRequest{Mode: &partial}); err != nil {
		t.Fatal(err)
	}
	prior := append([]byte(nil), p.raw...)
	saves := p.saves
	gen := s.ConfigGeneration()
	rules := []adminRule{{ID: "candidate", Mode: "allow", Protocols: []string{"ssh"}}}
	ttl := 120
	invalid := "invalid"
	if _, err := ApplyAdminUpdate(s, "tenant", AdminUpdateRequest{Mode: &invalid, Rules: &rules, MaxGrantTTLSeconds: &ttl}); err == nil {
		t.Fatal("invalid mode accepted")
	}
	if p.saves != saves || !bytes.Equal(prior, p.raw) || s.ConfigGeneration() != gen || len(s.EastWestRulesFor("tenant")) != 0 {
		t.Fatal("invalid request partly saved")
	}
	full := "full"
	if _, err := ApplyAdminUpdate(s, "tenant", AdminUpdateRequest{Mode: &full, Rules: &rules, MaxGrantTTLSeconds: &ttl}); err != nil {
		t.Fatal(err)
	}
	if p.saves != saves+1 || AdminStatus(s, "tenant").Mode != "full" || s.EastWestMaxGrantTTL("tenant") != 120 {
		t.Fatal("update was not one save")
	}
}
