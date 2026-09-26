package assetcatalog

import (
	"bytes"
	"encoding/json"
	"testing"
)

type serviceMemoryWriter struct {
	data  []byte
	saves int
}

func (p *serviceMemoryWriter) Load() ([]byte, error) { return p.data, nil }
func (p *serviceMemoryWriter) Save(b []byte) error {
	p.data = append([]byte{}, b...)
	p.saves++
	return nil
}

func TestServiceTransportAdmissionAndReload(t *testing.T) {
	p := &serviceMemoryWriter{}
	s := NewStore()
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	input := Service{TenantID: "a", ID: "svc", Alias: "service", Ports: []PortProto{{Protocol: " TCP ", Port: 443}, {Protocol: "Udp", Port: 53}}}
	got, e := s.UpsertService(input)
	if e != nil {
		t.Fatal(e)
	}
	if input.Ports[0].Protocol != " TCP " || got.Ports[0].Protocol != "tcp" || got.Ports[1].Protocol != "udp" {
		t.Fatal("normalization/input alias", got, input)
	}
	saved := append([]byte{}, p.data...)
	gen := s.ConfigGeneration()
	writes := p.saves
	for _, ports := range [][]PortProto{nil, {{Protocol: "", Port: 443}}, {{Protocol: "sctp", Port: 443}}, {{Protocol: "tcp", Port: 0}}, {{Protocol: "udp", Port: 65536}}, {{Protocol: "tcp", Port: 443}, {Protocol: "invalid", Port: 53}}} {
		bad := input
		bad.Ports = ports
		if _, e := s.UpsertService(bad); e == nil {
			t.Fatalf("accepted %v", ports)
		}
		if _, e := s.ReplaceAuthored(nil, nil, []Service{bad}); e == nil {
			t.Fatalf("bundle accepted %v", ports)
		}
		if p.saves != writes || !bytes.Equal(saved, p.data) || s.ConfigGeneration() != gen {
			t.Fatal("invalid candidate changed live/durable")
		}
	}
	var snap persistedCatalog
	if e := json.Unmarshal(saved, &snap); e != nil {
		t.Fatal(e)
	}
	legacy := snap.Services["a"]["svc"]
	legacy.Ports[0].Protocol = " TCP "
	snap.Services["a"]["svc"] = legacy
	raw, _ := json.Marshal(snap)
	loaded := NewStore()
	if e := loaded.SetPersister(&serviceMemoryWriter{data: raw}); e != nil {
		t.Fatal(e)
	}
	if !loaded.ServiceIncludesTransport("a", "svc", "tcp", 443) || loaded.ServiceIncludesTransport("a", "svc", "udp", 443) {
		t.Fatal("loaded transport differs")
	}
	legacy.Ports[0].Protocol = "bad"
	snap.Services["a"]["svc"] = legacy
	raw, _ = json.Marshal(snap)
	legacyWriter := &serviceMemoryWriter{data: raw}
	if e := s.SetPersister(legacyWriter); e != nil {
		t.Fatal("legacy service blocked load", e)
	}
	if len(s.ServiceTransportPorts("a", "svc")) != 0 {
		t.Fatal("invalid legacy service became executable")
	}
	if _, e := s.UpsertService(input); e != nil {
		t.Fatal(e)
	}
	if legacyWriter.saves != 1 || p.saves != writes {
		t.Fatal("repair did not save to loaded writer")
	}
	pairs := s.ServiceTransportPorts("a", "svc")
	pairs["tcp"][0] = 22
	if !s.ServiceIncludesTransport("a", "svc", "tcp", 443) {
		t.Fatal("resolver alias")
	}
}
