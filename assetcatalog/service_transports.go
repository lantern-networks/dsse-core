package assetcatalog

import (
	"fmt"
	"strings"
)

// Normalize at admission and snapshot loading so every consumer sees the same
// protocol vocabulary. Work on a copy; a rejected candidate cannot mutate input.
func normalizeServiceTransports(svc Service) (Service, error) {
	svc = copyService(svc)
	if len(svc.Ports) == 0 {
		return Service{}, fmt.Errorf("service requires at least one port")
	}
	for i := range svc.Ports {
		p := &svc.Ports[i]
		p.Protocol = strings.ToLower(strings.TrimSpace(p.Protocol))
		if p.Protocol != "tcp" && p.Protocol != "udp" {
			return Service{}, fmt.Errorf("service protocol must be tcp or udp")
		}
		if p.Port < 1 || p.Port > 65535 {
			return Service{}, fmt.Errorf("service port must be between 1 and 65535")
		}
	}
	return svc, nil
}

// ServiceTransportPorts preserves the association between protocol and ports.
// Missing or invalid services return nil; callers must not interpret that as Any.
func (s *Store) ServiceTransportPorts(tenant, serviceID string) map[string][]int {
	if s == nil || serviceID == "" {
		return nil
	}
	for _, svc := range s.ListServices(tenant) {
		if svc.ID != serviceID {
			continue
		}
		valid, err := normalizeServiceTransports(svc)
		if err != nil {
			return nil
		}
		out := map[string][]int{}
		for _, p := range valid.Ports {
			out[p.Protocol] = append(out[p.Protocol], p.Port)
		}
		return out
	}
	return nil
}
