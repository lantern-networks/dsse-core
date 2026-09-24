package policyrule

import "sort"

type serviceTransportResolver interface {
	ServiceTransportPorts(tenant, serviceID string) map[string][]int
}

// A named service requires exact protocol/port resolution. Port-only resolvers
// cannot establish that contract, so their named services match nothing.
func egressServiceConditions(tenant, serviceID string, resolver any) ([]map[string]any, bool) {
	if serviceID == "" {
		return []map[string]any{{}}, true // explicit Any
	}
	noMatch := []map[string]any{{"protocol": []any{}}}
	r, ok := resolver.(serviceTransportResolver)
	if !ok {
		return noMatch, false
	}
	transports := r.ServiceTransportPorts(tenant, serviceID)
	if len(transports) == 0 {
		return noMatch, false
	}
	for protocol, ports := range transports {
		if (protocol != "tcp" && protocol != "udp") || len(ports) == 0 {
			return noMatch, false
		}
		for _, port := range ports {
			if port < 1 || port > 65535 {
				return noMatch, false
			}
		}
	}
	var out []map[string]any
	for _, protocol := range []string{"tcp", "udp"} {
		set := map[int]bool{}
		for _, port := range transports[protocol] {
			set[port] = true
		}
		if len(set) == 0 {
			continue
		}
		ports := make([]int, 0, len(set))
		for port := range set {
			ports = append(ports, port)
		}
		sort.Ints(ports)
		var cond any = ports[0]
		if len(ports) > 1 {
			values := make([]any, len(ports))
			for i, port := range ports {
				values[i] = port
			}
			cond = values
		}
		out = append(out, map[string]any{"protocol": protocol, "destination_port": cond})
	}
	return out, true
}

// EgressServiceUnresolved describes the same resolution used by the compiler.
// Retaining an authored rule does not mean an unresolved deny is enforcing.
func EgressServiceUnresolved(tenant, serviceID string, resolver any) bool {
	_, ok := egressServiceConditions(tenant, serviceID, resolver)
	return !ok
}
