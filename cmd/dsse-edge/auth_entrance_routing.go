package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/lantern-networks/dsse-core/authportal"
	"github.com/lantern-networks/dsse-core/edgeplane"
)

// The map is an explicit cutover switch. The older profile-origin allowlist
// alone must not enable shared-fleet admission during a rolling binary update.
func parseEntrancePortalOrigins(raw string, approved []string) (map[string]string, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	trusted := map[string]bool{}
	for _, origin := range approved {
		canonical, err := authportal.Origin(origin)
		if err != nil {
			return nil, err
		}
		trusted[canonical] = true
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, fmt.Errorf("entrance mapping must be a JSON object")
	}
	mapping := map[string]string{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, fmt.Errorf("invalid entrance mapping")
		}
		name, ok := token.(string)
		if !ok {
			return nil, fmt.Errorf("invalid entrance TLS name")
		}
		name = strings.ToLower(name)
		if strings.ContainsAny(name, ":/ \\?@#\t\r\n") {
			return nil, fmt.Errorf("entrance key must be an exact TLS server name")
		}
		if _, err := authportal.Origin("https://" + name); err != nil {
			return nil, fmt.Errorf("invalid entrance TLS name")
		}
		if _, exists := mapping[name]; exists {
			return nil, fmt.Errorf("duplicate entrance TLS name")
		}
		var origin string
		if err := decoder.Decode(&origin); err != nil {
			return nil, fmt.Errorf("entrance mapping value must be an HTTPS origin")
		}
		canonical, err := authportal.Origin(origin)
		if err != nil || !trusted[canonical] {
			return nil, fmt.Errorf("entrance must select a configured Portal origin")
		}
		mapping[name] = strings.TrimSuffix(canonical, ":443")
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF || len(mapping) == 0 {
		return nil, fmt.Errorf("entrance mapping must be nonempty with no trailing data")
	}
	return mapping, nil
}

// Health-check failover can carry a valid agent transport SNI to another
// Region. Only the SNI keys in the operator-approved mapping are accepted,
// but a three-region Edge must issue *new* ceremonies at its own reachable
// Portal. An already issued callback remains bound to its original origin.
func localizeEntrancePortalOrigins(profile string, mapping map[string]string, served []string) map[string]string {
	if profile != "three-regions-multi-edge" || len(mapping) == 0 || len(served) != 1 {
		return mapping
	}
	local := make(map[string]string, len(mapping))
	for name := range mapping {
		local[name] = served[0]
	}
	return local
}

// Capture the outer transport SNI before mux upgrade/interception. HTTP Host,
// forwarded headers and the decrypted destination's SNI are not this identity.
func transportIngressMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			r = r.WithContext(edgeplane.WithTransportServerName(r.Context(), r.TLS.ServerName))
		}
		next.ServeHTTP(w, r)
	})
}

func (g *federatedAuthGate) stepUpURLForRequest(r *http.Request, returnTo, device, tenant string, requirements federatedRequirements) string {
	if g == nil {
		return ""
	}
	if len(g.entranceOrigins) == 0 {
		return g.stepUpURLWithRequirements(returnTo, device, tenant, requirements)
	}
	name := ""
	if r != nil {
		name = edgeplane.TransportServerNameFromContext(r.Context())
		if name == "" && r.TLS != nil {
			name = strings.ToLower(r.TLS.ServerName)
		}
	}
	origin, ok := g.entranceOrigins[name]
	if !ok {
		log.Printf("authentication_portal_selection_refused reason=unmapped_transport_sni")
		return ""
	}
	return g.stepUpURLWithRequirementsAtOrigin(origin, returnTo, device, tenant, requirements)
}
