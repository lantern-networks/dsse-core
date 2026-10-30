package main

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/lantern-networks/dsse-core/authportal"
)

// Each broker keeps one immutable redirect_uri and recovery-AAD origin. Never
// derive either from Host, forwarded headers, or a client-provided return URL.
func configuredBrokerOrigins(config serverConfig) ([]string, error) {
	rawOrigins := append([]string{config.ClientlessBaseURL}, strings.FieldsFunc(config.StepUpPortalOrigins, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\t' || r == '\n' })...)
	var origins []string
	seen := map[string]bool{}
	for _, raw := range rawOrigins {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		canonical, err := authportal.Origin(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid configured HTTPS origin")
		}
		origin := strings.TrimSuffix(canonical, ":443")
		if !seen[origin] {
			seen[origin] = true
			origins = append(origins, origin)
		}
	}
	return origins, nil
}

// The signed device profile may advertise every Regional Portal, but a
// three-region Edge only serves the Portal behind its own Regional entrance.
// A combined-node one-region deployment still serves all three entrances.
func servedBrokerOrigins(profile string, config serverConfig, approved []string) ([]string, error) {
	if profile != "three-regions-multi-edge" {
		return approved, nil
	}
	if len(approved) != 3 {
		return nil, fmt.Errorf("three-region deployment requires three approved Portal origins")
	}
	canonical, err := authportal.Origin(config.ClientlessBaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid local Portal origin")
	}
	local := strings.TrimSuffix(canonical, ":443")
	for _, origin := range approved {
		if origin == local {
			return []string{local}, nil
		}
	}
	return nil, fmt.Errorf("local Portal origin is absent from approved origins")
}

func registerBrokerOrigins(mux *http.ServeMux, origins []string, handlers map[string]http.Handler) {
	registerBrokerOriginsForProfile(mux, origins, handlers, false)
}

func registerBrokerOriginsForProfile(mux *http.ServeMux, origins []string, handlers map[string]http.Handler, strictSingleOrigin bool) {
	// Preserve legacy single-origin dispatch. The TLS lane still checks Host/SNI.
	if len(origins) == 1 && !strictSingleOrigin {
		registerBrokerHandler(mux, handlers[origins[0]])
		return
	}
	dispatch := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		canonical, err := authportal.Origin("https://" + r.Host)
		handler := handlers[strings.TrimSuffix(canonical, ":443")]
		if err != nil || handler == nil {
			http.Error(w, "Authentication portal host mismatch", http.StatusMisdirectedRequest)
			return
		}
		handler.ServeHTTP(w, r)
	})
	registerBrokerHandler(mux, dispatch)
}

func registerBrokerHandler(mux *http.ServeMux, handler http.Handler) {
	mux.Handle("GET /clientless/auth/start", handler)
	mux.Handle("POST /clientless/auth/start", handler)
	mux.Handle("GET /clientless/auth/callback", handler)
	mux.Handle("POST /clientless/auth/retry", handler)
	mux.Handle("GET /clientless/auth/whoami", handler)
}
