package deploymentcrl

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

// InspectionCRLPathPrefix is where an organization's interception authorities publish their lists. The
// deployment's own lists are under /pki/deployment-crl/; a certificate of either kind names the same origin.
const InspectionCRLPathPrefix = "/pki/crl/"

// WithInspectionCRLUpstream lets one HTTP entrance serve both kinds of list. Requests under
// InspectionCRLPathPrefix for a declared origin are handed, unchanged, to the control plane's own read-only
// list listener on this machine; everything else goes to next. The upstream must be on loopback: this
// process holds no key and is not a way to reach anything else.
func WithInspectionCRLUpstream(next http.Handler, origins []string, upstream string) (http.Handler, error) {
	host, _, err := net.SplitHostPort(upstream)
	if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
		return nil, fmt.Errorf("the inspection CRL upstream must be a loopback address and port, like 127.0.0.1:18080; got %q", upstream)
	}
	allowedHosts := map[string]bool{}
	for _, origin := range origins {
		u, perr := url.Parse(strings.TrimSpace(origin))
		if perr != nil || u.Scheme != "http" || u.Host == "" {
			return nil, fmt.Errorf("invalid CRL origin %q", origin)
		}
		allowedHosts[httpHostKey(u.Host)] = true
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme = "http"
			r.Out.URL.Host = upstream
			r.Out.Host = r.In.Host // the control plane checks the name the certificate carries
		},
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "revocation status unavailable", http.StatusServiceUnavailable)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, InspectionCRLPathPrefix) {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !allowedHosts[httpHostKey(r.Host)] || r.URL.RawQuery != "" || r.URL.RawPath != "" || !strings.HasSuffix(r.URL.Path, ".crl") || strings.Contains(r.URL.Path, "..") {
			http.NotFound(w, r)
			return
		}
		proxy.ServeHTTP(w, r)
	}), nil
}

// httpHostKey names an HTTP host by what it is: the host name in lower case and the port it is reached on.
// "crl.example.test" and "crl.example.test:80" are the same origin over HTTP, a client may send either, and a
// plan may declare either; compared as written, a list held here was refused to a client that asked for it
// by the other spelling (review, 2026-11-14).
func httpHostKey(hostport string) string {
	host, port := hostport, "80"
	if h, p, err := net.SplitHostPort(hostport); err == nil {
		host, port = h, p
	}
	return strings.ToLower(strings.Trim(host, "[]")) + ":" + port
}
