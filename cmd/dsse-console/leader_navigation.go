package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/authportal"
)

const consoleLeaderRoutingEnv = "DSSE_CONSOLE_LEADER_ROUTING"
const consoleHandoffQuery = "console_handoff"

type consoleLeaderCandidate struct {
	Node          string `json:"node"`
	LeaderURL     string `json:"leader_url"`
	TLSName       string `json:"tls_name"`
	ConsoleOrigin string `json:"console_origin"`
	client        *http.Client
}

type consoleLeaderRouting struct {
	LocalNode  string                   `json:"local_node"`
	Candidates []consoleLeaderCandidate `json:"candidates"`
	now        func() time.Time
	mu         sync.Mutex
	until      time.Time
	active     *consoleLeaderCandidate
}

// Destination origins and private leader probes come only from deployment
// configuration. No redirect target, Cookie or Authorization comes from a request.
func newConsoleLeaderRouting(raw string, trust *tls.Config) (*consoleLeaderRouting, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var routing consoleLeaderRouting
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&routing); err != nil {
		return nil, fmt.Errorf("invalid Console leader routing: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, fmt.Errorf("trailing Console leader routing data")
	}
	if routing.LocalNode == "" || len(routing.Candidates) == 0 || trust == nil {
		return nil, fmt.Errorf("Console leader routing needs local node, CP candidates and TLS trust")
	}
	nodes, probes := map[string]bool{}, map[string]bool{}
	for i := range routing.Candidates {
		c := &routing.Candidates[i]
		u, err := url.Parse(c.LeaderURL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "/leader" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.ContainsAny(c.TLSName, "*/\\@?# \t\r\n") || (strings.Contains(c.TLSName, ":") && net.ParseIP(c.TLSName) == nil) || c.TLSName == "" || c.Node == "" || nodes[c.Node] || probes[c.LeaderURL] {
			return nil, fmt.Errorf("Console candidates need distinct nodes and direct HTTPS /leader probes with exact TLS names")
		}
		origin, err := authportal.Origin(c.ConsoleOrigin)
		if err != nil {
			return nil, fmt.Errorf("invalid Console destination origin")
		}
		c.ConsoleOrigin = strings.TrimSuffix(origin, ":443")
		nodes[c.Node], probes[c.LeaderURL] = true, true
		config := trust.Clone()
		config.ServerName = c.TLSName
		if config.InsecureSkipVerify {
			return nil, fmt.Errorf("Console leader probes require TLS verification")
		}
		c.client = &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: config}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if !nodes[routing.LocalNode] {
		return nil, fmt.Errorf("local Console node is absent from CP candidates")
	}
	routing.now = time.Now
	return &routing, nil
}

func (p *consoleLeaderRouting) leader() *consoleLeaderCandidate {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.now().Before(p.until) {
		return p.active
	}
	// Coalesce anonymous navigation bursts, like /ready. A caller going away
	// cannot poison the shared result. Probes share one total bounded interval.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	found := make(chan *consoleLeaderCandidate, len(p.Candidates))
	for i := range p.Candidates {
		candidate := &p.Candidates[i]
		go func() {
			var active *consoleLeaderCandidate
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, candidate.LeaderURL, nil)
			if err == nil {
				response, e := candidate.client.Do(request)
				if e == nil {
					var status struct {
						Leader bool `json:"leader"`
					}
					if response.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&status) == nil && status.Leader {
						active = candidate
					}
					response.Body.Close()
				}
			}
			found <- active
		}()
	}
	var active *consoleLeaderCandidate
	count := 0
	for range p.Candidates {
		if candidate := <-found; candidate != nil {
			active = candidate
			count++
		}
	}
	if count != 1 {
		active = nil
	} // Neither guessing a leader nor accepting split-brain.
	p.active = active
	p.until = p.now().Add(time.Second)
	return active
}

func (p *consoleLeaderRouting) navigation(next http.Handler) http.Handler {
	if p == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Method != http.MethodGet && r.Method != http.MethodHead) || !isNavigation(r) || (r.URL.Path != "/" && r.URL.Path != "/index.html" && r.URL.Path != "/console.html") {
			next.ServeHTTP(w, r)
			return
		}
		// Activation links and OIDC callbacks belong to the original origin. Never
		// move authentication parameters, form submissions, API calls or assets.
		handoff := r.URL.RawQuery == consoleHandoffQuery+"=1"
		if r.URL.RawQuery != "" && !handoff {
			next.ServeHTTP(w, r)
			return
		}
		active := p.leader()
		if active == nil {
			consoleLeaderUnavailable(w, r)
			return
		}
		// A healthy entrance may have already routed this request to the active
		// Console under another approved public name. Keep that working path:
		// the active CP's own public entrance can be down while its CP/Console
		// remain healthy. The original origin's authentication gate still applies.
		if active.Node == p.LocalNode {
			if handoff {
				// Clear the one-hop marker on the confirmed destination so a
				// later reload can follow a subsequent leadership change.
				w.Header().Set("Cache-Control", "no-store")
				w.Header().Set("Referrer-Policy", "no-referrer")
				http.Redirect(w, r, r.URL.Path+"#", http.StatusFound)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		current, err := authportal.Origin("https://" + r.Host)
		target, _ := authportal.Origin(active.ConsoleOrigin)
		// Shared one-Region names already route through the leader-aware L4 pool.
		// During health-check overlap do not redirect to the same name in a loop.
		if handoff || (err == nil && current == target) {
			consoleLeaderUnavailable(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// A constant one-hop marker bounds races between independently cached
		// observations. Explicit empty fragment avoids inheriting a sensitive hash.
		http.Redirect(w, r, active.ConsoleOrigin+r.URL.Path+"?"+consoleHandoffQuery+"=1#", http.StatusFound)
	})
}

func consoleLeaderUnavailable(w http.ResponseWriter, r *http.Request) {
	title, body, retry := "Active management server unavailable", "The active control plane could not be confirmed. Retry shortly; no changes were submitted.", "Retry"
	if strings.HasPrefix(strings.ToLower(r.Header.Get("Accept-Language")), "ja") {
		title = "稼働中の管理サーバーを確認できません"
		body = "管理サーバーの切り替え中か、主系を確認できない状態です。少し待って再試行してください。変更は送信されていません。"
		retry = "再試行する"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Retry-After", "1")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusServiceUnavailable)
	// The retry is same-origin and has no handoff/credential query. Never use Host.
	fmt.Fprintf(w, "<!doctype html><html><head><meta charset=\"utf-8\"><title>%s</title></head><body><h1>%s</h1><p>%s</p><a href=\"%s\">%s</a></body></html>", html.EscapeString(title), html.EscapeString(title), html.EscapeString(body), html.EscapeString(r.URL.Path), html.EscapeString(retry))
}
