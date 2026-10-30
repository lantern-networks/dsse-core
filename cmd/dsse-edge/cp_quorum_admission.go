package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var errCPQuorumUnavailable = errors.New("control-plane consensus is unavailable; reconcile the operation before retrying")

const cpQuorumTimeout = 2 * time.Second

func (e *cpLeaderElector) checkQuorum(ctx context.Context) error {
	if e == nil || e.quorumCheck == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, cpQuorumTimeout)
	defer cancel()
	if e.quorumCheck(ctx) != nil {
		return errCPQuorumUnavailable
	}
	return nil
}

// The CP also authors enrollment and one-time credentials outside /admin.
// Administrative routes keep their permission-scoped refusal audit. Reads and
// Edge data traffic retain their existing authority/cache semantics.
func cpQuorumAdmissionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if adminMutatingMethod(r.Method) && !strings.HasPrefix(r.URL.Path, "/admin/") {
			if err := cpLeaderElectorInstance.checkQuorum(r.Context()); err != nil {
				writeError(w, http.StatusServiceUnavailable, err)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

type cpQuorumBootstrap struct {
	allowed                 bool
	marker, founderEndpoint string
}

// MemberList with linearizable=true cannot be served from a stale local cache.
// A response must describe all three planned voting client endpoints, preventing
// a freshly reset standalone etcd from being mistaken for the surviving cluster.
// One such response from any configured member proves consensus, not live TCP
// sockets or waiting for Patroni's lease to expire. No result is cached.
// This is admission, not an atomic etcd/Postgres transaction: a cut during an
// already admitted SQL transaction still has the existing PG fencing/RPO rules.
func newCPQuorumCheck(endpointsJSON, caFile, certFile, keyFile string, bootstrapOptions ...cpQuorumBootstrap) (func(context.Context) error, error) {
	var endpoints []string
	if err := json.Unmarshal([]byte(endpointsJSON), &endpoints); err != nil || len(endpoints) != 3 {
		return nil, fmt.Errorf("CP quorum requires exactly three HTTPS endpoints")
	}
	seen := make(map[string]bool)
	planned := make(map[string]bool)
	for _, endpoint := range endpoints {
		u, err := url.Parse(endpoint)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.Port() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" || seen[u.Host] {
			return nil, fmt.Errorf("invalid or duplicate CP quorum endpoint")
		}
		seen[u.Host] = true
		planned[endpoint] = true
	}
	bootstrap := cpQuorumBootstrap{}
	if len(bootstrapOptions) > 0 {
		bootstrap = bootstrapOptions[0]
	}
	if bootstrap.allowed && (bootstrap.marker == "" || !planned[bootstrap.founderEndpoint]) {
		return nil, fmt.Errorf("invalid founder-only quorum bootstrap configuration")
	}
	var sealed atomic.Bool
	sealed.Store(!bootstrap.allowed)
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CP quorum trust: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("invalid CP quorum trust")
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("read CP quorum identity: %w", err)
	}
	client := &http.Client{
		Transport:     &http.Transport{Proxy: nil, TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}, MaxIdleConnsPerHost: 4},
		Timeout:       cpQuorumTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return func(ctx context.Context) error {
		// The named-admin bootstrap writes this marker last. Its appearance seals
		// the live process immediately; absence after a seal cannot reopen it.
		// A stat failure other than absence is also closed, never a bypass.
		if !sealed.Load() {
			if _, err := os.Stat(bootstrap.marker); !os.IsNotExist(err) {
				sealed.Store(true)
			}
		}
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		results := make(chan bool, len(endpoints))
		for _, endpoint := range endpoints {
			go func(endpoint string) {
				body := []byte(`{"linearizable":true}`)
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/v3/cluster/member/list", bytes.NewReader(body))
				if err != nil {
					results <- false
					return
				}
				req.Header.Set("Content-Type", "application/json")
				response, err := client.Do(req)
				if err != nil {
					results <- false
					return
				}
				defer response.Body.Close()
				var membership struct {
					Header struct {
						ClusterID string `json:"cluster_id"`
					} `json:"header"`
					Members []struct {
						ID         string   `json:"ID"`
						Name       string   `json:"name"`
						ClientURLs []string `json:"clientURLs"`
						Learner    bool     `json:"isLearner"`
					} `json:"members"`
					Error json.RawMessage `json:"error"`
				}
				decoder := json.NewDecoder(io.LimitReader(response.Body, 65536))
				err = decoder.Decode(&membership)
				cluster, clusterErr := strconv.ParseUint(membership.Header.ClusterID, 10, 64)
				valid := err == nil && response.StatusCode == http.StatusOK && len(membership.Error) == 0 && clusterErr == nil && cluster > 0
				urls, ids, names := map[string]bool{}, map[string]bool{}, map[string]bool{}
				for _, member := range membership.Members {
					id, idErr := strconv.ParseUint(member.ID, 10, 64)
					if idErr != nil || id == 0 || ids[member.ID] || member.Name == "" || names[member.Name] || member.Learner || len(member.ClientURLs) != 1 || !planned[member.ClientURLs[0]] || urls[member.ClientURLs[0]] {
						valid = false
						break
					}
					ids[member.ID], names[member.Name], urls[member.ClientURLs[0]] = true, true, true
				}
				if valid && len(urls) == 3 {
					sealed.Store(true)
				} else if !(valid && !sealed.Load() && len(urls) == 1 && urls[bootstrap.founderEndpoint]) {
					valid = false
				}
				results <- valid
			}(strings.TrimSpace(endpoint))
		}
		for range endpoints {
			select {
			case ok := <-results:
				if ok {
					return nil
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return errCPQuorumUnavailable
	}, nil
}

func threeVoterDeployment(profile string) bool {
	return profile == "one-region-three-nodes" || profile == "three-regions-multi-edge"
}
