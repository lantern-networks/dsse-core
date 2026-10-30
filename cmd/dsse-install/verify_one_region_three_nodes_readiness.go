package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/lib/pq"
)

// Configuration is a precondition, never evidence that a running peer authenticates.
func verifyOneRegionThreeNodesReadiness(dir string, env map[string]string) []verifyResult {
	return []verifyResult{verifyStoreConsumerAuthentication(dir, env), verifyDatabaseIdentity(dir, env),
		verifySharedFleetPortalEntrances(dir, env, "")}
}

func verifyStoreConsumerAuthentication(dir string, env map[string]string) verifyResult {
	result := verifyResult{name: "etcd client mutual authentication", note: "runtime authentication not proven: require the dedicated consumer identity, authenticated etcd health, and rejection without a client certificate"}
	if env["DSSE_ETCD_CLIENT_CERT_AUTH"] != "true" || env["DSSE_ETCD_CLIENT_SCHEME"] != "https" || env["DSSE_ETCD_CLIENT_CERT"] != "/run/dsse-postgres-tls/store-client.pem" || env["DSSE_ETCD_CLIENT_KEY"] != "/run/dsse-postgres-tls/store-client-key.pem" {
		return result
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, storeClientFile), filepath.Join(dir, storeClientKeyFile))
	if err != nil {
		return result
	}
	ca, err := os.ReadFile(filepath.Join(dir, storeCAFile))
	if err != nil {
		return result
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return result
	}
	hosts := storeClientHosts(env["DSSE_ETCD_HOSTS"])
	if len(hosts) == 0 {
		return result
	}
	for _, host := range hosts {
		if !verifyStoreConsumerAt(host, roots, pair) {
			return result
		}
	}
	result.ok = true
	result.note = "every configured etcd endpoint answered authenticated health and rejected a TLS request without a client certificate; Patroni key readability must also be verified on the running image"
	return result
}

func verifyStoreConsumerAt(host string, roots *x509.CertPool, pair tls.Certificate) bool {
	authenticated := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{pair}}}}
	defer authenticated.CloseIdleConnections()
	endpoint := "https://" + host + "/health"
	r, err := authenticated.Get(endpoint)
	if err != nil {
		return false
	}
	body, readErr := io.ReadAll(io.LimitReader(r.Body, 4096))
	r.Body.Close()
	var health struct {
		Health string `json:"health"`
	}
	if readErr != nil || r.StatusCode != http.StatusOK || json.Unmarshal(body, &health) != nil || health.Health != "true" {
		return false
	}
	anonymous := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}}}
	defer anonymous.CloseIdleConnections()
	r, err = anonymous.Get(endpoint)
	if r != nil {
		r.Body.Close()
	}
	// Timeout, DNS failure or HTTP rejection is not evidence of client authentication.
	return err != nil && (strings.Contains(err.Error(), "remote error: tls: certificate required") || strings.Contains(err.Error(), "remote error: tls: bad certificate"))
}

func verifyDatabaseIdentity(dir string, env map[string]string) verifyResult {
	result := verifyResult{name: "database server identity verification", note: "runtime database identity not proven: require a successful verify-full connection using the dedicated database CA"}
	host := env["DSSE_PG_PUBLISH"]
	if host == "" {
		host = "127.0.0.1:15432"
	}
	u := url.URL{Scheme: "postgres", Host: host, Path: "postgres", User: url.UserPassword("postgres", env["PG_SUPERUSER_PASSWORD"])}
	query := url.Values{"sslmode": {"verify-full"}, "sslrootcert": {filepath.Join(dir, databaseCAFile)}, "connect_timeout": {"5"}}
	u.RawQuery = query.Encode()
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		return result
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var encrypted bool
	if err = db.QueryRowContext(ctx, "SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()").Scan(&encrypted); err != nil || !encrypted {
		return result
	}
	result.ok = true
	result.note = "the published database door accepted a verify-full connection with the dedicated database CA; pg_stat_ssl confirms TLS"
	return result
}
