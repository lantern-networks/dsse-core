package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeTransportMaterialIsScopedAndRejectsWrongPeers(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	sa, err := mintStoreAuthority("test", now, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeStoreAuthority(dir, sa); err != nil {
		t.Fatal(err)
	}
	if err = mintDatabaseAuthority(dir, "test", now, 2); err != nil {
		t.Fatal(err)
	}
	member, key, err := storeMemberMaterialFor(dir, map[string]string{"DSSE_ETCD_A_PEER_ADVERTISE": "https://127.0.0.1:2380"}, now, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, storeMemberFile), member, 0644); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, storeMemberKeyFile), key, 0600); err != nil {
		t.Fatal(err)
	}
	values := map[string]string{"DSSE_TOPOLOGY_PROFILE": "one-region-three-nodes", "DSSE_PG_A_NAME": "node-a", "DSSE_PG_A_ADVERTISE": "node-a.test:5432", "DSSE_NODE_ADDRESS": "127.0.0.1"}
	material, err := runtimeTransportMaterialFor(dir, values, now)
	if err != nil {
		t.Fatal(err)
	}
	other, err := runtimeTransportMaterialFor(dir, map[string]string{"DSSE_TOPOLOGY_PROFILE": "one-region-three-nodes", "DSSE_PG_A_NAME": "node-b", "DSSE_PG_A_ADVERTISE": "node-b.test:5432"}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{storeClientKeyFile, databaseServerKeyFile, cpQuorumKeyFile} {
		if bytes.Equal(material[name], other[name]) {
			t.Fatal("two nodes share runtime key: " + name)
		}
	}
	if err = writeRuntimeTransportMaterial(dir, material); err != nil {
		t.Fatal(err)
	}
	if err = validateRuntimeTransportMaterial(dir, values, now); err != nil {
		t.Fatal(err)
	}
	if err = validateRuntimeTransportMaterial(dir, map[string]string{"DSSE_PG_A_NAME": "node-b"}, now); err == nil {
		t.Fatal("another node accepted this material")
	}
	if err = validateRuntimeTransportMaterial(dir, values, now.AddDate(2, 0, 0)); err == nil {
		t.Fatal("expired material accepted")
	}
	for _, name := range []string{storeClientKeyFile, databaseServerKeyFile, cpQuorumKeyFile} {
		st, err := os.Stat(filepath.Join(dir, name))
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatalf("key permissions: %s %v", name, err)
		}
	}
	if bytes.Equal(material[storeClientKeyFile], material[databaseServerKeyFile]) || bytes.Equal(material[storeClientKeyFile], key) {
		t.Fatal("consumer and server keys were reused")
	}
	if bytes.Equal(material[cpQuorumKeyFile], material[storeClientKeyFile]) || bytes.Equal(material[cpQuorumKeyFile], key) {
		t.Fatal("CP quorum identity reuses Patroni or member key")
	}
	pool := x509.NewCertPool()
	pool.AddCert(sa.Cert)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"health":"true"}`)) }))
	memberPair, err := tls.X509KeyPair(member, key)
	if err != nil {
		t.Fatal(err)
	}
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{memberPair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	defer srv.Close()
	clientPair, err := tls.X509KeyPair(material[storeClientFile], material[storeClientKeyFile])
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		certs []tls.Certificate
		ok    bool
	}{
		{"consumer", []tls.Certificate{clientPair}, true}, {"no certificate", nil, false},
		{"database identity", nil, false},
	} {
		if tc.name == "database identity" {
			pair, e := tls.X509KeyPair(material[databaseServerFile], material[databaseServerKeyFile])
			if e != nil {
				t.Fatal(e)
			}
			tc.certs = []tls.Certificate{pair}
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "dsse-store-a", Certificates: tc.certs}}, Timeout: time.Second}
		r, e := client.Get(srv.URL)
		if r != nil {
			r.Body.Close()
		}
		if (e == nil) != tc.ok {
			t.Fatalf("%s result=%v", tc.name, e)
		}
		client.CloseIdleConnections()
	}

	if !verifyStoreConsumerAt(strings.TrimPrefix(srv.URL, "https://"), pool, clientPair) {
		t.Fatal("live verifier rejected authenticated store")
	}
	permissive := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{"health":"true"}`)) }))
	permissive.TLS = &tls.Config{Certificates: []tls.Certificate{memberPair}, ClientCAs: pool, ClientAuth: tls.VerifyClientCertIfGiven}
	permissive.StartTLS()
	defer permissive.Close()
	if verifyStoreConsumerAt(strings.TrimPrefix(permissive.URL, "https://"), pool, clientPair) {
		t.Fatal("store allowing anonymous clients passed verification")
	}
	if dest := os.Getenv("DSSE_RUNTIME_TRANSPORT_FIXTURE"); dest != "" {
		if err = os.MkdirAll(dest, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{storeCAFile, storeMemberFile, storeMemberKeyFile, databaseCAFile, storeClientFile, storeClientKeyFile, databaseServerFile, databaseServerKeyFile, cpQuorumFile, cpQuorumKeyFile} {
			b, e := os.ReadFile(filepath.Join(dir, name))
			if e != nil {
				t.Fatal(e)
			}
			mode := os.FileMode(0644)
			if name == storeMemberKeyFile || name == storeClientKeyFile || name == databaseServerKeyFile || name == cpQuorumKeyFile {
				mode = 0600
			}
			if e = os.WriteFile(filepath.Join(dest, name), b, mode); e != nil {
				t.Fatal(e)
			}
		}
		// The live fixture uses the generated private-key init service verbatim.
		if err = os.WriteFile(filepath.Join(dest, "init-compose.yml"), []byte("services:\n"+composePostgresTLSInit+"volumes:\n  postgres-tls:\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// Optional real fixed-image test. The fixture contains only disposable synthetic
// runtime identities; the caller starts and owns the containers and their cleanup.
func TestRuntimeTransportLiveVerificationFromFixture(t *testing.T) {
	path := os.Getenv("DSSE_RUNTIME_TRANSPORT_VERIFY_ENV")
	if path == "" {
		t.Skip("live Docker fixture not requested")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]string
	if err = json.Unmarshal(b, &env); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(path)
	for _, check := range verifyOneRegionThreeNodesReadiness(dir, env)[:2] {
		if !check.ok {
			t.Fatalf("live check failed: %s: %s", check.name, check.note)
		}
	}
}
