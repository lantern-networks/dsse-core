package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// storeUnder starts a server that answers etcd's member-list gateway with the given membership, using a
// certificate this deployment's store authority signed — so the check's TLS, its client certificate and its
// parsing are all exercised, not just its arithmetic.
func storeUnder(t *testing.T, dir, membersJSON string) string {
	t.Helper()
	now := time.Now().UTC()
	sa, err := mintStoreAuthority("Example", now, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeStoreAuthority(dir, sa); err != nil {
		t.Fatal(err)
	}
	cert, key, err := storeMemberMaterialFor(dir, nil, now, 5)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeStoreMemberBytes(t, dir, cert, key); err != nil {
		t.Fatal(err)
	}

	// The server's own certificate has to be valid for the loopback address the check will dial.
	srvKey, err := newKey()
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "dsse-store-test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, sa.Cert, &srvKey.PublicKey, sa.Key)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v3/cluster/member/list" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(membersJSON))
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: srvKey}}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "https://")
}

func writeStoreMemberBytes(t *testing.T, dir string, cert, key []byte) error {
	t.Helper()
	c, err := firstCertificateIn(cert)
	if err != nil {
		return err
	}
	k, err := firstECKeyIn(key)
	if err != nil {
		return err
	}
	return writeStoreMember(dir, c, k)
}

// ★★★ TWO VOTING MEMBERS IS A WORKING DEPLOYMENT THAT CANNOT LOSE ONE, and it looks exactly like three from
// every other angle. This is the only check that asks what happens when a place stops.
func TestAStoreThatCannotLoseAPlaceIsNotGreen(t *testing.T) {
	dir := t.TempDir()
	host := storeUnder(t, dir, `{"members":[
	  {"name":"dsse-store-tokyo-a","peerURLs":["https://a.example.test:12390"]},
	  {"name":"dsse-store-tokyo-c","peerURLs":["https://c.example.test:12390"]},
	  {"name":"dsse-store-osaka","peerURLs":["https://o.example.test:12390"],"isLearner":true}]}`)

	got := verifyTheStoreCanLoseAPlace(dir, map[string]string{
		"DSSE_ETCD_CLIENT_SCHEME": "https",
		"DSSE_ETCD_HOSTS":         "'" + host + "'",
	})
	if len(got) != 1 {
		t.Fatalf("expected one result, got %d", len(got))
	}
	if got[0].ok {
		t.Errorf("a cluster of two voting members and a learner was reported as able to lose a place: %s", got[0].note)
	}
	for _, want := range []string{"2 voting member(s)", "learner", "MANUAL"} {
		if !strings.Contains(got[0].note, want) {
			t.Errorf("the note does not say %q, so a reader cannot tell why it is not redundant: %s", want, got[0].note)
		}
	}
}

// ★ AND THREE VOTING MEMBERS IN THREE PLACES IS. The arithmetic is "losing one leaves a quorum", not "three".
func TestAStoreWithAVoteInEachPlaceIsGreen(t *testing.T) {
	dir := t.TempDir()
	host := storeUnder(t, dir, `{"members":[
	  {"name":"dsse-store-tokyo-a","peerURLs":["https://a.example.test:12390"]},
	  {"name":"dsse-store-tokyo-c","peerURLs":["https://c.example.test:12390"]},
	  {"name":"dsse-store-osaka","peerURLs":["https://o.example.test:12390"]}]}`)
	got := verifyTheStoreCanLoseAPlace(dir, map[string]string{
		"DSSE_ETCD_CLIENT_SCHEME": "https",
		"DSSE_ETCD_HOSTS":         "'" + host + "'",
	})
	if !got[0].ok {
		t.Errorf("a vote in each of three places was not reported as able to lose one: %s", got[0].note)
	}
	if !strings.Contains(got[0].note, "3 place(s)") {
		t.Errorf("the note does not say where the votes are: %s", got[0].note)
	}
}

// ★ AND A STORE NOBODY CAN REACH IS NOT GREEN EITHER. "No member answered" is not "nothing is wrong".
func TestAStoreThatCannotBeAskedIsNotGreen(t *testing.T) {
	dir := t.TempDir()
	_ = storeUnder(t, dir, `{"members":[]}`)
	got := verifyTheStoreCanLoseAPlace(dir, map[string]string{
		"DSSE_ETCD_CLIENT_SCHEME": "https",
		"DSSE_ETCD_HOSTS":         "'127.0.0.1:1'",
	})
	if got[0].ok {
		t.Errorf("an unreachable store was reported as fine: %s", got[0].note)
	}
}
