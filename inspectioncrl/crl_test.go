package inspectioncrl

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestRedundantDistributionPointsAreIssuerBoundAndUnique(t *testing.T) {
	certs, _, _, _ := fixture(t)
	issuer := certs[1]
	bases := []string{"http://192.0.2.1:80", "http://192.0.2.2:80", "http://192.0.2.3:80"}
	points, err := URLs(bases, "tenant_customer", issuer)
	if err != nil {
		t.Fatal(err)
	}
	got, err := BasesFromPoints(points, "tenant_customer", issuer)
	if err != nil || len(got) != 3 {
		t.Fatalf("valid redundant CDPs rejected: %v %v", got, err)
	}
	for i := range bases {
		if got[i] != bases[i] {
			t.Fatalf("CDP order or origin changed: %v", got)
		}
	}
	if _, err := URLs([]string{bases[0], bases[0]}, "tenant_customer", issuer); err == nil {
		t.Fatal("duplicate CDP origin accepted")
	}
	if _, err := URLs([]string{"http://crl.example.test", "http://CRL.example.test:80"}, "tenant_customer", issuer); err == nil {
		t.Fatal("equivalent default-port CDP origins accepted")
	}
	if _, err := BasesFromPoints(points, "another_tenant", issuer); err == nil {
		t.Fatal("another tenant's CDP accepted")
	}
	if _, err := BasesFromPoints(points, "tenant_customer", certs[2]); err == nil {
		t.Fatal("another issuer's CDP accepted")
	}
}

func fixture(t *testing.T) ([]*x509.Certificate, []*ecdsa.PrivateKey, map[string][]byte, time.Time) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	certs := make([]*x509.Certificate, 4)
	keys := make([]*ecdsa.PrivateKey, 4)
	lists := map[string][]byte{}
	for i := 0; i < 4; i++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys[i] = key
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(int64(i + 1)), Subject: pkix.Name{CommonName: []string{"root", "issuing", "edge", "leaf"}[i]}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true, IsCA: i < 3, MaxPathLen: 2 - i, MaxPathLenZero: i == 2, KeyUsage: x509.KeyUsageDigitalSignature}
		if i < 3 {
			tmpl.KeyUsage |= x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		} else {
			tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			tmpl.DNSNames = []string{"app.dsse.test"}
		}
		parent := tmpl
		parentKey := key
		if i > 0 {
			parent = certs[i-1]
			parentKey = keys[i-1]
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		if err != nil {
			t.Fatal(err)
		}
		certs[i], err = x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if i < 3 {
			lists[Fingerprint(certs[i])], err = Sign(certs[i], key, big.NewInt(1), nil, now, 5*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	return []*x509.Certificate{certs[3], certs[2], certs[1], certs[0]}, []*ecdsa.PrivateKey{keys[3], keys[2], keys[1], keys[0]}, lists, now
}

func TestCompleteChainRevocation(t *testing.T) {
	chain, keys, lists, now := fixture(t)
	if err := CheckChain(chain, lists, now); err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"leaf", "edge", "issuing"} {
		t.Run("revoked_"+name, func(t *testing.T) {
			next := map[string][]byte{}
			for fp, der := range lists {
				next[fp] = der
			}
			issuer := chain[i+1]
			der, err := Sign(issuer, keys[i+1], big.NewInt(2), []x509.RevocationListEntry{{SerialNumber: chain[i].SerialNumber, RevocationTime: now}}, now, 5*time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			next[Fingerprint(issuer)] = der
			if CheckChain(chain, next, now) == nil {
				t.Fatal("revoked certificate accepted")
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		delete(lists, Fingerprint(chain[1]))
		if CheckChain(chain, lists, now) == nil {
			t.Fatal("missing status accepted")
		}
	})
}

func TestCRLRejectsUnverifiableStatus(t *testing.T) {
	chain, keys, lists, now := fixture(t)
	issuer := chain[1]
	valid := lists[Fingerprint(issuer)]
	for _, name := range []string{"stale", "wrong_issuer", "tampered", "missing", "future"} {
		t.Run(name, func(t *testing.T) {
			der := append([]byte(nil), valid...)
			at := now
			switch name {
			case "stale":
				at = now.Add(6 * time.Minute)
			case "wrong_issuer":
				der = lists[Fingerprint(chain[2])]
			case "tampered":
				der[len(der)-1] ^= 1
			case "missing":
				der = nil
			case "future":
				var err error
				der, err = Sign(issuer, keys[1], big.NewInt(2), nil, now.Add(2*time.Minute), time.Minute)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := ParseAndValidate(der, issuer, at); err == nil {
				t.Fatal("bad status accepted")
			}
		})
	}
	if _, err := Sign(issuer, keys[2], big.NewInt(2), nil, now, time.Minute); err == nil {
		t.Fatal("wrong signer accepted")
	}
	if _, err := Sign(issuer, keys[1], big.NewInt(2), []x509.RevocationListEntry{{SerialNumber: nil}}, now, time.Minute); err == nil {
		t.Fatal("nil serial accepted")
	}
}

func TestCRLUpdatesCannotHideKnownRevocations(t *testing.T) {
	chain, keys, _, now := fixture(t)
	issuer := chain[1]
	entries := []x509.RevocationListEntry{{SerialNumber: chain[0].SerialNumber, RevocationTime: now}}
	prior, err := Sign(issuer, keys[1], big.NewInt(2), entries, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err = AcceptUpdate(prior, prior, issuer, now); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		number  int64
		entries []x509.RevocationListEntry
		pass    bool
	}{
		{"higher_preserves", 3, entries, true}, {"lower", 1, entries, false}, {"same_equivocates", 2, nil, false}, {"cleared", 3, nil, false}, {"postponed", 3, []x509.RevocationListEntry{{SerialNumber: chain[0].SerialNumber, RevocationTime: now.Add(time.Second)}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			next, e := Sign(issuer, keys[1], big.NewInt(tc.number), tc.entries, now, time.Minute)
			if e != nil {
				t.Fatal(e)
			}
			if (AcceptUpdate(prior, next, issuer, now) == nil) != tc.pass {
				t.Fatal("unexpected update result")
			}
		})
	}
	next, _ := Sign(issuer, keys[1], big.NewInt(3), entries, now.Add(2*time.Minute), time.Minute)
	if err = AcceptUpdate(prior, next, issuer, now.Add(2*time.Minute)); err != nil {
		t.Fatal("fresh CRL must replace stale status while preserving denials:", err)
	}
}

func TestNaturalCRLExpiration(t *testing.T) {
	chain, keys, _, _ := fixture(t)
	now := time.Now().UTC()
	der, err := Sign(chain[1], keys[1], big.NewInt(9), nil, now, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ParseAndValidate(der, chain[1], time.Now()); err != nil {
		t.Fatal(err)
	}
	list, _ := x509.ParseRevocationList(der)
	time.Sleep(time.Until(list.NextUpdate) + 50*time.Millisecond)
	if _, err = ParseAndValidate(der, chain[1], time.Now()); err == nil {
		t.Fatal("naturally expired CRL accepted")
	}
}
