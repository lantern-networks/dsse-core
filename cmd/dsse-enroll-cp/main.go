// dsse-enroll-cp — a reference/dev Control-Plane enrollment endpoint (roadmap M4c). It stands up the
// enroll.Issuer over HTTP: verify a shared eligibility token, sign the device CSR with a device CA, assign a
// tenant/group, and return the issued cert + CA. This is the standalone reference for wiring the same handler
// into cmd/edge (registerEnrollEndpoint). It generates a fresh device CA and prints its SHA-256 pin so an agent
// can pass --enroll-ca-pin. NOT for production (in prod the CA key lives in an HSM and eligibility is real).
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"flag"
	"log"
	"math/big"
	"net/http"
	"time"

	"github.com/lantern-networks/dsse-core/deviceca"
	"github.com/lantern-networks/dsse-core/enroll"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18099", "listen address")
	token := flag.String("token", "good", "shared eligibility token that enrolls")
	tenant := flag.String("tenant", "acme", "tenant the CP assigns")
	group := flag.String("group", "developers", "group the CP assigns")
	flag.Parse()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now()
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "DSSE Device CA (dev)"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(3650 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		log.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	signer := deviceca.NewSigner(caCert, caKey)
	sum := sha256.Sum256(caCert.Raw)

	iss := enroll.Issuer{
		Signer:  signer,
		CertTTL: 60 * 24 * time.Hour, // 60-day device cert (short-lived; auto-renew replaces manual re-mint)
		Assign: func(req enroll.Request) (t, g, reason string, ok bool) {
			if req.Eligibility.Mode == "token" && req.Eligibility.Token == *token {
				return *tenant, *group, "", true
			}
			return "", "", "invalid or missing eligibility token", false
		},
		Record: func(deviceID, t, g string) error {
			log.Printf("enrolled device=%q tenant=%q group=%q", deviceID, t, g)
			return nil
		},
		Logf:             log.Printf,
		NowPolicyVersion: 1,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/enroll", iss.Handler())
	log.Printf("dsse-enroll-cp on http://%s/enroll  tenant=%s group=%s", *listen, *tenant, *group)
	log.Printf("device CA pin (--enroll-ca-pin): %s", hex.EncodeToString(sum[:]))
	log.Fatal(http.ListenAndServe(*listen, mux))
}
