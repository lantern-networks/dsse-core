package main

import (
	"github.com/lantern-networks/dsse-core/certreload"
	"log"
	"strings"
)

func recoverConfiguredCertificatePairs(pairs ...[2]string) {
	for _, pair := range pairs {
		cp, kp := strings.TrimSpace(pair[0]), strings.TrimSpace(pair[1])
		if cp == "" || kp == "" {
			continue
		}
		if err := certreload.RecoverPair(cp, kp); err != nil {
			log.Fatalf("recover configured certificate pair: %v", err)
		}
	}
}
