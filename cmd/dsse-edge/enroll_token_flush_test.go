package main

import (
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/enrolltoken"
)

func TestEnrolmentDoesNotIssueIdentityAfterUnconfirmedTokenSpend(t *testing.T) {
	for _, mode := range []string{"unconfirmed", "bridge", "synced_in_place"} {
		t.Run(mode, func(t *testing.T) {
			mux, tokens, ledger := newTokenEnrolTestMux(t)
			p := &enrolmentAuditPersister{}
			tokens.SetPersister(p)
			secret := mintToken(t, tokens, time.Hour)
			generation := tokens.Generation()
			_, unknown := enrolPost(t, mux, "unknown-device", "never-issued")
			p.saveErr = blobstore.ErrDurabilityUnconfirmed
			if mode == "bridge" {
				p.saveErr = errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
			}
			if mode == "synced_in_place" {
				p.saveErr = blobstore.ErrSavedWithoutAtomicity
			}
			code, resp := enrolPost(t, mux, "first-device", secret)
			if mode == "synced_in_place" {
				if code != http.StatusOK || resp.CertPEM == "" || !ledger.IsAdmitted("first-device") || tokens.Generation() != generation+1 || tokens.Health() != nil {
					t.Fatal("completed save refused enrolment")
				}
			} else {
				if code != http.StatusForbidden || resp.CertPEM != "" || ledger.IsAdmitted("first-device") || resp.Error != unknown.Error {
					t.Fatal("unconfirmed token spend issued an identity or disclosed token validity")
				}
				if !errors.Is(tokens.Health(), enrolltoken.ErrStateUnavailable) || tokens.Generation() != generation {
					t.Fatal("unconfirmed spend not latched")
				}
			}
			// Restoring storage alone cannot authorize a second device, including
			// after a completed in-place spend. Both refusals use the generic message.
			p.saveErr = nil
			code, resp = enrolPost(t, mux, "second-device", secret)
			if code != http.StatusForbidden || resp.CertPEM != "" || ledger.IsAdmitted("second-device") || resp.Error != unknown.Error {
				t.Fatal("retry admitted second device or exposed validity")
			}
			// This fake retained the new bytes; reopening sees the spend even
			// though the failed operation never returned a certificate.
			reopened := enrolltoken.NewStore()
			reopened.SetPersister(p)
			if _, err := reopened.Verify(secret, "tenant_test", time.Now()); !errors.Is(err, enrolltoken.ErrTokenUsed) {
				t.Fatalf("retained spend lost: %v", err)
			}
		})
	}
}
