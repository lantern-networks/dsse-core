package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/vendorlicense"
)

// ★ "NO LONGER VERIFIES" HAS THREE CAUSES AND THEY NEED THREE DIFFERENT RESPONSES (2026-08-17, found on the
// lab). The verifier names the one that happened; the store discarded it and answered a bare false, so the
// Console guessed — "usually a vendor signing key that has been withdrawn" — and the guess was wrong. The
// licence verified perfectly and was addressed to an MSSP id the deployment had since been renamed away from.
// Meanwhile no device could enrol: POST /enroll answered 403 with a freshly issued enrolment token.
//
// A wrong cause is worse than none: it sends an operator to their vendor for a replacement key while the fix
// was a re-issue to the new holder.
func TestALicenceThatStoppedVerifyingSaysWhichCheckFailed(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	accepted := []*ecdsa.PublicKey{&key.PublicKey}
	payload := testLicence(10)
	payload.MSSPID = "tenant_old_name"
	env, err := vendorlicense.Sign(payload, "signing-key.pem", key, licenceNow())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	store := newLicenseStore()
	if _, err := store.Apply(env, accepted, "tenant_old_name", "adm_test", licenceNow().Format(time.RFC3339)); err != nil {
		t.Fatalf("apply: %v", err)
	}

	// It verifies for the holder it was issued to.
	if _, ok := store.Current(accepted, "tenant_old_name"); !ok {
		t.Fatal("the licence must verify for the holder it names")
	}

	// The deployment is renamed. This is the lab's actual situation.
	p, ok, why := store.CurrentWithReason(accepted, "tenant_new_name")
	if ok {
		t.Fatalf("a licence addressed elsewhere must not verify here, got %+v", p)
	}
	if why == nil {
		t.Fatal("the reason was discarded — this is the defect: the Console can then only guess at the cause")
	}
	if !strings.Contains(why.Error(), "tenant_old_name") || !strings.Contains(why.Error(), "tenant_new_name") {
		t.Fatalf("the reason must name BOTH holders so an operator knows what to ask for, got %q", why.Error())
	}
	// And it must not be mistaken for the other two causes.
	if strings.Contains(why.Error(), "signed by any accepted vendor key") || strings.Contains(why.Error(), "replay") {
		t.Fatalf("the addressee failure is being reported as a signing-key or rollback failure: %q", why.Error())
	}

	// A withdrawn signing key is a DIFFERENT sentence, from the same call.
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	_, ok, why = store.CurrentWithReason([]*ecdsa.PublicKey{&other.PublicKey}, "tenant_old_name")
	if ok || why == nil {
		t.Fatal("a licence signed by no accepted key must fail, with a reason")
	}
	if !strings.Contains(why.Error(), "vendor key") {
		t.Fatalf("a withdrawn key must say so, got %q", why.Error())
	}
}
