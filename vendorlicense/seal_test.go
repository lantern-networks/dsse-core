package vendorlicense

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
)

func newRecipient(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("recipient key: %v", err)
	}
	return k
}

func TestASealedLicenceOpensForItsRecipientAndVerifies(t *testing.T) {
	signing := newKey(t)
	recipient := newRecipient(t)

	sealed, err := Seal(sign(t, paidPayload(), signing), recipient.PublicKey(), "mssp_partner_a-key-1")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	env, err := Open(sealed, recipient)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// Decryption proves only that the file was addressed here. The signature is what proves the vendor issued
	// it, and it is checked afterwards, exactly as it would be for an unsealed file.
	got, err := Verify(env, []*ecdsa.PublicKey{&signing.PublicKey}, "mssp_partner_a", 0)
	if err != nil {
		t.Fatalf("verify after open: %v", err)
	}
	if got.SeatsAt(testNow()) != 5000 {
		t.Fatalf("payload did not survive sealing: %+v", got)
	}
}

// The point of sealing: everyone who handles the file in transit learns nothing from it.
func TestASealedLicenceRevealsNothingToSomeoneHandlingIt(t *testing.T) {
	signing := newKey(t)
	p := paidPayload()
	sealed, err := Seal(sign(t, p, signing), newRecipient(t).PublicKey(), "")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	raw, _ := json.Marshal(sealed)
	for _, secret := range []string{"5000", "mssp_partner_a", "seats", "expires_at"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("the sealed file leaks %q to anyone who opens it", secret)
		}
	}
}

func TestAnotherHoldersKeyCannotOpenIt(t *testing.T) {
	sealed, err := Seal(sign(t, paidPayload(), newKey(t)), newRecipient(t).PublicKey(), "")
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := Open(sealed, newRecipient(t)); err == nil {
		t.Fatalf("a different holder's key must not open it")
	}
}

// Wrong key and tampered file must be indistinguishable: telling them apart would let somebody probing find out
// whether they have the right key.
func TestATamperedSealedLicenceFailsTheSameWayAsAWrongKey(t *testing.T) {
	recipient := newRecipient(t)
	sealed, _ := Seal(sign(t, paidPayload(), newKey(t)), recipient.PublicKey(), "")

	ct, _ := base64.StdEncoding.DecodeString(sealed.Ciphertext)
	ct[len(ct)/2] ^= 0xff
	tampered := sealed
	tampered.Ciphertext = base64.StdEncoding.EncodeToString(ct)

	_, tamperErr := Open(tampered, recipient)
	_, wrongKeyErr := Open(sealed, newRecipient(t))
	if tamperErr == nil || wrongKeyErr == nil {
		t.Fatalf("both must fail")
	}
	if tamperErr.Error() != wrongKeyErr.Error() {
		t.Fatalf("the two must be indistinguishable, got %q and %q", tamperErr, wrongKeyErr)
	}
}

// Sign-then-seal lets a recipient re-seal the same signed licence to somebody else. It decrypts there — nothing
// stops that — and the addressee check inside the signed payload is what refuses it.
func TestASignedLicenceReSealedToAnotherHolderStillFailsVerification(t *testing.T) {
	signing := newKey(t)
	first, second := newRecipient(t), newRecipient(t)

	sealed, _ := Seal(sign(t, paidPayload(), signing), first.PublicKey(), "")
	env, err := Open(sealed, first)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	// The first holder forwards it, sealed to the second.
	reSealed, _ := Seal(env, second.PublicKey(), "")
	envAgain, err := Open(reSealed, second)
	if err != nil {
		t.Fatalf("re-sealing decrypts, as expected: %v", err)
	}
	// And is refused, because the signed payload names who it is for.
	if _, err := Verify(envAgain, []*ecdsa.PublicKey{&signing.PublicKey}, "mssp_the_second_one", 0); err == nil {
		t.Fatalf("a re-targeted licence must fail verification for the new holder")
	}
	// It still verifies for the holder it was actually issued to, which is what makes it a forwarding attack
	// rather than a forgery.
	if _, err := Verify(envAgain, []*ecdsa.PublicKey{&signing.PublicKey}, "mssp_partner_a", 0); err != nil {
		t.Fatalf("the real addressee is unaffected: %v", err)
	}
}

// Every licence gets a fresh ephemeral key, which is what makes the fixed nonce safe. Two seals of identical
// content must not produce identical bytes.
func TestEachSealUsesAFreshEphemeralKey(t *testing.T) {
	signing := newKey(t)
	recipient := newRecipient(t)
	env := sign(t, paidPayload(), signing)
	a, _ := Seal(env, recipient.PublicKey(), "")
	b, _ := Seal(env, recipient.PublicKey(), "")
	if a.EphemeralPublicKey == b.EphemeralPublicKey {
		t.Fatalf("the ephemeral key must never repeat — a fixed nonce is only safe because of that")
	}
	if a.Ciphertext == b.Ciphertext {
		t.Fatalf("identical ciphertext means the key repeated")
	}
}

func TestRecipientKeysRoundTripThroughPEM(t *testing.T) {
	k := newRecipient(t)
	privDER, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatalf("marshal private: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(k.PublicKey())
	if err != nil {
		t.Fatalf("marshal public: %v", err)
	}
	priv, err := ParseRecipientPrivateKeyPEM(string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})))
	if err != nil {
		t.Fatalf("parse private: %v", err)
	}
	pub, err := ParseRecipientPublicKeyPEM(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})))
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}
	// The parsed halves must still be a pair, or a deployment would silently fail to open anything.
	sealed, _ := Seal(sign(t, paidPayload(), newKey(t)), pub, "")
	if _, err := Open(sealed, priv); err != nil {
		t.Fatalf("a key that round-tripped through PEM must still work: %v", err)
	}
	if _, err := ParseRecipientPrivateKeyPEM("not a pem"); err == nil {
		t.Fatalf("garbage must be an error rather than a nil key that fails later")
	}
}

// An import path has to take both: a deployment not yet issued a recipient key still receives plain envelopes,
// and making an operator choose the right menu item would be a way to fail for no reason.
func TestSealedAndPlainFilesAreDistinguishable(t *testing.T) {
	plain, _ := json.Marshal(sign(t, paidPayload(), newKey(t)))
	sealed, _ := Seal(sign(t, paidPayload(), newKey(t)), newRecipient(t).PublicKey(), "")
	sealedRaw, _ := json.Marshal(sealed)

	if LooksSealed(plain) {
		t.Fatalf("a plain envelope must not be mistaken for a sealed one")
	}
	if !LooksSealed(sealedRaw) {
		t.Fatalf("a sealed file must be recognised")
	}
	if LooksSealed([]byte("not json")) {
		t.Fatalf("garbage is not sealed")
	}
}

func TestSealingRequiresARecipientAndOpeningRequiresAKey(t *testing.T) {
	if _, err := Seal(sign(t, paidPayload(), newKey(t)), nil, ""); err == nil {
		t.Fatalf("sealing to nobody must be an error")
	}
	sealed, _ := Seal(sign(t, paidPayload(), newKey(t)), newRecipient(t).PublicKey(), "")
	if _, err := Open(sealed, nil); err == nil {
		t.Fatalf("opening with no key must be an error, not an empty envelope")
	}
}
