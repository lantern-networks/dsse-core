package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/installprofile"
)

func testCA(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func profileWithDeployment(t *testing.T) installprofile.InstallProfile {
	t.Helper()
	return installprofile.InstallProfile{
		TenantID:     "tenant_sakura",
		TransportURL: "https://agents.osaka.hikari.lab",
		Deployment: installprofile.DeploymentSpec{
			AnchorPEM:                   testCA(t, "Hikari Networks Root CA"),
			TransportAnchorsPEM:         []string{testCA(t, "sakura.hikari.lab Transport CA")},
			DeviceCAPinSHA256:           "4c129d794c13f8598b684070b97aeeaacf2002a909e8065d616698fddff184b6",
			InterceptionRootPEM:         testCA(t, "Sakura Foods Interception Root"),
			AgentPolicySigningPublicKey: "0ae740bd219e4bc112ac84f6153972406a5415999f1eec6e8fa9cacf1a518220",
			UpdateSigningKeys:           []string{"f95090bb69020b27192a046e5c31918ac05c573f481c9c13c3c4a4c50cb9a0cf"},
			UpdatePublisherTeamID:       "M4U8GSBL6C",
		},
	}
}

// ★★★ THE WHOLE POINT: a profile and a token are enough. Everything else a Windows device needed — the anchor,
// the organization's interception root, the device-CA pin, the update pins, and the enrolment seed nothing in
// the product produced — comes out of the two artefacts the Console hands over.
func TestAProfileAndATokenAreEnoughToProvisionADevice(t *testing.T) {
	plan, err := planProvision(profileWithDeployment(t), "one-time-secret")
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if len(plan.AnchorsPEM) == 0 {
		t.Fatal("no transport anchors — the device would have nothing to verify its Edge with")
	}
	if len(plan.InterceptionRootPEM) == 0 {
		t.Fatal("no interception root — every intercepted site would fail with an unknown issuer")
	}
	if plan.AgentPolicyPin == "" || len(plan.UpdateSigningKeys) != 1 || plan.UpdatePublisherID == "" {
		t.Fatalf("pins did not come across: %+v", plan)
	}
	if plan.Seed == nil {
		t.Fatal("no enrolment seed — this is the file nothing in the product wrote, which is why every Windows install needed a shell")
	}
	if plan.Seed.EnrolURL != "https://agents.osaka.hikari.lab/enroll" {
		t.Fatalf("enrol url = %q", plan.Seed.EnrolURL)
	}
	if plan.Seed.Tenant != "tenant_sakura" || plan.Seed.Token != "one-time-secret" {
		t.Fatalf("seed = %+v", plan.Seed)
	}
	if plan.Seed.DeviceCAPinSHA256 == "" || plan.Seed.EnrolCAPEM == "" {
		t.Fatal("the bootstrap channel is unpinned — the agent refuses to enrol over one, so this would fail on the device")
	}
	// The machine's own name is not invented here.
	if plan.Seed.DeviceID != "" {
		t.Fatalf("device_id = %q — a machine already has a name; the installer must not be a second place that decides it", plan.Seed.DeviceID)
	}
}

// A profile issued before the deployment block existed cannot provision a generic package, and saying so names
// the two ways forward. The failure that is NOT acceptable is a clean install that fails later as a TLS error.
func TestAProfileWithoutADeploymentBlockIsRefusedWithBothWaysForward(t *testing.T) {
	_, err := planProvision(installprofile.InstallProfile{
		TenantID: "tenant_sakura", TransportURL: "https://agents.osaka.hikari.lab"}, "tok")
	if err == nil {
		t.Fatal("a profile carrying no deployment facts was accepted as enough to provision a device")
	}
	for _, want := range []string{"deployment block", "Download a new one", "build-msi.ps1"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

// No token is a supported state (MDM, or a device that already holds an identity) and must not be an error —
// but it must be SAID, because a device that silently never enrols is the failure this product keeps finding.
func TestNoTokenProvisionsTrustButSaysThisDeviceWillNotEnrol(t *testing.T) {
	plan, err := planProvision(profileWithDeployment(t), "  ")
	if err != nil {
		t.Fatalf("a tokenless provision must not be an error: %v", err)
	}
	if plan.Seed != nil {
		t.Fatal("a seed was written with no token in it")
	}
	if len(plan.AnchorsPEM) == 0 {
		t.Fatal("trust material must still be provisioned without a token")
	}
	if !strings.Contains(strings.Join(plan.Notes, "|"), "will not enrol itself") {
		t.Fatalf("nothing said this device will not enrol: %v", plan.Notes)
	}
}

// An unpinned bootstrap is refused at install. The agent would refuse it anyway, on a machine nobody is
// watching, with a message about a channel rather than about the profile that authored it.
func TestAnUnpinnedBootstrapIsRefusedAtInstall(t *testing.T) {
	p := profileWithDeployment(t)
	p.Deployment.AnchorPEM = ""
	p.Deployment.TransportAnchorsPEM = nil
	p.Deployment.DeviceCAPinSHA256 = ""
	if _, err := planProvision(p, "tok"); err == nil {
		t.Fatal("a profile pinning neither the enrol CA nor the device CA was accepted")
	}
}

func TestTheTokenFileIsReadAndItsOrdinaryMistakesAreNamed(t *testing.T) {
	dir := t.TempDir()
	ok := filepath.Join(dir, "t.txt")
	if err := os.WriteFile(ok, []byte("  secret-value\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readTokenFile(ok); err != nil || got != "secret-value" {
		t.Fatalf("got %q, %v — a trailing newline from a text editor must not become part of the token", got, err)
	}
	empty := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(empty, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTokenFile(empty); err == nil || !strings.Contains(err.Error(), "shown once") {
		t.Fatalf("an empty token file was accepted or the message did not say why it matters: %v", err)
	}
	two := filepath.Join(dir, "two.txt")
	if err := os.WriteFile(two, []byte("a b"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readTokenFile(two); err == nil {
		t.Fatal("a file holding two values was accepted as one token")
	}
	if got, err := readTokenFile(""); err != nil || got != "" {
		t.Fatalf("no token path must be the ordinary no-token case, got %q %v", got, err)
	}
}

// ★ A DEVICE THAT ALREADY ENROLLED MUST NOT BE GIVEN A SECOND IDENTITY. A re-install that drops a fresh token
// beside an existing key either spends an approval for nothing or starts a second identity for one machine.
func TestReProvisioningAnEnrolledDeviceSpendsNothing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "device.crt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	note, err := writeSeed(dir, &enrolmentSeed{EnrolURL: "https://e/enroll", Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, "NOT written") || !strings.Contains(note, "no approval was spent") {
		t.Fatalf("note = %q", note)
	}
	if _, err := os.Stat(filepath.Join(dir, "enrolment.json")); !os.IsNotExist(err) {
		t.Fatal("a seed was written beside an existing identity")
	}
}

// And a seed already in flight is left alone, or a re-run of the installer replaces a token the device may be
// in the middle of spending.
func TestAnExistingSeedIsNotReplaced(t *testing.T) {
	dir := t.TempDir()
	first := &enrolmentSeed{EnrolURL: "https://e/enroll", Token: "first"}
	if _, err := writeSeed(dir, first); err != nil {
		t.Fatal(err)
	}
	if _, err := writeSeed(dir, &enrolmentSeed{EnrolURL: "https://e/enroll", Token: "second"}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "enrolment.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got enrolmentSeed
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Token != "first" {
		t.Fatalf("token = %q — a re-run replaced a token that may already be in flight", got.Token)
	}
}

// The field names are the AGENT's. A second spelling here is a second thing to keep true, and the agent would
// read a file it did not understand as "no token" and stand aside for ever.
func TestTheSeedUsesTheFieldNamesTheAgentReads(t *testing.T) {
	raw, err := json.Marshal(enrolmentSeed{
		EnrolURL: "u", Token: "t", Tenant: "x", EnrolCAPEM: "p", DeviceCAPinSHA256: "d"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"enrol_url", "enrolment_token", "tenant", "enrol_ca_pem", "device_ca_pin_sha256"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("the seed has no %q field — the agent's enrolmentConfig reads that name", k)
		}
	}
}

// ★★★ A DEVICE MOVED TO ANOTHER DEPLOYMENT HOLDS AN IDENTITY, AND IT IS THE WRONG ONE (2026-08-30).
//
// Declining to write a seed beside an existing identity stops a re-install spending an approval for a machine
// that needs none. A device moved to a DIFFERENT deployment also holds one — issued by the old organization's
// device CA, which the new Edge has no reason to accept. Suppressing the seed there leaves a live approval
// unused beside a credential nobody will take, and the device stands aside for ever.
func TestAnIdentityFromAnotherOrganizationDoesNotSuppressTheSeed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "device.crt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "enrolled.json"),
		[]byte(`{"device_id":"m","tenant":"tenant_yesterday"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	note, err := writeSeedForOrganization(dir, &enrolmentSeed{EnrolURL: "https://e/enroll", Token: "tok"}, "tenant_today")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, "enrolment seed written") {
		t.Fatalf("the seed was suppressed by a credential this deployment cannot use: %q", note)
	}
	if _, err := os.Stat(filepath.Join(dir, "enrolment.json")); err != nil {
		t.Fatalf("no seed on disk: %v", err)
	}
}

// The original protection still holds for the case it was written for: a re-install into the SAME organization
// must not spend an approval.
func TestAReinstallIntoTheSameOrganizationStillSpendsNothing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "device.crt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "enrolled.json"),
		[]byte(`{"device_id":"m","tenant":"tenant_same"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	note, err := writeSeedForOrganization(dir, &enrolmentSeed{EnrolURL: "https://e/enroll", Token: "tok"}, "tenant_same")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(note, "no approval was spent") {
		t.Fatalf("note = %q", note)
	}
}

// Proof, never absence. An identity with no recorded organization, or a profile that names none, is left alone
// — refusing on "cannot tell" would disenrol working devices to catch a case that has not happened to them.
func TestAnIdentityThatNamesNoOrganizationIsLeftAlone(t *testing.T) {
	for _, tc := range []struct{ held, profile string }{{"", "tenant_today"}, {"tenant_yesterday", ""}, {"", ""}} {
		if identityIsForAnotherOrganization(tc.held, tc.profile) {
			t.Fatalf("held=%q profile=%q was judged foreign on missing information", tc.held, tc.profile)
		}
	}
	if !identityIsForAnotherOrganization("tenant_a", "tenant_b") {
		t.Fatal("two different organizations were not distinguished")
	}
	if identityIsForAnotherOrganization("TENANT_A", "tenant_a") {
		t.Fatal("case decided the answer")
	}
}

// ★ A seed addressed to another organization is not "a token in flight" (2026-08-30, measured moving this
// box between two labs). The guard that protects an unspent approval was protecting a seed that named a
// DELETED deployment, and it silently undid the line above it that had just decided to write a new one.
func TestASeedForAnotherOrganizationIsReplaced(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A device already enrolled elsewhere, with that deployment's seed still beside it.
	if err := os.WriteFile(filepath.Join(dir, "device.crt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "enrolled.json"), []byte(`{"tenant":"tenant_old"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "enrolment.json"), []byte(`{"tenant":"tenant_old","enrol_url":"https://gone.example/enroll"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	seed := &enrolmentSeed{EnrolURL: "https://new.example/enroll", Token: "t", Tenant: "tenant_new"}
	if _, err := writeSeedForOrganization(dir, seed, "tenant_new"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "enrolment.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "tenant_new") {
		t.Fatalf("the stale seed survived: %s", raw)
	}
}

// And a seed for THIS organization is still left alone — that is the case the guard exists for.
func TestASeedForThisOrganizationIsLeftAlone(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "enrolment.json"), []byte(`{"tenant":"tenant_new","enrolment_token":"inflight"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	seed := &enrolmentSeed{EnrolURL: "https://new.example/enroll", Token: "replacement", Tenant: "tenant_new"}
	if _, err := writeSeedForOrganization(dir, seed, "tenant_new"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "enrolment.json"))
	if !strings.Contains(string(raw), "inflight") {
		t.Fatalf("an approval already in flight was overwritten: %s", raw)
	}
}
