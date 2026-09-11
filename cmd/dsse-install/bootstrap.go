package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// bootstrap.go — creating the deployment's first administrator, and closing the circle that let it be created.
//
// ★★★ THE CIRCLE (2026-08-23, walked). A control plane authenticates named principals and API tokens. A
// deployment that has just been created has neither — so nothing can authenticate: not an administrator
// creating the first account, and not an Edge pulling its configuration. The break-glass credential exists to
// break that, and it authorises as OWNER while attributing every act to a synthetic principal.
//
// So the generated start script arms it. That opens the circle. Leaving it there is the part that was wrong:
// every deployment would ship with an owner-level credential live, and whether it stayed that way depended on
// somebody reading a paragraph.
//
// ★ CLOSING IT IS A RESTART, NOT AN API CALL. Arming is a startup flag and there is no route that disarms a
// running process — deliberately, since a credential that can be turned on and off over the network is not the
// last resort it is meant to be. So the sequence is: start armed, create the named administrator, restart
// without the flag. Walked end to end: after the restart with no arming, the named account authenticates
// (200 and a TOTP challenge) and the deployment is administrable by a person rather than by a synthetic owner.
//
// ★★ AND THE SCRIPT DECIDES, NOT THE OPERATOR'S MEMORY. Once this has run it writes a marker beside the keys,
// and the start script arms only while that marker is absent. The closing then happens on the next restart
// whether or not anybody remembered — which is the difference between a procedure and a note.

// adminBootstrappedMarker records that this deployment has a named administrator. Its presence is what stops
// the start script arming the break-glass credential again.
const adminBootstrappedMarker = "admin-bootstrapped"

type bootstrapResult struct {
	Email         string   `json:"email"`
	TOTPSecret    string   `json:"totp_secret"`
	RecoveryCodes []string `json:"recovery_codes"`
	// OperatorToken is the named API credential that replaces the break-glass one for everything asked over
	// the API. Shown once, like the rest; never written to deployment.env, because it is a credential and
	// deployment.env is configuration a deployment reads at every start.
	OperatorToken string `json:"-"`
}

// bootstrapFirstAdministrator invites, activates and proves the deployment's first named administrator.
//
// It does the whole sequence rather than the first step, because a half-activated invitation is an account
// nobody can use and an invitation somebody has to find again. Either this deployment has an administrator
// when it returns, or it has none and says why.
func bootstrapFirstAdministrator(dir, cpAdmin, email, password string) (*bootstrapResult, error) {
	client, err := deploymentClient(dir)
	if err != nil {
		return nil, err
	}
	env, err := readEnvFile(filepath.Join(dir, "deployment.env"))
	if err != nil {
		return nil, fmt.Errorf("read deployment.env: %w", err)
	}
	token := strings.TrimSpace(env["ADMIN_TOKEN"])
	if token == "" {
		return nil, fmt.Errorf("deployment.env carries no ADMIN_TOKEN, so the break-glass credential cannot be used")
	}
	cpAdmin = strings.TrimRight(cpAdmin, "/")

	// 1. Invite. This is the call that needs the break-glass credential armed.
	body, _ := json.Marshal(map[string]any{"email": email, "roles": []string{"admin", "super_admin"}})
	code, raw, err := post(client, cpAdmin+"/admin/admins/invite", token, body)
	if err != nil {
		return nil, fmt.Errorf("invite %s: %w", email, err)
	}
	code, raw, err = waitForALeaderToExist(code, raw, func() (int, []byte, error) {
		return post(client, cpAdmin+"/admin/admins/invite", token, body)
	})
	if err != nil {
		return nil, fmt.Errorf("invite %s: %w", email, err)
	}
	if code == 409 {
		return nil, fmt.Errorf("invite %s -> 409 after waiting %s: no control plane took leadership. The "+
			"database elects it, so this is the database not coming up rather than anything about the "+
			"administrator: %s", email, adminLeadershipWait, first(raw, 200))
	}
	if code == 401 {
		return nil, fmt.Errorf("the control plane refused the break-glass credential (401). It is armed only "+
			"while %s is absent — if this deployment already has an administrator, sign in as them instead",
			runtimePath(dir, adminBootstrappedMarker))
	}
	if code == 503 {
		return nil, fmt.Errorf("the control plane answered 503: first-party admin accounts are not enabled. " +
			"The generated start script passes -first-party-accounts; a control plane started another way needs it")
	}
	if code != 201 && code != 200 {
		return nil, fmt.Errorf("invite %s -> %d: %s", email, code, first(raw, 200))
	}
	var invited struct {
		ActivationLink string `json:"activation_link"`
	}
	if json.Unmarshal(raw, &invited) != nil {
		return nil, fmt.Errorf("the control plane returned an invitation this installer cannot read")
	}
	activation := activationTokenFrom(invited.ActivationLink)
	if activation == "" {
		return nil, fmt.Errorf("the invitation carried no activation token")
	}

	// 2. Set the password. From here the invitation is what authenticates, not the break-glass credential.
	if code, raw, err = postJSON(client, cpAdmin+"/admin/activate/password",
		map[string]any{"token": activation, "new_password": password}); err != nil || code != 200 {
		return nil, fmt.Errorf("set the first administrator's password -> %d %v: %s", code, err, first(raw, 200))
	}

	// 3. Second factor. Not optional: an administrator of this deployment holds owner-level authority, and the
	// account that replaces a break-glass credential should not be weaker than the thing it replaces.
	code, raw, err = postJSON(client, cpAdmin+"/admin/activate/totp/begin", map[string]any{"token": activation})
	if err != nil || code != 200 {
		return nil, fmt.Errorf("begin the second factor -> %d %v: %s", code, err, first(raw, 200))
	}
	secret := totpSecretFrom(raw)
	if secret == "" {
		return nil, fmt.Errorf("the control plane returned no second-factor secret")
	}
	otp, err := totpNow(secret)
	if err != nil {
		return nil, fmt.Errorf("compute the second-factor code: %w", err)
	}
	code, raw, err = postJSON(client, cpAdmin+"/admin/activate/totp/complete",
		map[string]any{"token": activation, "code": otp})
	if err != nil || code != 200 {
		return nil, fmt.Errorf("complete the second factor -> %d %v: %s", code, err, first(raw, 200))
	}
	var completed struct {
		RecoveryCodes []string `json:"recovery_codes"`
	}
	_ = json.Unmarshal(raw, &completed)

	// 4. SIGN IN AS THEM. This both proves the account works — one that was created and cannot sign in is the
	// same as no account, and this is the last moment anybody is looking — and gives the credentials below a
	// principal that is a person. See bootstrap_session.go: minted with the break-glass bearer instead, every
	// act performed with them for the life of the deployment is filed under the synthetic owner this whole
	// procedure exists to retire.
	session, serr := signInAsAdministrator(client, cpAdmin, email, password, secret)
	if serr != nil {
		return nil, serr
	}

	// ★★★ 4b. AND A CREDENTIAL FOR THE EDGES, OR CLOSING THE CIRCLE TAKES THE FLEET WITH IT (2026-08-23,
	// found by closing it and watching -verify).
	//
	// An Edge pulls its configuration over the same admin surface, and it was authenticating with the
	// break-glass credential — the one that is supposed to stop working. So the moment the deployment became
	// correct, every Edge stopped receiving configuration: still healthy, still enforcing what it booted with,
	// and nothing said so. The check caught it; a deployment handed over without the check would not have.
	//
	// So the bootstrap mints a NAMED token for the fleet, with the read scope a config pull needs and nothing
	// else. It is written into deployment.env under the name the start script already reads, so an Edge picks
	// it up on its next start with nothing to transcribe.
	edgeToken, err := mintFleetToken(client, cpAdmin, session)
	if err != nil {
		return nil, fmt.Errorf("the administrator exists but the fleet has no credential of its own (%w) — "+
			"closing the break-glass credential would stop every Edge receiving configuration", err)
	}
	if err := replaceEnvValue(filepath.Join(dir, "deployment.env"), "EDGE_CP_TOKEN", edgeToken); err != nil {
		return nil, fmt.Errorf("the fleet token was minted but could not be written to deployment.env: %w", err)
	}

	// 4b. AND A NAMED CREDENTIAL FOR THE PERSON WHO OPERATES THIS DEPLOYMENT.
	//
	// ★★★ CLOSING THE BREAK-GLASS CREDENTIAL LEFT THE OPERATOR WITH NO API CREDENTIAL AT ALL (2026-08-25,
	// measured). The first administrator gets a password and a second factor, which are a CONSOLE sign-in.
	// Every question asked over the API — including the two this installer asks itself, -verify and
	// -who-depends — takes a bearer token, and -verify's own help says it needs "a named API token ... after
	// -bootstrap-admin has run". Nothing minted one. So the deployment closed correctly and became
	// unaskable: the only token left was the fleet's, which is scoped to reading policy and nothing else.
	//
	// ★ NAMED, NOT ANOTHER BREAK-GLASS. What was retired is the credential attributed to NOBODY: this one is
	// an api token with a name, its acts are filed under it, and it can be revoked from the Console without
	// touching the deployment. It carries the administrator roles because the questions it exists to ask are
	// the deployment-wide ones.
	operatorToken, oerr := mintOperatorToken(client, cpAdmin, session)
	if oerr != nil {
		return nil, fmt.Errorf("the administrator exists but this deployment has no named API credential "+
			"(%w) — once the break-glass credential is closed, nothing could ask it a deployment-wide "+
			"question", oerr)
	}
	// 5. Close the circle. The marker is what stops the start script arming the break-glass credential again,
	// so the closing happens on the next restart whether or not anybody remembered.
	marker := fmt.Sprintf("%s created the first administrator (%s) at %s.\n"+
		"While this file exists, start-control-plane.sh does NOT arm the break-glass credential.\n"+
		"Restart the control plane to take it out of effect.\n", "dsse-install", email,
		time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(runtimePath(dir, adminBootstrappedMarker), []byte(marker), 0o600); err != nil {
		return nil, fmt.Errorf("the administrator exists but the marker could not be written (%w) — the "+
			"break-glass credential would be armed again on the next restart", err)
	}
	return &bootstrapResult{Email: email, TOTPSecret: secret, RecoveryCodes: completed.RecoveryCodes,
		OperatorToken: operatorToken}, nil
}

// postJSON is post() with the body marshalled and no bearer: from the password step onward the INVITATION is
// what authenticates, not the break-glass credential.
func postJSON(client *http.Client, url string, body map[string]any) (int, []byte, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	return post(client, url, "", raw)
}

func activationTokenFrom(link string) string {
	if u, err := url.Parse(strings.TrimSpace(link)); err == nil {
		if v := u.Query().Get("activate"); v != "" {
			return v
		}
	}
	m := regexp.MustCompile(`activate=([A-Za-z0-9_-]+)`).FindStringSubmatch(link)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

// totpSecretFrom reads the shared secret out of whichever shape the control plane answered with — a bare
// secret, or the otpauth URI an authenticator app scans.
func totpSecretFrom(raw []byte) string {
	var body struct {
		Secret     string `json:"secret"`
		OTPAuthURI string `json:"otpauth_uri"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	if s := strings.TrimSpace(body.Secret); s != "" {
		return s
	}
	if u, err := url.Parse(body.OTPAuthURI); err == nil {
		return u.Query().Get("secret")
	}
	return ""
}

// totpNow computes the current code. Written out rather than pulled in, because a dependency for thirty lines
// of RFC 6238 is a dependency in the supply chain of an installer that mints a deployment's keys.
func totpNow(secret string) (string, error) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	if pad := len(secret) % 8; pad != 0 {
		secret += strings.Repeat("=", 8-pad)
	}
	key, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}
	counter := make([]byte, 8)
	binary.BigEndian.PutUint64(counter, uint64(time.Now().Unix()/30))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter)
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000), nil
}

// runBootstrapAdmin drives the bootstrap and reports what an operator has to keep.
func runBootstrapAdmin(dir, cpAdmin, email, password string) error {
	dir, cpAdmin, email = strings.TrimSpace(dir), strings.TrimSpace(cpAdmin), strings.TrimSpace(email)
	if dir == "" || cpAdmin == "" || email == "" {
		return fmt.Errorf("-dir, -control-plane and -admin-email are all required")
	}
	// ★★★ NAME@ADDRESS HERE TOO, BECAUSE THIS IS THE STEP THAT COMES FIRST. The planes are separated by NAME,
	// so this dials a name — and on a deployment whose names DNS does not answer yet, which is every
	// one-machine deployment somebody is trying, the only way to reach it is to say where the name lives.
	// -verify has understood NAME@ADDRESS since it was written; this did not, so the printed order asked for
	// a name that does not resolve and, given the address the very next step uses, sent it as USERINFO:
	//
	//	Post "https://admin.tokyo.example.lab@127.0.0.1/admin/admins/invite": EOF
	//
	// which is a URL that parses, dials the wrong host and says nothing about why. The resolution belongs to
	// the client both commands share, so recording it here is all that was missing.
	cpAdmin = resolveDoorArguments(cpAdmin)
	if _, err := os.Stat(runtimePath(dir, adminBootstrappedMarker)); err == nil {
		return fmt.Errorf("this deployment already has an administrator (%s exists). The break-glass "+
			"credential is no longer armed, so sign in as them instead",
			runtimePath(dir, adminBootstrappedMarker))
	}
	// ★★★ SAID BEFORE ANYTHING IS MINTED, NOT AFTER (2026-08-26, learned by losing them). This command prints
	// a password, a second factor, recovery codes and an API token exactly once and stores none of them —
	// deliberately, because that is what makes them credentials rather than configuration.
	//
	// It is printed FIRST because a warning after the secrets is a warning the reader sees too late.
	//
	// ★★★ AND IT USED TO SAY "THERE IS NO SECOND WAY IN", WHICH IS NOT TRUE (2026-08-27, corrected by using
	// the way in). The break-glass credential is closed by a FILE — runtime/admin-bootstrapped, on the
	// control-plane machine, beside a deployment.env that still holds ADMIN_TOKEN. Whoever can write that
	// directory can move the file, restart the control plane, and be the owner again.
	//
	// Both halves matter. An operator sized their backup discipline against "unrecoverable" and it was not;
	// and a property this large — write access to one directory is owner-level access to the deployment —
	// was hidden behind a sentence claiming the opposite. It is stated here and in the threat model, and the
	// recovery is described so that whoever needs it does not invent a worse one.
	fmt.Printf("★ CAPTURE THIS OUTPUT. What follows is shown ONCE and is stored nowhere — not by this\n")
	fmt.Printf("  installer, not in the deployment directory. If you are not capturing, stop now and run it\n")
	fmt.Printf("  again as:  dsse-install -bootstrap-admin … 2>&1 | tee credentials.txt\n\n")
	fmt.Printf("  ★★ IF YOU LOSE THEM, the way back is on the control plane's machine and it is not a nice\n")
	fmt.Printf("  one: move %s aside, restart the control plane, and the\n", runtimePath("<dir>", adminBootstrappedMarker))
	fmt.Printf("  break-glass credential in deployment.env is armed again — owner-level, with every act\n")
	fmt.Printf("  attributed to nobody. Mint a named token, put the marker back and restart.\n")
	fmt.Printf("  ★★★ WHICH IS ALSO A PROPERTY OF THIS DEPLOYMENT, whether or not you ever use it: anyone who\n")
	fmt.Printf("  can WRITE that directory can do the same. Protect it as you would the credentials below.\n\n")

	generated := false
	if strings.TrimSpace(password) == "" {
		password, generated = randomSecret(), true
	}

	result, err := bootstrapFirstAdministrator(dir, cpAdmin, email, password)
	if err != nil {
		return err
	}

	fmt.Printf("dsse-install: %s is this deployment's first administrator.\n\n", result.Email)
	if generated {
		fmt.Printf("  password        %s\n", password)
	}
	fmt.Printf("  second factor   %s\n", result.TOTPSecret)
	if len(result.RecoveryCodes) > 0 {
		fmt.Printf("  recovery codes  %s\n", strings.Join(result.RecoveryCodes, " "))
	}
	if strings.TrimSpace(result.OperatorToken) != "" {
		fmt.Printf("  api token       %s\n", result.OperatorToken)
		fmt.Printf("                  (named \"deployment-operator\" — this is what -verify -admin-token and\n")
		fmt.Printf("                   -who-depends take, once the break-glass credential is closed)\n")
	}
	reportConsoleFirstVisit(dir, consoleURLForFirstVisit(dir))
	fmt.Printf("\n  ★ THIS IS THE ONLY TIME THESE ARE SHOWN. They are not stored anywhere this installer can\n")
	fmt.Printf("  read them back, which is what makes them credentials rather than configuration.\n")
	fmt.Printf("\n  ★★★ AND CARRY TWO THINGS TO EVERY OTHER REGION'S DIRECTORY (2026-08-25, measured on a\n")
	fmt.Printf("  two-region deployment). What just happened is a fact about the DEPLOYMENT — the break-glass\n")
	fmt.Printf("  credential stops working and the fleet gets its own — but it was recorded in ONE directory.\n")
	fmt.Printf("  Every other region keeps presenting the credential that just stopped working, is answered 401\n")
	fmt.Printf("  on every pull and every report, and goes on serving what it booted with. Its Edges do not\n")
	fmt.Printf("  appear in the fleet view at all, which is what the view also shows for a machine that is\n")
	fmt.Printf("  switched off.\n\n")
	fmt.Printf("      %s          the marker: it is what makes an Edge use the fleet credential\n", adminBootstrappedMarker)
	fmt.Printf("      EDGE_CP_TOKEN in deployment.env   the fleet credential itself\n\n")
	fmt.Printf("  ★★★ AND TO THE DIRECTORY YOU CARRY FROM, which is the one nobody thinks of (2026-08-27,\n")
	fmt.Printf("  measured by installing a second region afterwards). This ran against ONE machine's copy. The\n")
	fmt.Printf("  minting directory — where -carry packs every machine you will ever add — still holds the\n")
	fmt.Printf("  credential that just stopped working and no marker, so every machine created from now on is\n")
	fmt.Printf("  born answering 401 to its own control plane, on a deployment that is otherwise correct. It\n")
	fmt.Printf("  reads as a broken new region and it is a stale source.\n\n")
	fmt.Printf("  Then restart that region's Edges. dsse-install -verify against that region says whether it\n")
	fmt.Printf("  worked: \"the Edge has applied the control plane's configuration\" is exactly this question.\n")
	fmt.Printf("\n  ★★ RESTART THE CONTROL PLANE. %s now exists, so start-control-plane.sh will not arm the\n",
		adminBootstrappedMarker)
	fmt.Printf("  break-glass credential again — but the process running NOW still has it armed, and it\n")
	fmt.Printf("  authorises as owner while attributing every act to nobody. The restart is what closes that.\n")
	return nil
}

// mintFleetToken creates the named API token the Edges authenticate everything they ask the control plane with.
//
// ★★★ "EVERY ACT AN EDGE PERFORMS IS A READ" WAS WRONG, AND IT CLOSED THE DEPLOYMENT'S FRONT DOOR
// (2026-08-25, measured on the deployment this installer produced, minutes after it was correctly closed).
//
// This token used to carry admin.policy.read and admin.state.read on exactly that reasoning. What actually
// happened the moment the break-glass credential stopped working:
//
//	revocation sync: pull failed: 403 {"error":"admin api token scope admin.endpoints.read is required"}
//	  — every two seconds, for ever. A blocked device would never have been refused anywhere.
//	enroll_refused: the identity-claim authority refused: HTTP 403
//	  — NO DEVICE COULD ENROL AT ALL, in a deployment where every other check passed.
//
// An Edge does not only receive. It takes a one-time identity claim so two Edges cannot admit the same device
// twice, it reports the revocations it applied, it reports the exclusions it observed, and it tells the
// authority about an enrolment and a connector that joined. Those are writes, and they are the writes that
// make the authority the authority — refusing them does not make the deployment safer, it makes the Edge the
// only place that knows.
//
// ★ WHAT IS STILL WITHHELD IS THE ONE THAT MATTERED. admin.policy.write is NOT here, so a compromised Edge
// still cannot author the configuration it is supposed to receive — which is the distinction the original
// comment was reaching for. Neither is admin.tenant.*, admin.certs.*, or anything about accounts.
//
// ★ THE LIST IS ENUMERATED, NOT WIDENED TO A ROLE. Every entry below is a route this Edge actually calls, and
// the next Edge-to-control-plane call that is added has to be added here too — where a 403 in a sync loop is
// the symptom, that is a feature: the failure is loud, in one place, and about a name.
func mintFleetToken(client *http.Client, cpAdmin string, session adminSession) (string, error) {
	// ★ admin.state.read IS WHAT LETS A TOKEN BE INTROSPECTED (2026-08-23, measured). An Edge resolves a
	// credential it does not hold by asking the control plane's /admin/session — and that endpoint requires
	// this scope of the credential being presented. Without it the Edge answers 401 to a token the control
	// plane would have recognised, and the refusal reads as "wrong credential" rather than "this token cannot
	// be looked up".
	body, _ := json.Marshal(map[string]any{
		"name":  "fleet-config-pull",
		"roles": []string{"admin"},
		"scopes": []string{
			// Configuration: pull the bundle, report what was applied.
			"admin.policy.read",
			// Resolve the credential it presents — without this the Edge is answered 401 for a token the
			// control plane would have recognised, and the refusal reads as "wrong credential".
			"admin.state.read",
			// Revocations: pull what is revoked, report what was applied. Without the read, a blocked device
			// is refused nowhere.
			"admin.endpoints.read", "admin.endpoints.write",
			// Steer exclusions: the admin-managed set, and what this node observed devices actually holding.
			"admin.steering.read", "admin.steering.write",
			// Enrolment: take and release the one-time identity claim, and tell the authority who enrolled.
			// Without the write, no device can enrol through any Edge.
			"admin.enrollment.read", "admin.enrollment.write",
			// Connectors: a connector reaches only an Edge, so what it delivers has to be carried here.
			"admin.connectors.read", "admin.connectors.write",
			// ★★★ RELEASES: WITHOUT THIS AN EDGE CAN NEVER OFFER ONE (2026-08-28, measured by publishing a real
			// notarised package and asking a device for it). An Edge pulls the published set from the control
			// plane and is answered
			//
			//	admin api token scope admin.agents.read is required
			//
			// so it holds nothing, and every device is told "no agent updates are published by this edge" —
			// which is also what a deployment that has published nothing says. The two are indistinguishable
			// from the device, and neither the Edge nor the screen said a scope was missing.
			"admin.agents.read",
		},
	})
	code, raw, err := postAsAdministrator(client, strings.TrimRight(cpAdmin, "/")+"/admin/api-tokens", session, body)
	if err != nil {
		return "", err
	}
	if code != 200 && code != 201 {
		return "", fmt.Errorf("POST /admin/api-tokens -> %d: %s", code, first(raw, 200))
	}
	// ★ raw_token IS THE ONE THAT MATTERS, and "token" beside it is the RECORD — id, name, roles, when it was
	// created. Reading the wrong one gets a JSON object where a credential should be, which is how this failed
	// the first time it ran. The secret is returned exactly once, which is also why it is written straight into
	// deployment.env rather than reported and expected to be copied.
	var minted struct {
		RawToken string `json:"raw_token"`
		Secret   string `json:"secret"`
	}
	if json.Unmarshal(raw, &minted) != nil {
		return "", fmt.Errorf("the control plane returned a token this installer cannot read")
	}
	for _, candidate := range []string{minted.RawToken, minted.Secret} {
		if strings.TrimSpace(candidate) != "" {
			return strings.TrimSpace(candidate), nil
		}
	}
	return "", fmt.Errorf("the control plane returned a token record but no token value")
}

// replaceEnvValue rewrites one name in deployment.env, keeping everything else — including the comments, which
// are the only place the file explains what it is.
func replaceEnvValue(path, name, value string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(raw), "\n")
	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), name+"=") {
			lines[i], replaced = name+"="+value, true
			break
		}
	}
	if !replaced {
		lines = append(lines, name+"="+value)
	}
	return os.WriteFile(path, []byte(withTrailingNewline(strings.Join(lines, "\n"))), 0o600)
}

// mintOperatorToken creates the named API credential the deployment's operator asks questions with.
//
// ★ THE ROLES, NOT A SCOPE LIST. The fleet token beside it is deliberately scoped to two reads, because an
// Edge only ever reads. This one replaces a person's reach, and the questions it exists for — is this
// deployment one deployment, who trusts it, is anything about to be stranded — are answered only to a caller
// the control plane recognises as operating the whole deployment. Narrowing it to a scope list produced a
// token that authenticated and was then answered with the customer projection, which reads as "everything is
// fine" for every question about nodes.
func mintOperatorToken(client *http.Client, cpAdmin string, session adminSession) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"name":  "deployment-operator",
		"roles": []string{"admin", "super_admin"},
	})
	code, raw, err := postAsAdministrator(client, strings.TrimRight(cpAdmin, "/")+"/admin/api-tokens", session, body)
	if err != nil {
		return "", err
	}
	if code != 200 && code != 201 {
		return "", fmt.Errorf("POST /admin/api-tokens -> %d: %s", code, first(raw, 200))
	}
	var minted struct {
		RawToken string `json:"raw_token"`
		Secret   string `json:"secret"`
	}
	if json.Unmarshal(raw, &minted) != nil {
		return "", fmt.Errorf("the control plane returned a token this installer cannot read")
	}
	for _, candidate := range []string{minted.RawToken, minted.Secret} {
		if strings.TrimSpace(candidate) != "" {
			return strings.TrimSpace(candidate), nil
		}
	}
	return "", fmt.Errorf("the control plane returned a token record but no token value")
}

// waitForALeaderToExist retries an administrative write while the control plane answers 409.
//
// ★★★ A STEP MAY NOT REQUIRE ITS READER TO ALREADY KNOW TO WAIT (2026-09-01, measured while walking the
// printed order end to end). -bootstrap-admin's stated precondition is "the control plane answering", and it
// was answering — with "this control plane does not hold leadership, and an administrative change written
// here would be accepted and then discarded". Fifty-six seconds after the previous step, the database had
// come up and Patroni had not finished electing.
//
// ★ THE REFUSAL IS CORRECT AND THE PROCEDURE WAS WRONG. An operator following the order as printed hits it,
// and the only way past was knowing to wait — which is not something a procedure may require its reader to
// already know.
//
// ★ AND THE WAIT IS BOUNDED, because a wait without one is a step that hangs and says nothing.
func waitForALeaderToExist(code int, raw []byte, again func() (int, []byte, error)) (int, []byte, error) {
	var err error
	for waited := time.Duration(0); code == 409 && waited < adminLeadershipWait; waited += adminLeadershipPoll {
		if waited == 0 {
			fmt.Printf("  the control plane answers and has not elected a leader yet — waiting up to %s.\n",
				adminLeadershipWait)
			fmt.Printf("  (a change written to a node that does not lead would be accepted and then discarded)\n")
		}
		time.Sleep(adminLeadershipPoll)
		if code, raw, err = again(); err != nil {
			return code, raw, err
		}
	}
	return code, raw, nil
}

// How long an administrative write waits for a leader, and how often it asks. A deployment that has just
// started elects one in seconds; ninety is generous and a failure after it is a real one.
// ★ Variables, not constants, so a test can exercise the bound without waiting it out: a check that takes a
// minute and a half is a check somebody eventually stops running.
var (
	adminLeadershipWait = 90 * time.Second
	adminLeadershipPoll = 5 * time.Second
)
