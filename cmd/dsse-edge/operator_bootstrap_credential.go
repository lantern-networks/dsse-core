package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// operator_bootstrap_credential.go — how the FIRST cross-organization credential comes into being.
//
// ★★★ THE BOOTSTRAP MUST NOT BE WEAKER THAN THE THING IT BOOTSTRAPS (decided 2026-08-20).
//
// Acting inside a customer goes through the envelope: a standing delegation the customer can withdraw, plus a
// time-boxed elevation for the heavy acts. A permanent operator account would be a permanent key to a door
// built to be temporary — so this mints a credential that EXPIRES, and it is not reachable over the network
// at all. It runs on the control-plane host, against the control plane's own store, and exits.
//
// ★ WHY IT EXISTS AT ALL, measured 2026-08-20: this lab held no usable cross-organization credential. Every
// token and account was scoped to one organization, and the operator tenant's secrets were recorded nowhere —
// so the envelope, the only door for cross-organization acts, had never been walked through by anybody. A
// guard nothing has ever passed through is a guard nobody has tested.
//
// ★ AND IT IS NOT A BREAK-GLASS. Break-glass was retired because it issued cross-organization sessions
// silently; this issues a NAMED, time-boxed, audited credential whose every use is attributable, and it can
// only be run by somebody who already controls the machine the control plane runs on. Possession of the host
// is the authority — which is the one authority that cannot be phished, and the one that is already required
// to change what the control plane is.
func registerOperatorBootstrapFlags() (mint *bool, ttl *time.Duration, label *string) {
	mint = flag.Bool("mint-operator-credential", false, "control-plane host only: mint a TIME-BOXED operator credential, print it once, and exit. Not a server mode and not reachable over the network — possession of this host is the authority. Use it to obtain the first cross-organization credential, or one after the last has expired")
	ttl = flag.Duration("mint-operator-credential-ttl", time.Hour, "how long the minted operator credential is valid. Capped at 24h: the envelope it opens is time-boxed, so its bootstrap must be too")
	label = flag.String("mint-operator-credential-label", "", "who is taking it and why, recorded on the credential and in the audit trail (required: a credential nobody is named on is one nobody can be asked about)")
	return mint, ttl, label
}

const maxOperatorBootstrapTTL = 24 * time.Hour

// operatorBootstrapPrincipalID is who a bootstrap credential is attributed to: whoever could reach the
// control-plane host. Stable, so repeated mints do not accumulate principals.
const operatorBootstrapPrincipalID = "admin_operator_bootstrap_host"

type operatorBootstrapDeps struct {
	OperatorTenantID string
	Store            adminAuthTokenWriter
	Now              func() time.Time
	Out              func(string, ...any)
}

// adminAuthTokenWriter is the slice of the admin auth store this needs: enough to write one token, and
// nothing else. Narrow on purpose — a bootstrap that could read the store could read every credential in it.
type adminAuthTokenWriter interface {
	PersistAPIToken(ctx context.Context, token adminAPIToken) error
	PersistPrincipal(ctx context.Context, principal adminPrincipal) error
}

// mintOperatorBootstrapCredential is the whole command. It returns the raw secret so the caller prints it
// exactly once; nothing here logs it.
func mintOperatorBootstrapCredential(ctx context.Context, deps operatorBootstrapDeps, ttl time.Duration,
	label string) (adminAPIToken, string, error) {
	tenant := strings.TrimSpace(deps.OperatorTenantID)
	if tenant == "" {
		return adminAPIToken{}, "", fmt.Errorf("this node does not know which organization is the operator's, so " +
			"it cannot mint a credential that acts across organizations. Run this on the control plane")
	}
	if deps.Store == nil {
		return adminAPIToken{}, "", fmt.Errorf("this node has no durable admin credential store — a credential " +
			"written only into memory would vanish with this process, which is worse than not issuing one")
	}
	if strings.TrimSpace(label) == "" {
		return adminAPIToken{}, "", fmt.Errorf("say who is taking this credential and why: a cross-organization " +
			"credential nobody is named on is one nobody can be asked about afterwards")
	}
	if ttl <= 0 {
		return adminAPIToken{}, "", fmt.Errorf("a credential that opens a time-boxed door must itself expire")
	}
	if ttl > maxOperatorBootstrapTTL {
		return adminAPIToken{}, "", fmt.Errorf("%s is longer than this bootstrap will issue (%s). The envelope "+
			"this opens is time-boxed; if the work needs longer, take another one and let the first expire",
			ttl, maxOperatorBootstrapTTL)
	}
	now := deps.Now
	if now == nil {
		now = time.Now
	}
	at := now().UTC()
	// ★★★ A CREDENTIAL WITH NO PRINCIPAL AUTHENTICATES NOWHERE, AND SAYS 201 WHILE DOING IT (2026-08-20, and
	// this is the second time this shape has been found — see the note on the token lookup query, 2026-08-16).
	// The lookup joins every token to the principal that created it and requires that principal to be ACTIVE,
	// because revoking a person must stop their tokens. A creator that does not exist means a token that is
	// stored, unexpired, active — and refused on every plane, forever, with nothing saying why.
	//
	// So the host is a NAMED principal, written first. It is also the honest answer to "who did this": every
	// use of this credential is attributed to somebody who could reach the control-plane host.
	principal := adminPrincipal{
		ID:        operatorBootstrapPrincipalID,
		TenantID:  tenant,
		Subject:   operatorBootstrapPrincipalID,
		Email:     "operator-bootstrap@control-plane.host",
		Roles:     []string{"super_admin", "admin"},
		IDPID:     "control_plane_host",
		Status:    "active",
		CreatedAt: at.Format(time.RFC3339),
		Metadata:  map[string]any{"source": "control-plane host bootstrap"},
	}
	if err := deps.Store.PersistPrincipal(ctx, principal); err != nil {
		return adminAPIToken{}, "", fmt.Errorf("write the principal this credential is attributed to (without it "+
			"the credential is refused everywhere and nothing says why): %w", err)
	}
	token, raw, _, err := buildAdminAPIToken(adminAPITokenCreateRequest{
		Name:      "operator bootstrap — " + strings.TrimSpace(label),
		Roles:     []string{"super_admin", "admin"},
		ExpiresAt: at.Add(ttl).Format(time.RFC3339),
	}, tenant, operatorBootstrapPrincipalID, at)
	if err != nil {
		return adminAPIToken{}, "", err
	}
	token.Metadata["minted_by"] = "control-plane host"
	token.Metadata["reason"] = strings.TrimSpace(label)
	if err := deps.Store.PersistAPIToken(ctx, token); err != nil {
		return adminAPIToken{}, "", fmt.Errorf("write the credential: %w", err)
	}
	return token, raw, nil
}

// runOperatorBootstrapAndExit prints the secret once and ends the process. Never returns on success: this is
// a command, and a process that went on to serve traffic after minting a cross-organization credential would
// be a very odd thing to have running.
func runOperatorBootstrapAndExit(ctx context.Context, deps operatorBootstrapDeps, ttl time.Duration, label string) {
	token, raw, err := mintOperatorBootstrapCredential(ctx, deps, ttl, label)
	if err != nil {
		log.Fatalf("mint-operator-credential: %v", err)
	}
	out := deps.Out
	if out == nil {
		out = func(format string, a ...any) { fmt.Fprintf(os.Stdout, format+"\n", a...) }
	}
	out("operator credential minted for %s", token.TenantID)
	out("  expires:  %s  (%s from now)", token.ExpiresAt, ttl)
	out("  reason:   %s", token.Metadata["reason"])
	out("  id:       %s", token.ID)
	out("")
	out("%s", raw)
	out("")
	out("This is the only time it is shown. It acts across organizations, every use is attributed to it, and")
	out("it stops working at the time above — take another one rather than extending this.")
	os.Exit(0)
}
