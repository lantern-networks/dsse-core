package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	grantstore "github.com/lantern-networks/dsse-core/grantstore"
	model "github.com/lantern-networks/dsse-core/model"
)

// deviceBindingSigner signs what the gate carries to the broker inside the step-up start URL — the verified
// (T) device identity AND the organization the held flow belonged to. Both are client-visible and neither may
// be forgeable: the device decides which device a grant binds to, and the organization decides WHOSE identity
// provider is trusted to mint it.
//
// ★★★ THE KEY IS THE DEPLOYMENT'S, NOT THE PROCESS'S (2026-09-02, measured on a three-region deployment).
//
// It used to be per-process random, on the reasoning that a pending auth state lives only minutes so a key
// that rotates on restart is sufficient. That is true of ONE Edge. This deployment has a fleet: the step-up
// URL names the deployment's agent plane, the region's door hands that connection to whichever Edge it
// likes, and the Edge that ISSUED the URL is usually not the Edge that receives it. The signature then does
// not verify — and it does not fail loudly, because an unverifiable device is treated as "no device
// identity", which mints a tenant-wide grant instead of a device-bound one. The binding this whole mechanism
// exists to provide would have been silently absent on every ceremony that crossed a node.
//
// So the key is a deployment secret, generated once by the installer and carried to every Edge, like the
// connector and audit-ingest secrets beside it. A node given none falls back to a random key and says so:
// single-node use keeps working, and a fleet with one node misconfigured is visible in its log rather than in
// a grant that is weaker than it looks.
type deviceBindingSigner struct{ key []byte }

func newDeviceBindingSigner() (*deviceBindingSigner, error) {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		return nil, err
	}
	return &deviceBindingSigner{key: k}, nil
}

// newDeviceBindingSignerFromSecret uses the deployment's shared secret. An empty secret returns nil, which
// the caller reads as "fall back to a random key and say so".
func newDeviceBindingSignerFromSecret(secret string) *deviceBindingSigner {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return nil
	}
	sum := sha256.Sum256([]byte("dsse step-up binding v1|" + secret))
	return &deviceBindingSigner{key: sum[:]}
}

// signBinding covers the device AND the organization together, so neither can be moved onto another
// signature. An empty device still signs, because the organization alone is worth carrying.
func (s *deviceBindingSigner) signBinding(device, tenant string) string {
	device, tenant = strings.TrimSpace(device), strings.TrimSpace(tenant)
	if s == nil || (device == "" && tenant == "") {
		return ""
	}
	mac := hmac.New(sha256.New, s.key)
	mac.Write([]byte("device=" + device + "\ntenant=" + tenant + "\n"))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (s *deviceBindingSigner) sign(device string) string { return s.signBinding(device, "") }

// verifiedBinding returns the device and organization iff the signature covers exactly those two values.
func (s *deviceBindingSigner) verifiedBinding(device, tenant, sig string) (string, string) {
	device, tenant, sig = strings.TrimSpace(device), strings.TrimSpace(tenant), strings.TrimSpace(sig)
	if s == nil || sig == "" || (device == "" && tenant == "") {
		return "", ""
	}
	if hmac.Equal([]byte(s.signBinding(device, tenant)), []byte(sig)) {
		return device, tenant
	}
	return "", ""
}

// verifiedDevice returns the device iff the signature matches (constant-time); empty otherwise. This is how the
// broker decides whether to trust a device carried in a client-visible start URL.
func (s *deviceBindingSigner) verifiedDevice(device, sig string) string {
	device, sig = strings.TrimSpace(device), strings.TrimSpace(sig)
	if s == nil || device == "" || sig == "" {
		return ""
	}
	if hmac.Equal([]byte(s.sign(device)), []byte(sig)) {
		return device
	}
	return ""
}

// federatedAuthGate turns an "authenticate" decision on the DECRYPTED (steered) browser path into a real IdP
// redirect instead of a bare 401: when a policy requires authentication and the flow is a browser top-level
// navigation, the Edge 302-redirects to the clientless broker (which redirects to the tenant's IdP); once a
// federated grant exists the same flow is allowed. This is the steered counterpart of the clientless front
// door — the "Google policy lens" demo's 401 becomes a redirect.
//
// Per-device binding: the gate has the verified (T) device identity for the steered protected-resource flow
// (that flow IS decrypted), so it SIGNS the device into the step-up start URL it emits (inline 302 for a
// browser, X-Dsse-Stepup-Url for a native flow). The broker verifies the signature and mints the grant bound
// to that device. This works even though the browser→broker hop is not steered (the broker is co-located on
// the edge's steering-excluded address, so the device cannot reach the callback any other way). A tenant-wide
// grant (no device / no signer) remains the fallback. See docs/idp_federated_authentication_design.md.
type federatedAuthGate struct {
	grants        *grantstore.Store
	brokerBaseURL string
	tenantID      string
	// signer binds the verified (T) device into the step-up start URL so the broker (holding the same signer)
	// can mint a device-bound grant even though the browser→broker hop is not itself steered/decrypted (the
	// broker is co-located on the edge's steering-excluded address). Nil → grants stay tenant-wide.
	signer *deviceBindingSigner
}

// isAuthRedirectCase reports whether this decision + request is a browser authenticate flow the gate handles
// (vs a plain deny, or a non-browser flow that cannot follow a redirect).
func (g *federatedAuthGate) isAuthRedirectCase(r *http.Request, decision string) bool {
	if g == nil || strings.TrimSpace(g.brokerBaseURL) == "" {
		return false
	}
	if !decisionRequiresOIDCRedirect(decision) {
		return false
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

// hasLiveGrant reports whether a live federated grant satisfies this flow. When the steered flow carries a
// verified transport device identity, the grant must be bound to THAT device (per-device) — except a
// tenant-wide grant (no device) still satisfies it, the documented lab fallback for flows whose device
// identity is not yet plumbed. When the flow has no device identity, tenant-level presence is used.
//
// When the resource requires a step-up assurance (requiredACR != ""), the satisfying grant must ALSO carry that
// acr — exact match, the same semantics the broker enforces at grant-mint (oidcbroker.ValidateIDToken). Without
// this, a baseline grant (acr absent) would satisfy a step-up-gated resource and the step-up requirement would
// leak; the user must hold a grant minted at the required assurance. An empty requiredACR keeps presence-only.
func (g *federatedAuthGate) hasLiveGrant(deviceID, requiredACR string) bool {
	return g.hasLiveGrantFor("", deviceID, requiredACR)
}

// ★★★ AND IT LOOKS UNDER THE FLOW'S ORGANIZATION (2026-09-02). Asking g.tenantID — this node's own — is the
// same defect as the broker's: the grant a customer's user just earned is filed under the customer, and a
// gate that looks for it under the operator finds none and holds the flow again, forever.
func (g *federatedAuthGate) hasLiveGrantFor(tenantID, deviceID, requiredACR string) bool {
	if g == nil || g.grants == nil {
		return false
	}
	if strings.TrimSpace(tenantID) == "" {
		tenantID = g.tenantID
	}
	deviceID = strings.TrimSpace(deviceID)
	requiredACR = strings.TrimSpace(requiredACR)
	now := time.Now().UTC()
	for _, gr := range g.grants.List(strings.TrimSpace(tenantID)) {
		if !g.grants.Valid(gr.GrantID, now) {
			continue
		}
		if deviceID != "" && strings.TrimSpace(gr.DeviceID) != "" && gr.DeviceID != deviceID {
			continue // a grant bound to a different device does not satisfy this device
		}
		if requiredACR != "" && strings.TrimSpace(gr.ACR) != requiredACR {
			continue // a grant minted at a weaker (or absent) assurance does not satisfy a step-up-gated resource
		}
		return true
	}
	return false
}

// stepUpChallengeHeader carries the step-up portal URL on a NON-browser (native: SMB/RDP/WinRM) authenticate
// deny, so the steering agent can open it out-of-band; after the user completes the step-up a device grant
// exists and the retried native connection is allowed.
const stepUpChallengeHeader = "X-Dsse-Stepup-Url"

// stepUpURL builds the clientless-broker start URL carrying the original resource (return_to) + the policy's
// required IdP + step-up acr, so the broker requests the stronger context from the (single) corporate IdP —
// no second IdP needed; the SAME IdP re-prompts for phishing-resistant MFA via acr_values. When the steered
// flow carried a verified (T) device identity, it is signed into the URL (device + device_sig) so the broker
// binds the minted grant to THAT device — the broker hop itself is not steered, so the device cannot otherwise
// reach the callback.
func (g *federatedAuthGate) stepUpURL(returnTo, requiredIdP, requiredACR, deviceID string) string {
	return g.stepUpURLFor(returnTo, requiredIdP, requiredACR, deviceID, g.tenantID)
}

// ★★★ AND THE ORGANIZATION THE HELD FLOW BELONGED TO (2026-09-02, measured on the live deployment).
//
// The broker resolved the identity provider against the EDGE'S OWN organization, so a customer's device was
// answered "no usable IdP for the tenant" about a registry that belonged to the operator — while the
// customer's own provider sat in the same Edge's registry, applied from the config bundle seconds earlier.
// This is the family this deployment keeps producing: a question about somebody else answered with an
// attribute of this node.
//
// The organization travels signed, beside the device, because it selects WHOSE identity provider is trusted
// to mint a grant. An unsigned organization in a client-visible URL would let a device ask to be
// authenticated by another customer's IdP.
func (g *federatedAuthGate) stepUpURLFor(returnTo, requiredIdP, requiredACR, deviceID, tenantID string) string {
	// ★ A NODE WITH NO PORTAL HAS NO URL TO GIVE, and must say nothing rather than a relative path. A header
	// carrying "/clientless/auth/start?..." is an address an agent would open against whatever host it
	// happened to be talking to.
	if g == nil || strings.TrimSpace(g.brokerBaseURL) == "" {
		return ""
	}
	q := url.Values{}
	q.Set("return_to", returnTo)
	if strings.TrimSpace(requiredIdP) != "" {
		q.Set("idp", strings.TrimSpace(requiredIdP))
	}
	if strings.TrimSpace(requiredACR) != "" {
		q.Set("acr", strings.TrimSpace(requiredACR))
	}
	if tenantID = strings.TrimSpace(tenantID); tenantID == "" {
		tenantID = g.tenantID
	}
	if sig := g.signer.signBinding(deviceID, tenantID); sig != "" {
		if d := strings.TrimSpace(deviceID); d != "" {
			q.Set("device", d)
		}
		q.Set("tenant", tenantID)
		q.Set("device_sig", sig)
	}
	return strings.TrimRight(g.brokerBaseURL, "/") + "/clientless/auth/start?" + q.Encode()
}

// redirectToIdP writes the 302 to the step-up portal (browser flows can follow it inline).
func (g *federatedAuthGate) redirectToIdP(w http.ResponseWriter, r *http.Request, returnTo, requiredIdP, requiredACR, deviceID, tenantID string) {
	http.Redirect(w, r, g.stepUpURLFor(returnTo, requiredIdP, requiredACR, deviceID, tenantID), http.StatusFound)
}

// authStepUpRequirements pulls the required IdP + step-up acr from an authenticate decision's
// prompt_reauthentication action (set by the authored rule / policy), so the redirect can request that
// step-up from the SAME IdP.
func authStepUpRequirements(dec model.AccessDecision) (idpID, acr string) {
	for _, a := range dec.Actions {
		if a.Type != "prompt_reauthentication" || a.Metadata == nil {
			continue
		}
		if v, ok := a.Metadata["required_idp_id"].(string); ok {
			idpID = v
		}
		if v, ok := a.Metadata["min_acr"].(string); ok {
			acr = v
		}
	}
	return idpID, acr
}
