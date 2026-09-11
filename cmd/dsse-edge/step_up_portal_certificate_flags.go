package main

import "flag"

// stepUpPortalCertificateFlags declares the certificate a USER'S BROWSER validates at the step-up portal.
//
// The identity provider is not part of this product — it is the customer's Okta or Entra ID, reached over a
// publicly trusted certificate. The DSSE hop in between is a browser-facing page like any other, so its
// certificate is provided for it rather than minted from a CA that exists to do something else. See
// the_step_up_portal_is_a_browser_facing_page.go for the two alternatives that were measured and rejected.
func stepUpPortalCertificateFlags() (cert, key *string) {
	return flag.String("clientless-tls-cert", "",
			"certificate presented at the step-up portal's own name (the host in -clientless-base-url). A "+
				"browser is sent here to authenticate, so this is the operator's certificate for a name they "+
				"hold — publicly trusted in production. Empty = the agent plane's certificate, which a browser "+
				"has no reason to trust."),
		flag.String("clientless-tls-key", "", "private key for -clientless-tls-cert.")
}
