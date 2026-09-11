//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lantern-networks/dsse-core/clients/windows-wfp/configstore"
)

// doProvision â the part of provisioning that only exists on Windows.
//
// â IT LIVES HERE BECAUSE provision.go MUST BUILD EVERYWHERE (2026-08-29). The file had no build tag and
// called escrowProfile, enrolmentDir and doInstallInterceptionRoot, all of which are //go:build windows. The
// package therefore did not compile on any other platform, which the published-tree gate caught: the tree
// somebody else gets has to stand up on its own, and it did not. Splitting on the tag rather than tagging the
// whole file keeps planProvision, readTokenFile and writeSeed â and their eight tests â building and running
// on the machine this is developed from.

// doProvision is the install-time act: verify and persist the profile, then derive from it everything this
// device needs and put it where the agent looks.
//
// â THE ORDER IS THE POINT. Trust material goes down BEFORE the enrolment seed, and the seed before the service
// is raised to auto-start. A device that starts with a token and no anchors enrols over an unpinned channel or
// not at all; a device that starts with anchors and no token stands aside and says so, which is recoverable.
// The failure this ordering forbids is the one that is not: steering armed with nowhere to go.
func doProvision(be configstore.Backend, configPath, tokenPath, pinFilePath, pin string) error {
	if strings.TrimSpace(configPath) == "" {
		return fmt.Errorf("--config is required for --provision: the profile downloaded from the Console")
	}
	// âââ THE FOURTH ARTEFACT (2026-08-29, the operator's decision). The key that verifies the profile is
	// placed by the operator beside the token, not baked into the package and not taken from the profile.
	// See signing_key_artefact.go for why both alternatives were rejected. A pin supplied on the command line
	// or baked in still wins, because a deployment that provisions its own packages should not have to hand
	// its own key back to itself.
	operatorKey, err := readSigningKeyFile(pinFilePath)
	if err != nil {
		return err
	}
	if strings.TrimSpace(pin) == "" {
		pin = operatorKey
	}
	if strings.TrimSpace(pin) == "" {
		return fmt.Errorf("no key to verify the profile with: pass PIN=<the key file the Console issued " +
			"beside the token>, or --pin. A profile cannot carry the key that proves it â a document that " +
			"certifies itself certifies anything â so this is the one thing that must arrive separately")
	}
	token, err := readTokenFile(tokenPath)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(configPath) {
		if exe, e := os.Executable(); e == nil {
			configPath = filepath.Join(filepath.Dir(exe), configPath)
		}
	}
	env, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read profile %q: %w", configPath, err)
	}
	prof, err := configstore.Apply(be, env, pin, "path", time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("apply profile: %w", err)
	}
	fmt.Printf("profileapply: applied version=%d tenant=%q posture=%q transport=%q\n",
		prof.Version, prof.TenantID, prof.Posture, prof.TransportURL)

	plan, err := planProvision(prof, token)
	if err != nil {
		return fmt.Errorf("provision: %w", err)
	}
	for _, n := range plan.Notes {
		fmt.Println("profileapply: " + n)
	}
	if err := escrowProfile(env); err != nil {
		fmt.Fprintf(os.Stderr, "profileapply: WARNING â the profile is applied but could not be escrowed: %v\n", err)
	}

	dataDir := filepath.Dir(enrolmentDir())
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dataDir, err)
	}
	anchorPath := filepath.Join(dataDir, "transport_ca.pem")
	if err := os.WriteFile(anchorPath, plan.AnchorsPEM, 0o644); err != nil {
		return fmt.Errorf("write transport anchors: %w", err)
	}
	fmt.Println("profileapply: transport anchors -> " + anchorPath)
	// ★★★ AND THE ORGANIZATION'S TRANSPORT ANCHOR IS TRUSTED BY THIS MACHINE, NOT JUST BY THE AGENT
	// (2026-09-03, the operator's decision).
	//
	// The step-up portal is served by the Edge on the organization's own transport certificate, and the
	// branded step-up window is a WebView2 that has no interstitial to click through. Until now the window
	// answered that by setting --ignore-certificate-errors unconditionally — on the one surface where a user
	// types their password and second factor — which also made the operator's decision that the portal's
	// certificate is theirs to provide worth nothing, because nothing checked it.
	//
	// So the organization's OWN transport anchor is laid into the machine store — the narrowest authority the
	// profile carries, never a provider root that also vouches for other organizations. See
	// organization_anchor.go for the selection and for what this still does NOT fix: a machine-store anchor
	// reaches every TLS verification on the box, and neither this CA nor the interception root carries Name
	// Constraints.
	//
	// ★ REFUSED RATHER THAN OVERWRITTEN when a different authority already holds the subject — the same rule
	// and the same code path as the interception root, for the same reason: a trust store shows only the
	// name, and two authorities sharing one has taken this product down twice.
	// ★★★ IN PRODUCTION THIS MACHINE TRUSTS NOTHING EXTRA (2026-09-03, the operator's question settled it).
	//
	// The step-up ceremony makes three navigations and only the middle one is the identity provider; the
	// first and last are the DSSE portal. Moving from a lab Keycloak to Entra ID fixes the middle one and
	// leaves the portal exactly where it was — and what fixes THE PORTAL is the operator's own certificate,
	// which they had already decided to provide. Once they have, there is nothing for a device to add.
	//
	// So the anchor below is the LAB's answer, taken only when the deployment says its portal is still on the
	// certificate it minted itself. Saying which case this machine is in matters more than the action: a
	// machine that quietly widened its trust store for a lab would carry that for the rest of its life.
	if plan.StepUpPortalCertificateIsOperators {
		fmt.Println("profileapply: the step-up portal is on the operator's own certificate — nothing is added " +
			"to this machine's trust store for it")
	} else {
		fmt.Println("profileapply: ★ this deployment's step-up portal is on a certificate it issued itself, " +
			"so this machine must trust that authority to complete a step-up. Put your own certificate in " +
			"the deployment's clientless/ directory and re-provision, and this step disappears.")
		// The profile names the authority the portal is served under. A device does not get to guess it: this
		// machine trusted the organization's own transport CA for a whole afternoon while the portal was
		// presenting the deployment's, because the guess was made here from a name.
		if len(plan.StepUpPortalAnchorPEM) == 0 {
			return fmt.Errorf("this deployment's step-up portal is on its own certificate but the profile does " +
				"not say which authority serves it, so there is nothing this machine could trust for it")
		}
		portalAnchorPath := filepath.Join(dataDir, "step_up_portal_ca.pem")
		if err := os.WriteFile(portalAnchorPath, plan.StepUpPortalAnchorPEM, 0o644); err != nil {
			return fmt.Errorf("write the step-up portal's authority: %w", err)
		}
		if err := doInstallTrustAnchor(portalAnchorPath, "the step-up portal's authority"); err != nil {
			return fmt.Errorf("trust the step-up portal's authority: %w", err)
		}
		fmt.Println("profileapply: the step-up portal's authority is trusted by this machine -> " + portalAnchorPath)
	}

	if len(plan.InterceptionRootPEM) > 0 {
		rootPath := filepath.Join(dataDir, "interception-root.pem")
		if err := os.WriteFile(rootPath, plan.InterceptionRootPEM, 0o644); err != nil {
			return fmt.Errorf("write interception root: %w", err)
		}
		keepPublicReadable(rootPath)
		// Carrying it is not trusting it. This is the step that makes intercepted TLS verifiable on this
		// machine, and it refuses rather than overwrites when a DIFFERENT authority already holds the subject.
		if err := doInstallInterceptionRoot(rootPath); err != nil {
			return fmt.Errorf("install interception root: %w", err)
		}
		// â And the third place, which this program does not own: the combined bundle the CA environment
		// variables point at. Provisioning updates the machine store and interception-root.pem, so a rotation
		// leaves Node working and every openssl-linked tool broken, invisibly (2026-08-31, eleven hours on
		// this box). Reported, never rewritten â see sibling_trust_bundle.go.
		// ★ AND THE THIRD PLACE, WHICH THIS PACKAGE NOW OWNS (2026-09-07, the operator's decision to unify
		// with macOS: write the bundle and set the variables). Until today this only WARNED, on the argument
		// that the bundle was an operator's composition — see the head of sibling_trust_bundle.go, whose
		// reasoning was sound for a file somebody else built. It does not apply to one we author and rewrite
		// on every provision: the failure it warned about was a bundle going STALE, and a file rebuilt from
		// this machine's own store plus the current root has no stale state to hold.
		//
		// Measured on a steered box before this existed: schannel, .NET and Go verify without it (they read
		// the machine store), while node, curl, ruby and the python-based AWS CLI all fail. This closes the
		// second group. Java and Firefox keep their own stores and are not reachable from here; the bundle
		// writer says so rather than leaving it to be discovered.
		if err := writeCABundleAndPointAtIt(dataDir, plan.InterceptionRootPEM); err != nil {
			// Not fatal. The device is correctly provisioned and steering either way, and refusing an install
			// over a convenience file would be the wrong trade — but it is absolutely worth saying.
			fmt.Fprintf(os.Stderr, "profileapply: could not write the CA bundle (%v) — programs carrying their "+
				"own CA list (curl, openssl, python, node, ruby) will NOT verify intercepted TLS on this "+
				"machine until one is written by hand\n", err)
		}
	}

	note, err := writeSeedForOrganization(enrolmentDir(), plan.Seed, prof.TenantID)
	if err != nil {
		return err
	}
	if note != "" {
		fmt.Println("profileapply: " + note)
	}

	// The operator key, left where a person will look for it, and put in force where the AGENT reads it.
	if operatorKey != "" {
		if n, err := installSigningKey(dataDir, operatorKey); err != nil {
			fmt.Fprintf(os.Stderr, "profileapply: WARNING - the profile is applied but the key could not be recorded: %v\n", err)
		} else if n != "" {
			fmt.Println("profileapply: " + n)
		}
		if n, err := putPinsInServiceArgs("DsseSteer", operatorKey); err != nil {
			// Not fatal: the profile is applied and the material is down. A service that cannot be reconfigured
			// is a box that will not verify its NEXT profile, which is worth shouting about and not worth
			// rolling an install back for.
			fmt.Fprintf(os.Stderr, "profileapply: WARNING - %v. Until this is fixed the agent verifies "+
				"profiles against whatever its service arguments already named.\n", err)
		} else {
			fmt.Println("profileapply: " + n)
		}
		// ★ AND RECORDED WHERE AN UPGRADE CAN FIND IT AGAIN. The operator's placing of the key is the explicit
		// act that adopts it, so this is the moment it is authoritative — and a major upgrade deletes the
		// service arguments it was just written into. The store is created protected (see
		// verifier_store_windows.go); a failure is loud and non-fatal, because a box that provisioned
		// correctly and cannot survive a future upgrade is better than a failed provision.
		// Recorded per purpose from what is now actually in force, rather than writing operatorKey into every
		// slot: pinArgs above set config and policy to this key, and a --update-pin the package baked in is a
		// third authority this must carry forward without claiming the operator chose it.
		// Recorded per (service, flag) from what is now actually in force, rather than writing operatorKey into
		// every slot: pinArgs above set DsseSteer's config and policy pins to this key, while DsseUpdater's
		// update pin, plan pin and publisher are separate conditions the package baked in — this must carry
		// them forward without claiming the operator chose them.
		provisioned := pinSet{}
		for _, service := range servicesWithPurposes() {
			args, found, aerr := serviceArgsFor(service)
			if aerr != nil || !found {
				continue
			}
			for name, value := range pinsInArgs(service, args) {
				provisioned[name] = value
			}
		}
		if _, err := recordCapturedPins(provisioned); err != nil {
			fmt.Fprintf(os.Stderr, "profileapply: WARNING - the key is in force but could NOT be recorded in "+
				"the protected verifier store (%v). This box will lose its verifier at the next major "+
				"upgrade.\n", err)
		} else {
			fmt.Println("profileapply: the adopted verifier is recorded in the protected store, so a major " +
				"upgrade can put it back")
		}
	}
	// Both copies were just written; say whether they agree. A check that only runs when asked is a check
	// that runs after somebody is already confused.
	agree := reportPinAgreement(dataDir, "DsseSteer")
	fmt.Println("profileapply: " + agree.Note)
	// ★ And the third value: the key THIS run verified with. See pin_used_now.go.
	if n := usedNowNote(pin, agree); n != "" {
		fmt.Fprintln(os.Stderr, "profileapply: "+n)
	}
	return nil
}
