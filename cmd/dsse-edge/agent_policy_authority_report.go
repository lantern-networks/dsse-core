package main

import (
	"strings"
	"sync/atomic"
)

// agent_policy_authority_report.go — which signing authority THIS node serves under, said out loud.
//
// ★★★ WHY A DEPLOYMENT HAS TO BE ABLE TO COUNT ITS SIGNING AUTHORITIES (2026-08-25, measured).
//
// A second region was carried from the first and came up healthy in every view: containers up, front door
// answering, Edges reporting to the control plane, four Edges agreeing on two regions. What it was actually
// doing was refusing every config bundle the deployment served, every ten seconds, because it had minted its
// own agent-policy signing key — the deployment's copy of that key was made by whichever node booted first,
// so a directory carried before that carried a hole, and the hole filled itself differently in each place.
//
// The installer now mints that key with the rest of the deployment's authorities, and refuses to prepare a
// region whose carried directory lacks it. Both of those act before anything is running. This is the one that
// acts after: an Edge SAYS which key it signs under, so "does this deployment have one signing authority"
// is a question with an answer, asked of the fleet the control plane can already see.
//
// ★ IT IS REPORTED, NOT ASKED FOR — invariant 12. The control plane serves no agent plane, so its own key
// says nothing about the nodes devices actually meet; and an Edge in another region is not reachable from
// here. What the authority can see is what every Edge tells it.
//
// ★ THE PUBLIC HALF ONLY. It is the value the Edge already prints at start-up for an operator to anchor in
// the device keyring, and it is what a device pins — so it discloses nothing that is not already meant to be
// distributed. The seed never leaves the node.
var agentPolicyAuthorityPublicKey atomic.Pointer[string]

// setAgentPolicyAuthority records the public half of the key this node signs agent policy with. Called once,
// where the signer is chosen — including the HSM path, because the question is "which authority", not "which
// storage".
func setAgentPolicyAuthority(publicKeyHex string) {
	v := strings.ToLower(strings.TrimSpace(publicKeyHex))
	if v == "" {
		return
	}
	agentPolicyAuthorityPublicKey.Store(&v)
}

// agentPolicyAuthorityForReport is what this node says about it, for the fleet report it already sends. Empty
// means this node signs nothing — which is a real state (an operator ran with -allow-unsigned-agent-policy),
// and reads as "no authority here" rather than as agreement with everybody else.
func agentPolicyAuthorityForReport() string {
	if p := agentPolicyAuthorityPublicKey.Load(); p != nil {
		return *p
	}
	return ""
}
