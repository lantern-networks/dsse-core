package main

// steer_agent_update_routes.go — handing a device the signed statement of which agent build it should run.
//
// ★ THE EDGE RELAYS, IT DOES NOT SIGN. Every other signed document on this surface is minted here per request
// with the agent-policy key. This one is not, and the difference is deliberate: an update manifest authorises
// PRIVILEGED CODE EXECUTION on every endpoint that accepts it. Giving an Edge the ability to mint one would
// make every Edge a release-authoring machine, and the design's first principle is that the update key is
// separate from the agent-policy and config-signing keys precisely so that compromising a traffic node cannot
// produce code the fleet will run.
//
// So the envelope is signed elsewhere — the release process, offline or in the HSM — and this serves the bytes
// verbatim. What the Edge holds is the PUBLIC key, and it uses it for one thing: refusing to publish a file it
// cannot verify.
//
// WHY VERIFY AT ALL, when the device verifies again with its own pin. Because the failure modes are different
// and one of them is silent. A wrong or corrupt file placed here is refused by every device in the fleet, at
// once, for a reason that reads as "untrusted key" on thousands of endpoints and nowhere else — a fleet-wide
// stall whose cause lives on one machine nobody is looking at. Checking at load turns that into a startup
// error on the machine where the mistake was made.
//
// NOT IMPLEMENTED HERE, and named so it is not mistaken for missing by accident:
//
//   - Authoring and durable storage. This loads a directory of envelopes given to it. The published set
//     belongs on the control plane like every other authored artefact, and a file directory is a lab-shaped
//     stand-in, not the end state.
//   - Wave staggering. agentrollout.WaveSchedule computes a device's EligibleSince, and the honest way to
//     apply it is to give the device that instant. WITHHOLDING the document until a wave opens would produce
//     roughly the same rollout shape by a different mechanism — and would quietly change what a wave means,
//     because a device that has not been told about a release cannot pre-stage it, so its window would then be
//     spent downloading. That is exactly the failure the pre-gate staging order exists to avoid.

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/agentupdate"
)

// publishedUpdate is one release this Edge is willing to hand out.
type publishedUpdate struct {
	Manifest agentupdate.Manifest
	Envelope agentpolicy.Envelope
	Source   string // the file it came from, so a wrong publication is traceable to a path
	// TenantID is whose release this is, and it exists because the ARTIFACT is stored per tenant while this
	// index is keyed only by platform/arch.
	//
	// ★ THE DEVICE ROUTE OPENED A FLAT PATH AND THE UPLOAD WROTE A TENANT ONE (2026-08-13, twenty-eighth
	// review). Publishing succeeded, activation succeeded, every screen said active — and every device staging
	// the release got 404, because the bytes were at dir/<tenant>/<name> and the route looked in dir/<name>.
	// A release nobody can stage, reported as published.
	TenantID string
}

// publishedUpdates indexes them by the only two things a device can be handed the wrong build for.
// restart-durability: cp_durable — on an enforcing edge this is a CACHE of the control plane's published set
// and is refilled by the first pull after a restart (agent_update_source). Where no control plane is
// configured it is rebuilt from the local manifest directory at startup, which is the deployment that has no
// control plane to fetch from.
//
// populated-by: hydrated — the pull replaces the whole set on every poll, so a release published centrally
// reaches devices without touching this edge, and a release withdrawn centrally stops being offered here. The
// no-control-plane deployment fills it once from the directory at startup, which is the only case where a
// restart is what makes a publication take effect.
type publishedUpdates struct {
	// mu guards byTarget, which is REPLACED wholesale when this Edge pulls a new set from the control plane.
	//
	// ★ It became mutable when publishing stopped being a startup-only fact (2026-08-11). Reading a directory
	// once at boot meant publishing a release required restarting every Edge — which is why every publication
	// today involved a restart — and, worse, that two Edges could serve DIFFERENT releases to the same fleet
	// with nothing comparing them. That is the per-edge authored-rules defect, on the document that decides
	// which code runs on every managed machine.
	mu       sync.RWMutex
	byTarget map[string]publishedUpdate // "platform/arch"
}

// replace swaps the whole published set atomically. A partial set is never visible: the caller builds the new
// map and hands it over, so a device asking mid-swap gets the old answer or the new one, never a mixture.
func (p *publishedUpdates) replace(byTarget map[string]publishedUpdate) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.byTarget = byTarget
}

// targets reports what is published, for logging and for the artifact-presence check.
func (p *publishedUpdates) targets() map[string]publishedUpdate {
	if p == nil {
		return nil
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make(map[string]publishedUpdate, len(p.byTarget))
	for k, v := range p.byTarget {
		out[k] = v
	}
	return out
}

func updateTargetKey(platform, arch string) string {
	return strings.ToLower(strings.TrimSpace(platform)) + "/" + strings.ToLower(strings.TrimSpace(arch))
}

// loadPublishedUpdates reads every *.json in dir, verifies it against the pinned update keys, and indexes it.
//
// A file that does not verify is an ERROR and not a skip. Skipping would mean an operator who published a
// corrupt or wrongly-signed manifest sees a healthy Edge and a fleet that never updates, with the two facts
// separated by a network. The whole value of checking here is that it fails where the mistake was made.
//
// Two manifests for the same platform and architecture is also an error rather than a last-wins: which build a
// fleet receives must not depend on filename ordering.
func loadPublishedUpdates(dir string, trustedKeys []string, now time.Time) (*publishedUpdates, error) {
	if len(trustedKeys) == 0 {
		return nil, fmt.Errorf("publishing agent updates requires -agent-update-pin: without it this Edge would " +
			"hand out documents it cannot check, and the first thing it would fail to notice is the wrong one")
	}
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		// ★ AN ABSENT DIRECTORY IS NOT A MISCONFIGURATION HERE (2026-08-12). It is the ordinary starting state of
		// a control plane that has published nothing yet, and of an Edge on its first boot before anything has
		// been placed. Treating it as fatal stopped the control plane from starting at all the moment it was
		// given a place to keep artifacts.
		//
		// The protection that matters is kept: a directory that EXISTS and holds something unreadable or
		// unverifiable is still fatal, because that is an operator who published something and would otherwise
		// never learn it did not take.
		if mkerr := os.MkdirAll(dir, 0o750); mkerr != nil {
			return nil, fmt.Errorf("create the agent-update directory %s: %w", dir, mkerr)
		}
		log.Printf("agent_update_published none: %s did not exist and has been created; nothing is published from "+
			"this process until a manifest is placed there or sent to it", dir)
		return &publishedUpdates{byTarget: map[string]publishedUpdate{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read agent-update directory %s: %w", dir, err)
	}
	out := &publishedUpdates{byTarget: map[string]publishedUpdate{}}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ".json") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // deterministic error reporting, not deterministic winner: duplicates are refused below
	for _, name := range names {
		path := filepath.Join(dir, name)
		raw, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil, fmt.Errorf("read %s: %w", path, rerr)
		}
		var env agentpolicy.Envelope
		if jerr := json.Unmarshal(raw, &env); jerr != nil {
			return nil, fmt.Errorf("%s is not a signed envelope: %w", path, jerr)
		}
		m, oerr := agentupdate.Open(env, trustedKeys, now)
		if oerr != nil {
			// Includes an EXPIRED manifest. Refusing to start on one is deliberate: a published manifest past
			// its not_after is served to a fleet that refuses every copy, which is the silent stall above.
			return nil, fmt.Errorf("%s will not verify and must not be published: %w", path, oerr)
		}
		key := updateTargetKey(m.Platform, m.Arch)
		if prev, dup := out.byTarget[key]; dup {
			return nil, fmt.Errorf("two manifests publish %s: %s (%s) and %s (%s). Which build a fleet receives "+
				"must not depend on filename order", key, prev.Source, prev.Manifest.Version, path, m.Version)
		}
		out.byTarget[key] = publishedUpdate{Manifest: m, Envelope: env, Source: path}
	}
	return out, nil
}

// forTarget returns the published release for a platform/arch, if any.
func (p *publishedUpdates) forTarget(platform, arch string) (publishedUpdate, bool) {
	if p == nil {
		return publishedUpdate{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	u, ok := p.byTarget[updateTargetKey(platform, arch)]
	return u, ok
}

// registerSteerAgentUpdateRoutes serves the device-facing update manifest.
func registerSteerAgentUpdateRoutes(mux *http.ServeMux, config serverConfig) {
	// GET /steer/agent-update-manifest?platform=windows&arch=amd64
	//
	// The platform and arch are DEVICE-DECLARED, and that is safe in a way most device-declared values are not:
	// they select which document to hand over, and the manifest itself carries the platform and arch it is for,
	// so a device that lies receives a manifest its own agentupdate.Applicable refuses. It cannot obtain a build
	// for a platform it is not — the worst it can do is fetch something useless to it.
	mux.HandleFunc("GET /steer/agent-update-manifest", func(w http.ResponseWriter, r *http.Request) {
		identity, verified := transportDeviceIdentityFromRequest(r)
		if !verified || strings.TrimSpace(identity) == "" {
			writeError(w, http.StatusUnauthorized, fmt.Errorf("a verified device transport identity is required"))
			return
		}
		if config.PublishedUpdates == nil {
			// 404 rather than 503: to the updater this is "nothing published for this device", which is the
			// normal, quiet state. A deployment that has not published anything is not degraded.
			writeError(w, http.StatusNotFound, fmt.Errorf("no agent updates are published by this edge"))
			return
		}
		platform := strings.TrimSpace(r.URL.Query().Get("platform"))
		arch := strings.TrimSpace(r.URL.Query().Get("arch"))
		if platform == "" || arch == "" {
			writeError(w, http.StatusBadRequest, fmt.Errorf("platform and arch query parameters are required"))
			return
		}
		u, ok := config.PublishedUpdates.forTarget(platform, arch)
		if !ok {
			writeError(w, http.StatusNotFound, fmt.Errorf("no agent update is published for %s/%s", platform, arch))
			return
		}
		// ★★★ WHICH VERSION THIS ORGANIZATION RUNS IS THE ORGANIZATION'S OWN (2026-08-28).
		//
		// The operator publishes what EXISTS, once, to the deployment's catalogue. Choosing among what is
		// offered — staying on a version, going back to one after a bad build — is the customer's, and their
		// rollout plan has carried DesiredVersion since the plan existed. This route did not read it: every
		// device of every organization was handed the catalogue's current release regardless, so a customer
		// could pin or roll back on their own screen and their fleet would move anyway.
		//
		// The freeze, the waves and the window already reach a device per organization through
		// GET /steer/agent-update-plan — resolved from the device's own certificate, after that route was found
		// answering for the wrong tenant. This is the one field of the same decision that never followed.
		//
		// ★ AN ORGANIZATION WHOSE DEVICE DOES NOT RESOLVE IS NOT GIVEN SOMEBODY ELSE'S CHOICE. The plan route
		// was found answering the bundle tenant's freeze to every fleet on the box; the same mistake here would
		// apply the operator's pin to a customer's devices. No organization resolved means no pin applied, and
		// the catalogue's current release is served exactly as before.
		planTenant := ""
		if bound, terr := authoritativeTenantForRequest(r, "", config.TenantCARegistry); terr == nil {
			planTenant = strings.TrimSpace(bound)
		}
		// ★★ THIS EDGE HOLDS ONE VERSION PER TARGET, and that is why a pin can only ever HOLD a fleet here, not
		// move it backwards. The catalogue keeps the release it currently distributes; going back to a version
		// this deployment no longer publishes would need the Edge to hold more than one, which it does not, and
		// pretending otherwise by serving the current one to an organization that asked for another is the
		// silent move this whole lane exists to prevent. So it is refused, by name, and said out loud.
		// ★ READ FROM WHERE THIS NODE ROLE KEEPS IT. A control plane holds the plans; an Edge that PULLS holds a
		// cache, and reading only the store here meant the version an organization named reached devices on a
		// combined control plane and nowhere else — which is every deployment this installer builds. The same
		// "wired to the source the serving node does not have" this tree has spent the day removing.
		if planTenant != "" {
			if want := strings.TrimSpace(agentDesiredVersionFor(config, planTenant)); want != "" &&
				!strings.EqualFold(want, strings.TrimSpace(u.Manifest.Version)) {
				log.Printf("agent_update_manifest_withheld device=%s tenant=%s platform=%s arch=%s wants=%s "+
					"this_edge_publishes=%s — the organization runs a version this Edge does not have, and it "+
					"is NOT moved onto another one", identity, planTenant, platform, arch, want, u.Manifest.Version)
				writeError(w, http.StatusNotFound, fmt.Errorf(
					"this organization runs %s, and this edge publishes %s", want, u.Manifest.Version))
				return
			}
		}
		// Logged per fetch, at INFO, because "which devices were told about this release" is the question asked
		// after a bad build and the one nothing else can answer: the device's own record is on the device, and
		// a device that took a bad update may be the one that cannot report.
		log.Printf("agent_update_manifest_served device=%s platform=%s arch=%s version=%s source=%s",
			identity, platform, arch, u.Manifest.Version, filepath.Base(u.Source))
		writeJSON(w, http.StatusOK, u.Envelope)
	})
}

// agentUpdateFlags are this surface's flags, defined HERE rather than in main.go.
//
// Not a style preference: the Phase 0 ratchet (edge_main_split_ratchet_contract_test.go) freezes main.go's flag
// count so the split cannot quietly regress, and a new surface adding two more to it would be the regression.
// The flags live beside the code that consumes them, which is where someone reading either will look.
type agentUpdateFlags struct {
	sourceURL  *string
	sourcePoll *time.Duration
	dir        *string
	pin        *string
	// publisher is the signing identity a device must find on a package before installing it. See the flag.
	publisher *string
	// The UPDATE-SIGNING key's token. Grouped with the rest of this lane rather than beside the other HSM flags
	// in main.go, because the decomposition ratchet freezes main.go's flag count and because these three only
	// mean anything together with -agent-update-pin above.
	hsmSocket *string
	hsmToken  *string
	hsmKeyID  *string
}

func registerAgentUpdateFlags() *agentUpdateFlags {
	return &agentUpdateFlags{
		dir: flag.String("agent-update-manifest-dir", "", "directory of SIGNED agent-update manifest envelopes to publish at GET /steer/agent-update-manifest. This edge relays them and never signs one: the update key is separate from the agent-policy key so that a traffic node cannot mint code the fleet will run. Requires -agent-update-pin. Empty = publish nothing."),
		sourceURL: flag.String("agent-update-source-url", "",
			"CP→Edge sync: control-plane admin base this enforcing Edge PULLS its PUBLISHED RELEASES from, "+
				"instead of reading a directory at startup. Publishing then needs no Edge restart and every Edge "+
				"offers the same release — two Edges serving different builds to one fleet is the defect this "+
				"closes. The envelope is still verified against -agent-update-pin HERE: trusting the channel "+
				"would make a compromised control plane able to choose what the fleet runs. Empty = the local "+
				"directory is the authority."),
		sourcePoll: flag.Duration("agent-update-source-poll", 60*time.Second,
			"how often to pull the published release set from the control plane"),
		// ★ THE FOURTH KEY (2026-08-13, the agent publishing-authority design). The update-signing key authorises
		// CODE: anything signed with it runs unattended as root/SYSTEM on every endpoint that pins it. Until now
		// the only way to produce a signature was dsse-signupdate with a FILE key on somebody's laptop. These put
		// it in the same PKCS#11 token as the other three, where this process holds a handle and never the key.
		//
		// There is deliberately NO on-disk fallback. The other signers degrade to a file because a config-signing
		// outage means "policy stops updating"; this one would degrade to "the release key is on the Edge", which
		// is the outcome the whole arrangement exists to prevent.
		hsmSocket: flag.String("agent-update-hsm-agent-socket", "",
			"unix socket of dsse-hsm-agent holding the UPDATE-SIGNING key. When set, POST /admin/agent-updates mints "+
				"signed update manifests through the token, so the key that authorises running code on every device "+
				"never enters this process. It must be a DIFFERENT key from the agent-policy key — one key signing "+
				"both the release and the rollout plan means a compromised release key can also lift the freeze that "+
				"would stop it — and this edge refuses to start if they coincide."),
		hsmToken: flag.String("agent-update-hsm-agent-token", "", "bearer token for the update-signing dsse-hsm-agent socket"),
		hsmKeyID: flag.String("agent-update-hsm-agent-key-id", "",
			"key id in the token to sign update manifests with. Empty = adopt the only key the agent holds, which on "+
				"a shared token is almost certainly the wrong key: name it."),
		// ★★★ WHO MAY BUILD SOFTWARE THAT INSTALLS ITSELF ON THIS DEPLOYMENT'S DEVICES (2026-08-27, found by
		// running the shipping macOS package's own preinstall against a published configuration). The pin
		// below says a trusted party CHOSE a package; this says the package IS theirs. A device holding
		// neither installs, as root, whatever a manifest points at, and the Developer ID signature every one
		// of these packages already carries goes unused — so the endpoint installer refuses to install at all
		// without it, and a deployment that cannot say this is one no device can join.
		publisher: flag.String("agent-update-publisher", "",
			"the signing identity a device must find on an agent package before installing it: an Apple Team ID "+
				"on macOS, its counterpart on Windows. Published to devices as update_publisher_team_id. Empty = "+
				"the configuration this deployment publishes is one the endpoint installer REFUSES, so no device "+
				"can be installed against it"),
		pin: flag.String("agent-update-pin", "", "comma-separated Ed25519 public keys (hex) the published update manifests are verified against AT LOAD. Verification here is not the device's (it pins its own): it turns a wrongly-signed publication into a startup error on the machine where the mistake was made, instead of a fleet that silently refuses every copy."),
	}
}

// load reads and verifies the publication set, and logs what this edge will hand out.
func (f *agentUpdateFlags) load(now time.Time) (*publishedUpdates, error) {
	dir := strings.TrimSpace(*f.dir)
	if dir == "" {
		if strings.TrimSpace(*f.pin) != "" {
			// A pin with nothing to publish is a half-finished deployment, and silence is how it stays that way.
			log.Printf("agent_update_published none: -agent-update-pin is set but -agent-update-manifest-dir is " +
				"empty, so this edge publishes no agent updates and every device reads 'nothing published'")
		}
		return nil, nil
	}
	p, err := loadPublishedUpdates(dir, splitAgentUpdatePins(*f.pin), now)
	if err != nil {
		return nil, err
	}
	for target, u := range p.byTarget {
		log.Printf("agent_update_published target=%s version=%s delivery=%s source=%s",
			target, u.Manifest.Version, u.Manifest.Delivery, filepath.Base(u.Source))
	}
	return p, nil
}

// splitAgentUpdatePins parses the comma-separated pin flag. Whitespace is tolerated because these are pasted
// by hand from a release document; an empty list is left empty so loadPublishedUpdates can refuse it with the
// reason rather than this function inventing a default.
func splitAgentUpdatePins(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// agentDesiredVersionFor is the version an organization says it runs, from whichever place this node role
// keeps it: the pulled cache on an enforcing Edge, the store on a control plane.
func agentDesiredVersionFor(config serverConfig, tenantID string) string {
	if config.AgentRolloutCache != nil {
		if plan, known := config.AgentRolloutCache.planFor(tenantID); known {
			return plan.DesiredVersion
		}
	}
	if config.AgentRolloutPlans != nil {
		return config.AgentRolloutPlans.Get(tenantID).DesiredVersion
	}
	return ""
}
