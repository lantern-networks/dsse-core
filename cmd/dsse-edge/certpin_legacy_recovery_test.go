package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"github.com/lantern-networks/dsse-core/policyrule"
)

// An offline, trusted-backup repair, not an automatic ownership claim. It covers
// the documented stop/quarantine/restore/review procedure without adding an API.
func checkLegacyCertPinRecovery(t *testing.T, ap, cp, rp blobstore.Persister) {
	t.Helper()
	ctx := context.Background()
	assets, rules, candidates := assetcatalog.NewStore(), policyrule.NewStore(), policycandidate.NewStore()
	reload := func() {
		assets, rules, candidates = assetcatalog.NewStore(), policyrule.NewStore(), policycandidate.NewStore()
		for _, err := range []error{assets.SetPersister(ap), rules.SetPersister(rp), candidates.SetPersister(cp)} {
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	reload()
	c, err := candidates.AddManualCertPinBypass(ctx, "own", "approved.example", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, _, err = candidates.Materialize(ctx, "own", c.CandidateID, false, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err = emitCertPinBypassRuleContext(ctx, assets, rules, c); err != nil {
		t.Fatal(err)
	}
	peer := assetcatalog.Endpoint{ID: "ordinary", TenantID: "peer", Kind: assetcatalog.KindNetwork, Source: assetcatalog.SourceManual, Address: "peer.example"}
	if _, err = assets.UpsertEndpointContext(ctx, peer); err != nil {
		t.Fatal(err)
	}
	id := "certpin-ep-" + c.CandidateID
	// The trusted backup precedes the legacy edit and agrees with the candidate.
	good, _ := ap.Load()
	var original map[string]json.RawMessage
	json.Unmarshal(good, &original)
	var eps map[string]map[string]assetcatalog.Endpoint
	json.Unmarshal(original["endpoints"], &eps)
	saved := eps["own"][id]
	saved.Source = assetcatalog.SourceManual // old generated shape
	bad := saved
	bad.Address = "unreviewed.example"
	bad.Tags = []string{"cert_pin", "legacy-edit"}
	eps["own"][id] = bad
	original["endpoints"], _ = json.Marshal(eps)
	corrupted, _ := json.Marshal(original)
	if err = ap.Save(corrupted); err != nil {
		t.Fatal(err)
	}
	reload()
	// Freeze protects ownership but does not by itself quarantine an old bypass.
	if got := policyrule.EgressBypassFQDNs("own", rules.List("own", policyrule.PlaneEgress), assets); !reflect.DeepEqual(got, []string{"unreviewed.example"}) {
		t.Fatal("legacy risk fixture", got)
	}
	before, _ := ap.Load()
	if _, err = assets.UpsertEndpointContext(ctx, saved); !errors.Is(err, assetcatalog.ErrCertPinEndpointOwnership) {
		t.Fatal(err)
	}
	if _, err = assets.DeleteEndpointContext(ctx, "own", id); !errors.Is(err, assetcatalog.ErrCertPinEndpointOwnership) {
		t.Fatal(err)
	}
	if err = emitCertPinBypassRuleContext(ctx, assets, rules, c); !errors.Is(err, assetcatalog.ErrCertPinEndpointOwnership) {
		t.Fatal(err)
	}
	after, _ := ap.Load()
	if !bytes.Equal(before, after) {
		t.Fatal("refused repair mutated original")
	}
	rule, ok := rules.Get("own", "certpin-rule-"+c.CandidateID)
	if !ok {
		t.Fatal("missing rule")
	}
	rule.Status = policyrule.StatusDisabled
	if _, err = rules.UpsertContext(ctx, rule); err != nil {
		t.Fatal(err)
	}
	reload()
	if got := policyrule.EgressBypassFQDNs("own", rules.List("own", policyrule.PlaneEgress), assets); len(got) != 0 {
		t.Fatal("disabled rule still bypasses", got)
	}
	// All writers/serving are stopped in the runbook. Change this endpoint only,
	// using the known pre-edit record; neither prefix nor candidate alone proves
	// ownership. Do not delete the whole catalog or infer missing backup fields.
	eps["own"][id] = saved
	original["endpoints"], _ = json.Marshal(eps)
	repaired, _ := json.Marshal(original)
	if err = ap.Save(repaired); err != nil {
		t.Fatal(err)
	}
	reload()
	if got := policyrule.EgressBypassFQDNs("own", rules.List("own", policyrule.PlaneEgress), assets); len(got) != 0 {
		t.Fatal("repair enabled rule")
	}
	if err = emitCertPinBypassRuleContext(ctx, assets, rules, c); err != nil {
		t.Fatal("original reviewed target cannot be adopted", err)
	}
	reload()
	endpoint, _ := assets.GetEndpoint("own", id)
	if endpoint.Source != assetcatalog.SourceCertPin || endpoint.Address != "approved.example" {
		t.Fatal(endpoint)
	}
	if got := policyrule.EgressBypassFQDNs("own", rules.List("own", policyrule.PlaneEgress), assets); !reflect.DeepEqual(got, []string{"approved.example"}) {
		t.Fatal("unexpected repaired bypass", got)
	}
	if got, ok := assets.GetEndpoint("peer", "ordinary"); !ok || got.Address != peer.Address {
		t.Fatal("peer changed")
	}
	final, _ := ap.Load()
	var doc map[string]json.RawMessage
	json.Unmarshal(final, &doc)
	for k, v := range original {
		var beforeValue, afterValue any
		json.Unmarshal(v, &beforeValue)
		json.Unmarshal(doc[k], &afterValue)
		if k != "endpoints" && !reflect.DeepEqual(beforeValue, afterValue) {
			t.Fatal("unrelated catalog field changed", k)
		}
	}
	if deleted, err := rules.DeleteContext(ctx, "own", rule.ID); !deleted || err != nil {
		t.Fatal("cannot remove bypass", deleted, err)
	}
	reload()
	if got := policyrule.EgressBypassFQDNs("own", rules.List("own", policyrule.PlaneEgress), assets); len(got) != 0 {
		t.Fatal("deleted rule resurrected", got)
	}
}
func TestLegacyCertPinRecoveryFile(t *testing.T) {
	dir := t.TempDir()
	checkLegacyCertPinRecovery(t, blobstore.FilePersister{Path: filepath.Join(dir, "assets.json")}, blobstore.FilePersister{Path: filepath.Join(dir, "candidates.json")}, blobstore.FilePersister{Path: filepath.Join(dir, "rules.json")})
}
func TestLegacyCertPinRecoveryPostgres(t *testing.T) {
	d, _, _, _ := trustDistributionPostgresFixture(t)
	p := d.store.(postgresBlobPersister)
	ap, cp, rp := p, p, p
	ap.key = "legacy_recovery_assets"
	cp.key = "legacy_recovery_candidates"
	rp.key = "legacy_recovery_rules"
	checkLegacyCertPinRecovery(t, ap, cp, rp)
}
