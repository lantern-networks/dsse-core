package main

import (
	"bytes"
	"encoding/json"
	"github.com/lantern-networks/dsse-core/blobstore"
	"github.com/lantern-networks/dsse-core/model"
	"github.com/lantern-networks/dsse-core/policy"
	"os"
	"path/filepath"
	"testing"
)

func TestPostgresConfiguredDLPReceiverAcceptsBundle(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("requires isolated PostgreSQL")
	}
	db, err := newCPStateBlobDB(dsn, "../../migrations", true)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	old := cpStateBlobDB
	cpStateBlobDB = db
	defer func() { cpStateBlobDB = old }()
	cp := dlpStoresForTest("authority")
	if err := cp.policies.Upsert(model.DLPPolicyObject{ID: "protect", TenantID: "a", Name: "Protect", Identifiers: []string{"credit_card"}, OnMatch: "block", Status: "active"}); err != nil {
		t.Fatal(err)
	}

	author := buildDLPRuntime(serverConfig{})
	for _, p := range []blobstore.Persister{author.policyObjects.persister, author.classifiers.persister, author.fingerprints.persister, author.allowlist.persister} {
		if !isDLPSharedPersister(p) {
			t.Fatal("publishing CP lost shared authority")
		}
	}
	for _, durable := range []bool{false, true} {
		name := "memory"
		if durable {
			name = "local_files"
		}
		t.Run(name, func(t *testing.T) {
			dir := ""
			if durable {
				dir = t.TempDir()
			}
			config := serverConfig{ConfigSourceURL: "https://control.example.invalid"}
			config.DLPPolicyObjectStorePath = configBundleStorePath(dir, config.ConfigSourceURL, "", "dlp_policy_objects")
			config.DLPClassifierStorePath = configBundleStorePath(dir, config.ConfigSourceURL, "", "dlp_classifiers")
			config.DLPFingerprintStorePath = configBundleStorePath(dir, config.ConfigSourceURL, "", "dlp_fingerprints")
			config.DLPAllowlistStorePath = configBundleStorePath(dir, config.ConfigSourceURL, "", "dlp_allowlist")
			config.VLANObjectStorePath = configBundleStorePath(dir, config.ConfigSourceURL, "", "vlan_objects")
			runtime := buildDLPRuntime(config)
			edge := &dlpConfigStores{runtime.policyObjects, runtime.classifiers, runtime.fingerprints, runtime.allowlist}
			networks := buildVLANBoundaryStore(config)
			payload := configBundlePayload{DLP: cp.Snapshot(), VLAN: &vlanBoundaryBundle{Complete: true, Objects: []model.VLANObject{{ID: "network", TenantID: "a", Class: "server", CIDRs: []string{"10.0.0.0/24"}}}}}
			if _, err := (configBundleSource{tenantID: "a"}).apply(payload, configApplyTargets{policyStore: policy.NewStore(nil), dlp: edge, vlan: networks}); err != nil {
				t.Fatal(err)
			}
			if p, ok := edge.policies.Get("a", "protect"); !ok || p.OnMatch != "block" {
				t.Fatal("received DLP protection missing")
			}
			if durable {
				// DLP uses its existing periodic-flush contract. Confirm that flush and
				// a fresh store load retain exactly the received detector library.
				for _, p := range []interface{ PersistIfDirty() error }{runtime.policyObjects, runtime.classifiers, runtime.fingerprints, runtime.allowlist} {
					if err := p.PersistIfDirty(); err != nil {
						t.Fatal(err)
					}
				}
				reloaded := dlpStoresForTest("authority")
				for _, item := range []struct {
					store interface {
						SetPersister(blobstore.Persister) error
					}
					key string
				}{{reloaded.policies, "dlp_policy_objects"}, {reloaded.classifiers, "dlp_classifiers"}, {reloaded.fingerprints, "dlp_fingerprints"}, {reloaded.allowlist, "dlp_allowlist"}} {
					if err := item.store.SetPersister(blobstore.FilePersister{Path: filepath.Join(dir, item.key+".json")}); err != nil {
						t.Fatal(err)
					}
				}
				want, _ := json.Marshal(edge.Snapshot())
				got, _ := json.Marshal(reloaded.Snapshot())
				if !bytes.Equal(want, got) {
					t.Fatalf("cache restart differs: %s / %s", want, got)
				}
			}
		})
	}
}

func TestBundleReceiverRejectsExplicitSharedAuthority(t *testing.T) {
	for _, key := range []string{"dlp_policy_objects", "dlp_classifiers", "dlp_fingerprints", "dlp_allowlist", "vlan_objects", "admin_runtime_state"} {
		for _, value := range []string{"postgres", "postgres+import:local.json"} {
			if _, err := configBundleStorePersister(value, "https://control.example.invalid", key); err == nil {
				t.Fatalf("accepted receiver authority %s %s", key, value)
			}
		}
	}
	old := sharedStateDSNConfigured
	sharedStateDSNConfigured = true
	defer func() { sharedStateDSNConfigured = old }()
	dir := t.TempDir()
	for _, key := range []string{"dlp_policy_objects", "dlp_classifiers", "dlp_fingerprints", "dlp_allowlist", "vlan_objects", "admin_runtime_state"} {
		if got := configBundleStorePath(dir, "https://control.example.invalid", "", key); got != filepath.Join(dir, key+".json") {
			t.Fatal("receiver selected shared authority", got)
		}
		if got := configBundleStorePath(dir, "", "", key); got != "postgres" {
			t.Fatal("author did not retain shared default", got)
		}
	}
}
