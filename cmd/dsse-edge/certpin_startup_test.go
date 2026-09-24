package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/assetcatalog"
	"github.com/lantern-networks/dsse-core/policycandidate"
	"github.com/lantern-networks/dsse-core/policyrule"
)

// This subprocess runs main, including persisted stores and the initial inspection
// apply. It must not derive new authored intent from a candidate's historical status.
func TestCertPinProductionStartupKeepsAuthoredIntent(t *testing.T) {
	if path := os.Getenv("DSSE_CERTPIN_STARTUP_ARGS"); path != "" {
		var args []string
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &args); err != nil {
			t.Fatal(err)
		}
		flag.CommandLine = flag.NewFlagSet("edge", flag.ExitOnError)
		os.Args = append([]string{os.Args[0]}, args...)
		main()
		return
	}
	for _, sourced := range []bool{false, true} {
		name := "local"
		if sourced {
			name = "configuration-pulling"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			seedCertPinStartup(t, dir)
			saved := map[string][]byte{}
			for _, name := range []string{"candidates", "assets", "rules"} {
				b, e := os.ReadFile(filepath.Join(dir, name+".json"))
				if e != nil {
					t.Fatal(e)
				}
				saved[name] = b
			}
			for restart := 0; restart < 2; restart++ {
				base, stop := startCertPinMain(t, dir, sourced)
				var rows effectiveEgressRuleListResponse
				certPinStartupGet(t, base, "/admin/egress-effective-rules", &rows)
				for _, row := range rows.Rules {
					if row.Kind == "cert_pin_bypass" {
						t.Errorf("candidate history became an active row: %+v", row)
					}
				}
				for _, name := range []string{"active", "disabled", "inspect", "deleted", "legacy", "partial", "foreign"} {
					var result effectivePolicyResponse
					certPinStartupGet(t, base, "/admin/effective-policy?destination="+name+".startup.example", &result)
					want := "inspect"
					if name == "active" {
						want = "bypass"
					}
					if result.Inspection.Decision != want {
						t.Errorf("restart %d %s: %+v, want %s", restart, name, result.Inspection, want)
					}
				}
				stop()
				for name, want := range saved {
					got, e := os.ReadFile(filepath.Join(dir, name+".json"))
					if e != nil {
						t.Fatal(e)
					}
					if !bytes.Equal(got, want) {
						t.Errorf("restart %d rewrote %s", restart, name)
					}
				}
			}
		})
	}
}

func seedCertPinStartup(t *testing.T, dir string) {
	t.Helper()
	write := func(name string, v any) {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(dir, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write("policy.json", map[string]any{"id": "pol-startup", "tenant_id": "startup-own", "name": "local startup check", "priority": 100, "status": "active", "conditions": map[string]any{"actor_type": "human"}, "action": map[string]any{"decision": "allow"}})
	write("bundle.json", map[string]any{"id": "pb-startup", "tenant_id": "startup-own", "version": "1", "policy_schema_version": "2026.05.22", "checksum": "sha256:mock-checksum", "signature": "mock-signature", "signing_key_id": "mock-local-signing-key", "target_scope": map[string]any{"target_type": "local_edge", "edge_region_id": "region-a", "edge_cluster_id": "local-edge-001"}, "policy_ids": []string{"pol-startup"}, "compiled_policy_ref": "policy.json", "bundle_type": "standard", "created_at": "2026-01-01T00:00:00Z", "expires_at": "2036-01-01T00:00:00Z", "status": "active"})
	candidates := policycandidate.NewStore()
	assets := assetcatalog.NewStore()
	rules := policyrule.NewStore()
	for _, err := range []error{candidates.SetStatePath(filepath.Join(dir, "candidates.json")), assets.SetStatePath(filepath.Join(dir, "assets.json")), rules.SetStatePath(filepath.Join(dir, "rules.json"))} {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"active", "disabled", "inspect", "deleted", "legacy", "partial", "foreign"} {
		owner := "startup-own"
		if name == "foreign" {
			owner = "startup-other"
		}
		c, e := candidates.AddManualCertPinBypass(context.Background(), owner, name+".startup.example", time.Now())
		if e != nil {
			t.Fatal(e)
		}
		c, _, e = candidates.Materialize(context.Background(), owner, c.CandidateID, false, time.Now())
		if e != nil {
			t.Fatal(e)
		}
		if name == "legacy" {
			continue
		}
		if name == "partial" {
			// Earlier candidate/endpoint saves succeeded; the rule save was refused.
			failed := policyrule.NewStore()
			if e := failed.SetPersister(&certPinRefuseSave{}); e != nil {
				t.Fatal(e)
			}
			if e := emitCertPinBypassRule(assets, failed, c); e == nil {
				t.Fatal("expected rule failure")
			}
			continue
		}
		if e := emitCertPinBypassRule(assets, rules, c); e != nil {
			t.Fatal(e)
		}
		id := "certpin-rule-" + c.CandidateID
		if name == "deleted" {
			if _, e := rules.Delete(owner, id); e != nil {
				t.Fatal(e)
			}
		}
		if name == "disabled" || name == "inspect" {
			r, _ := rules.Get(owner, id)
			if name == "disabled" {
				r.Status = "disabled"
			} else {
				r.Action.Inspection = "inspect"
			}
			if _, e := rules.Upsert(r); e != nil {
				t.Fatal(e)
			}
		}
	}
}

type certPinRefuseSave struct{}

func (*certPinRefuseSave) Load() ([]byte, error) { return nil, nil }
func (*certPinRefuseSave) Save([]byte) error     { return errors.New("injected rule-save refusal") }

func startCertPinMain(t *testing.T, dir string, sourced bool, extraArgs ...string) (string, func()) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	addr := l.Addr().String()
	l.Close()
	module, e := filepath.Abs("../..")
	if e != nil {
		t.Fatal(e)
	}
	args := []string{"-listen", addr, "-no-control-plane", "-lab-mode", "-policy", filepath.Join(dir, "policy.json"), "-bundle", filepath.Join(dir, "bundle.json"), "-schema-dir", filepath.Join(module, "schemas"), "-log-dir", filepath.Join(dir, "logs"), "-edge-region-id", "region-a", "-admin-token", "startup-test-token", "-admin-token-break-glass-armed", "-policy-candidate-store", filepath.Join(dir, "candidates.json"), "-asset-catalog-store", filepath.Join(dir, "assets.json"), "-policy-rule-store", filepath.Join(dir, "rules.json"), "-network-extension-runtime-copy-lab-tls-interception-hosts", "*"}
	args = append(args, extraArgs...)
	if sourced {
		args = append(args, "-config-source-url", "http://127.0.0.1:1")
	}
	argsPath := filepath.Join(dir, "args.json")
	b, _ := json.Marshal(args)
	if e = os.WriteFile(argsPath, b, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCertPinProductionStartupKeepsAuthoredIntent$")
	cmd.Env = append(os.Environ(), "DSSE_CERTPIN_STARTUP_ARGS="+argsPath)
	f, e := os.Create(filepath.Join(dir, "process.log"))
	if e != nil {
		cancel()
		t.Fatal(e)
	}
	cmd.Stdout = f
	cmd.Stderr = f
	if e := cmd.Start(); e != nil {
		cancel()
		f.Close()
		t.Fatal(e)
	}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		cancel()
		cmd.Wait()
		f.Close()
	}
	t.Cleanup(stop)
	base := "https://" + addr
	client := certPinStartupClient()
	for deadline := time.Now().Add(12 * time.Second); time.Now().Before(deadline); time.Sleep(30 * time.Millisecond) {
		resp, e := client.Get(base + "/healthz")
		if e == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return base, stop
			}
		}
	}
	stop()
	out, _ := os.ReadFile(filepath.Join(dir, "process.log"))
	t.Fatalf("main did not start: %s", out)
	return "", nil
}
func certPinStartupGet(t *testing.T, base, path string, out any) {
	t.Helper()
	req, e := http.NewRequest("GET", base+path, nil)
	if e != nil {
		t.Fatal(e)
	}
	req.Header.Set("Authorization", "Bearer startup-test-token")
	resp, e := certPinStartupClient().Do(req)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	b, e := io.ReadAll(resp.Body)
	if e != nil {
		t.Fatal(e)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: %d %s", path, resp.StatusCode, b)
	}
	if e = json.Unmarshal(b, out); e != nil {
		t.Fatal(e)
	}
}

func TestCertPinCandidateHistoryIsNotAnEffectiveRule(t *testing.T) {
	f := newCertPinPartialFixture(t, &candidateNthPersister{}, &candidateNthPersister{}, &candidateNthPersister{}, "")
	if w := f.post("/admin/cert-pin-bypass", `{"host":"manual.example"}`); w.Code != 200 {
		t.Fatal(w.Code)
	}
	before, _, _ := f.candidates.Get(context.Background(), f.tenant, f.candidate.CandidateID)
	for _, change := range []string{"disabled", "inspect", "deleted"} {
		t.Run(change, func(t *testing.T) {
			if e := emitCertPinBypassRule(f.assets, f.rules, before); e != nil {
				t.Fatal(e)
			}
			id := "certpin-rule-" + before.CandidateID
			if change == "deleted" {
				f.rules.Delete(f.tenant, id)
			} else {
				r, _ := f.rules.Get(f.tenant, id)
				if change == "disabled" {
					r.Status = "disabled"
				} else {
					r.Action.Inspection = "inspect"
				}
				if _, e := f.rules.Upsert(r); e != nil {
					t.Fatal(e)
				}
			}
			req := httptest.NewRequest("GET", "/admin/egress-effective-rules", nil)
			req.AddCookie(&http.Cookie{Name: "admin_session", Value: "pin-session"})
			w := httptest.NewRecorder()
			f.handler.ServeHTTP(w, req)
			if w.Code != 200 {
				t.Fatal(w.Code, w.Body)
			}
			var result effectiveEgressRuleListResponse
			if e := json.Unmarshal(w.Body.Bytes(), &result); e != nil {
				t.Fatal(e)
			}
			for _, r := range result.Rules {
				if r.Kind == "cert_pin_bypass" {
					t.Error("history became phantom bypass", r)
				}
			}
			after, _, _ := f.candidates.Get(context.Background(), f.tenant, f.candidate.CandidateID)
			if !reflect.DeepEqual(before, after) {
				t.Error("read changed history")
			}
		})
	}
}

// Only connects to the subprocess loopback listener, whose lab certificate is ephemeral.
func certPinStartupClient() *http.Client {
	return &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, DisableKeepAlives: true}}
}
