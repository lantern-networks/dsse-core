package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/agentpolicy"
	"github.com/lantern-networks/dsse-core/grantstore"
)

type grantPageSharedAuthority struct {
	mu   sync.Mutex
	raw  []byte
	fail bool
}

func (p *grantPageSharedAuthority) Load() ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail {
		return nil, fmt.Errorf("authority unavailable")
	}
	return append([]byte(nil), p.raw...), nil
}

func (p *grantPageSharedAuthority) Save(raw []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.raw = append([]byte(nil), raw...)
	return nil
}

func (p *grantPageSharedAuthority) UpdateContext(ctx context.Context, edit func([]byte) ([]byte, error)) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	next, err := edit(p.raw)
	if err == nil {
		p.raw = append([]byte(nil), next...)
	}
	return err
}

func TestGrantPagesRefreshRevocationAndRefuseUnavailableAuthority(t *testing.T) {
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	p := &grantPageSharedAuthority{}
	authority, peer := grantstore.NewStore(), grantstore.NewStore()
	for _, s := range []*grantstore.Store{authority, peer} {
		if err := s.SetPersister(p); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	rows := make([]grantstore.Grant, 0, 1800)
	for i := 0; i < 1800; i++ {
		rows = append(rows, grantstore.Grant{GrantID: fmt.Sprintf("grant-%04d", i), TenantID: "tenant",
			UserID: "user", IdPID: "idp", Scope: "app:22", IssuedAt: now.Format(time.RFC3339),
			ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	}
	if _, _, err := authority.MergeAuthorityEvidence(rows, now); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerGrantBundlePages(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
		func() *grantstore.Store { return authority }, signer, "epoch-one", "", true)
	request := func(offset int, generation uint64) int {
		t.Helper()
		url := fmt.Sprintf("/admin/grant-bundle-page?protocol=%s&epoch=epoch-one&generation=%d&offset=%d", grantPageProtocol, generation, offset)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, url, nil))
		return w.Code
	}
	initialGeneration := authority.ConfigGeneration()
	if got := request(0, initialGeneration); got != http.StatusOK {
		t.Fatalf("initial grant page: status %d", got)
	}
	if _, _, err := peer.RequireReauthenticationForTenantContext(context.Background(), "tenant", rows[0].GrantID, now); err != nil {
		t.Fatal(err)
	}
	if got := request(0, initialGeneration); got != http.StatusOK {
		t.Fatalf("new request did not refresh peer revocation: status %d", got)
	}
	newGeneration := authority.ConfigGeneration()
	if got := request(0, newGeneration); got != http.StatusOK {
		t.Fatalf("new generation after revocation: status %d", got)
	}
	p.mu.Lock()
	p.fail = true
	p.mu.Unlock()
	if got := request(0, newGeneration); got != http.StatusServiceUnavailable {
		t.Fatalf("unavailable shared authority served cached grants: status %d", got)
	}
}

func TestSignedGrantPagesCarryLargeFleetAndRevocation(t *testing.T) {
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	authority, edge := grantstore.NewStore(), grantstore.NewStore()
	now := time.Now().UTC()
	rows := make([]grantstore.Grant, 0, 1800)
	for i := 0; i < 1800; i++ {
		rows = append(rows, grantstore.Grant{GrantID: fmt.Sprintf("grant-%04d", i), TenantID: "tenant",
			UserID: "user", IdPID: "idp", Scope: "app:22", IssuedAt: now.Format(time.RFC3339),
			ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	}
	if _, _, err := authority.MergeAuthorityEvidence(rows, now); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerGrantBundlePages(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
		func() *grantstore.Store { return authority }, signer, "epoch-one", "", true)
	pages := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(&grantPageFlushWriter{ResponseWriter: w, after: func() { pages++ }}, r)
	}))
	defer server.Close()
	source := configBundleSource{url: server.URL, client: server.Client(), verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true}
	ref := grantBundleReference{Protocol: grantPageProtocol, Epoch: "epoch-one", Generation: authority.ConfigGeneration()}
	section, err := source.fetchGrantPages(context.Background(), ref)
	if err != nil || pages < 2 || len(section.Grants) != len(rows) {
		t.Fatalf("large signed snapshot: pages=%d grants=%d err=%v", pages, len(section.Grants), err)
	}
	if _, _, err := applyGrantBundleEvidence(edge, section, now, true); err != nil || !edge.Valid(rows[0].GrantID, now) {
		t.Fatalf("Edge did not receive first signed grant: %v", err)
	}
	if _, _, err := authority.RequireReauthenticationForTenantContext(context.Background(), "tenant", rows[0].GrantID, now); err != nil {
		t.Fatal(err)
	}
	ref.Generation = authority.ConfigGeneration()
	section, err = source.fetchGrantPages(context.Background(), ref)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := applyGrantBundleEvidence(edge, section, now, true); err != nil || edge.Valid(rows[0].GrantID, now) {
		t.Fatalf("signed revocation did not reach Edge: %v", err)
	}
}

func TestGrantPageSnapshotSurvivesWritesWithoutRevivingKnownRevocation(t *testing.T) {
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	store := grantstore.NewStore()
	now := time.Now().UTC()
	rows := make([]grantstore.Grant, 0, 1800)
	for i := 0; i < 1800; i++ {
		rows = append(rows, grantstore.Grant{GrantID: fmt.Sprintf("grant-%04d", i), TenantID: "tenant",
			UserID: "user", IdPID: "idp", Scope: "app:22", IssuedAt: now.Format(time.RFC3339),
			ExpiresAt: now.Add(time.Hour).Format(time.RFC3339)})
	}
	if _, _, err := store.MergeAuthorityEvidence(rows, now); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerGrantBundlePages(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
		func() *grantstore.Store { return store }, signer, "epoch-one", "", true)
	edge := grantstore.NewStore()
	mutated := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mux.ServeHTTP(&grantPageFlushWriter{ResponseWriter: w, after: func() {
			if mutated {
				return
			}
			mutated = true
			if _, _, err := store.RequireReauthenticationForTenantContext(context.Background(), "tenant", rows[0].GrantID, now); err != nil {
				t.Error(err)
				return
			}
			denial, _ := store.Get(rows[0].GrantID)
			if _, _, err := edge.MergeAuthorityEvidence([]grantstore.Grant{denial}, now); err != nil {
				t.Error(err)
			}
		}}, r)
	}))
	ref := grantBundleReference{Protocol: grantPageProtocol, Epoch: "epoch-one", Generation: store.ConfigGeneration()}
	source := configBundleSource{url: server.URL, client: server.Client(), verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true}
	section, err := source.fetchGrantPages(context.Background(), ref)
	if err != nil || section == nil || len(section.Grants) != len(rows) || section.generation != ref.Generation {
		t.Fatalf("immutable snapshot failed during a revocation: %v", err)
	}
	if _, _, err := applyGrantBundleEvidence(edge, section, now, true); err != nil || edge.Valid(rows[0].GrantID, now) {
		t.Fatalf("older stream revived a concurrently received revocation: %v", err)
	}
	section, err = source.fetchGrantPages(context.Background(), ref)
	if err != nil || section.generation <= ref.Generation || len(section.ProtectedGrants) != 1 || !section.ProtectedGrants[0].Revoked {
		t.Fatalf("next snapshot omitted the newer revocation: %v", err)
	}
	server.Close()

	// A signed page's offset and grant rows are both integrity-protected. A
	// proxy that alters either cannot make the Edge acknowledge a generation.
	page, err := makeGrantBundlePage(rows[:1], ref, 0)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := signer.Sign(page, now)
	if err != nil {
		t.Fatal(err)
	}
	tampered, _ := json.Marshal(envelope)
	var object map[string]any
	if err := json.Unmarshal(tampered, &object); err != nil {
		t.Fatal(err)
	}
	object["signature"] = "invalid"
	tampered, _ = json.Marshal(object)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(tampered)
	}))
	defer proxy.Close()
	source.url, source.client = proxy.URL, proxy.Client()
	if section, err := source.fetchGrantPages(context.Background(), ref); err == nil || section != nil {
		t.Fatal("altered signed page was accepted")
	}
}

func TestGrantPagePayloadIsBoundedWithoutGrantCountQuota(t *testing.T) {
	ref := grantBundleReference{Protocol: grantPageProtocol, Epoch: "epoch", Generation: 7}
	rows := make([]grantstore.Grant, 4000)
	for i := range rows {
		rows[i] = grantstore.Grant{GrantID: strconv.Itoa(i), TenantID: "tenant", UserID: "user", IdPID: "idp"}
	}
	page, err := makeGrantBundlePage(rows, ref, 0)
	if err != nil || page.NextOffset >= len(rows) || page.NextOffset == 0 {
		t.Fatalf("page did not split by encoded bytes: next=%d err=%v", page.NextOffset, err)
	}
	for at := page.NextOffset; at < len(rows); {
		page, err = makeGrantBundlePage(rows, ref, at)
		if err != nil || page.NextOffset <= at {
			t.Fatalf("pagination stalled at %d: %v", at, err)
		}
		at = page.NextOffset
	}
}

func TestGrantPageIsNotServedByAnEdge(t *testing.T) {
	signer, err := agentpolicy.LoadOrGenerateSigner("", true)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerGrantBundlePages(mux, func(_ string, h http.HandlerFunc) http.HandlerFunc { return h },
		grantstore.NewStore, signer, "epoch", "", false)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet,
		"/admin/grant-bundle-page?protocol=grant-pages-v1&epoch=epoch&generation=0&offset=0", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("Edge exposed the CP grant page route: status %d", w.Code)
	}
}

// Flush exposes the boundary between encoded pages without changing the server's
// snapshot. Tests inject writes at this boundary instead of racing wall clocks.
type grantPageFlushWriter struct {
	http.ResponseWriter
	after func()
}

func (w *grantPageFlushWriter) Flush() {
	if w.after != nil {
		w.after()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func TestGrantPageStreamRefusesIncompleteMixedAndOversizedInput(t *testing.T) {
	signer := testAgentPolicySigner(t)
	ref := grantBundleReference{Protocol: grantPageProtocol, Epoch: "epoch", Generation: 7}
	page := grantBundlePage{Protocol: grantPageProtocol, Epoch: ref.Epoch, Generation: 8,
		Offset: 0, NextOffset: 1, Total: 2, Grants: &grantBundle{Complete: true, Grants: []grantstore.Grant{{GrantID: "first"}}}}
	encode := func(p grantBundlePage) []byte {
		t.Helper()
		e, err := signer.Sign(p, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(e)
		return append(b, '\n')
	}
	first := encode(page)
	page.Offset, page.NextOffset = 1, 2
	second := encode(page)
	mixed := page
	mixed.Generation++
	reordered := page
	reordered.Offset = 0
	old := page
	old.Generation = ref.Generation - 1
	cases := map[string][]byte{
		"empty": nil, "truncated": first, "mixed-generation": append(append([]byte{}, first...), encode(mixed)...),
		"reordered":      append(append([]byte{}, first...), encode(reordered)...),
		"old-generation": encode(old), "oversized": bytes.Repeat([]byte("x"), grantPageBodyBytes+1),
		"trailing": append(append(append([]byte{}, first...), second...), second...),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(body) }))
			defer server.Close()
			source := configBundleSource{url: server.URL, client: server.Client(), verifyPubKeyHex: signer.PublicKeyHex()}
			if got, err := source.fetchGrantPages(context.Background(), ref); err == nil || got != nil {
				t.Fatal("invalid stream was accepted")
			}
		})
	}
}

func TestGrantPageStreamUsesPageProgressDeadlineAndParentCancellation(t *testing.T) {
	signer := testAgentPolicySigner(t)
	ref := grantBundleReference{Protocol: grantPageProtocol, Epoch: "epoch", Generation: 1}
	const pageCount = 6
	encoded := make([][]byte, pageCount)
	for i := range encoded {
		page := grantBundlePage{Protocol: grantPageProtocol, Epoch: ref.Epoch, Generation: ref.Generation,
			Offset: i, NextOffset: i + 1, Total: pageCount,
			Grants: &grantBundle{Complete: true, Grants: []grantstore.Grant{{GrantID: strconv.Itoa(i)}}}}
		env, err := signer.Sign(page, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		encoded[i], _ = json.Marshal(env)
		encoded[i] = append(encoded[i], '\n')
	}
	for _, mode := range []string{"progress", "stalled", "parent-cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for i, body := range encoded {
					if i > 0 && mode == "stalled" {
						<-r.Context().Done()
						return
					}
					select {
					case <-time.After(40 * time.Millisecond):
					case <-r.Context().Done():
						return
					}
					_, _ = w.Write(body)
					w.(http.Flusher).Flush()
					if mode == "parent-cancel" {
						cancel()
						return
					}
				}
			}))
			defer server.Close()
			client := server.Client()
			client.Timeout = 150 * time.Millisecond
			source := configBundleSource{url: server.URL, client: client, verifyPubKeyHex: signer.PublicKeyHex(), requireSigned: true}
			began := time.Now()
			got, err := source.fetchGrantPages(ctx, ref)
			if mode == "progress" {
				if err != nil || got == nil || len(got.Grants) != pageCount || time.Since(began) <= client.Timeout {
					t.Fatalf("progressing stream was bounded by total transfer time: %v", err)
				}
			} else if err == nil || got != nil {
				t.Fatal("incomplete stalled/cancelled snapshot was accepted")
			}
			if client.Timeout != 150*time.Millisecond {
				t.Fatal("ordinary client timeout changed")
			}
		})
	}
}
