package main

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type authorityMemoryCAS struct {
	mu                sync.Mutex
	data              []byte
	readErr, writeErr error
	beforeSave        func()
}

func (b *authorityMemoryCAS) Load() ([]byte, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return bytes.Clone(b.data), b.readErr
}
func (b *authorityMemoryCAS) Save([]byte) error {
	return errors.New("unconditional authority save forbidden")
}
func (b *authorityMemoryCAS) CompareAndSwap(old, next []byte) error {
	b.mu.Lock()
	hook := b.beforeSave
	b.beforeSave = nil
	b.mu.Unlock()
	if hook != nil {
		hook()
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.writeErr != nil {
		return b.writeErr
	}
	if !bytes.Equal(old, b.data) || (old == nil) != (b.data == nil) {
		return errAuthorityConflict
	}
	b.data = bytes.Clone(next)
	return nil
}

type authorityTestClient struct {
	create func(string) error
	rotate func(string) error
	retire func(string) error
	remove func(string) int
	issue  func(string) (string, error)
	parts  func() []string
}

func authorityClient(t *testing.T, kind string, backend authorityCASBackend) authorityTestClient {
	t.Helper()
	p := protectPKIAuthorityPersister(backend, "tenant_"+kind+"_authorities")
	seed, err := p.Load()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now
	switch kind {
	case "transport":
		a := newTenantTransportAuthorityWithReload(seed, p.Save, p.Load, now)
		return authorityTestClient{
			create: func(id string) error { _, e := a.EnsureCA(id, id+".dsse.invalid"); return e },
			rotate: func(id string) error { _, e := a.RotateCA(id); return e },
			retire: func(id string) error { _, e := a.RetirePrevious(id); return e },
			remove: a.RemoveTenant, parts: a.GenerationParts,
			issue: func(id string) (string, error) { m, e := a.IssueFor(id, "edge", time.Hour); return m.AnchorPEM, e },
		}
	case "device":
		a := newTenantDeviceAuthorityWithReload(seed, p.Save, p.Load, now)
		return authorityTestClient{
			create: func(id string) error { _, e := a.EnsureCA(id, id); return e },
			rotate: func(id string) error { _, e := a.RotateCA(id); return e },
			retire: func(id string) error { _, e := a.RetirePrevious(id); return e },
			remove: a.RemoveTenant, parts: a.GenerationParts,
			issue: func(id string) (string, error) { m, e := a.IssueFor(id, time.Hour); return m.CACertPEM, e },
		}
	case "interception":
		a := newTenantInterceptionAuthorityWithReload(seed, p.Save, p.Load, now)
		importCA := func(id string) error {
			root, key := interceptionTestCA(t, id+" root", nil, nil, now())
			cert, issuerKey := interceptionTestCA(t, id+" issuer", root, key, now())
			_, e := a.Import(id, certPEMForTest(root), certPEMForTest(cert), ecKeyPEMForTest(t, issuerKey))
			return e
		}
		return authorityTestClient{
			create: importCA, rotate: importCA,
			retire: func(id string) error { _, e := a.Promote(id); return e },
			remove: a.RemoveTenant, parts: a.GenerationParts,
			issue: func(id string) (string, error) { m, e := a.IssueFor(id, "edge", time.Hour); return m.RootPEM, e },
		}
	}
	t.Fatalf("unknown authority %s", kind)
	return authorityTestClient{}
}

func TestPKISharedAuthorityTransitions(t *testing.T) {
	for _, kind := range []string{"transport", "device", "interception"} {
		t.Run(kind, func(t *testing.T) {
			b := &authorityMemoryCAS{}
			leader := authorityClient(t, kind, b)
			if err := leader.create("tenant_a"); err != nil {
				t.Fatal(err)
			}
			standby := authorityClient(t, kind, b)
			initial := materialFingerprint(standby.parts())
			if err := leader.rotate("tenant_a"); err != nil {
				t.Fatal(err)
			}
			rotated := materialFingerprint(leader.parts())
			if initial == rotated || materialFingerprint(standby.parts()) != rotated {
				t.Fatal("existing row or fingerprint did not refresh after rotation")
			}
			if err := standby.create("tenant_b"); err != nil {
				t.Fatal(err)
			}
			if err := leader.retire("tenant_a"); err != nil {
				t.Fatal("another tenant's write reverted rotation:", err)
			}
			expected, err := leader.issue("tenant_a")
			if err != nil {
				t.Fatal(err)
			}
			actual, err := standby.issue("tenant_a")
			if err != nil || actual != expected {
				t.Fatal("standby issued retired authority", err)
			}
			if leader.remove("tenant_a") != 1 {
				t.Fatal("remove failed")
			}
			if _, err := standby.issue("tenant_a"); err == nil || authorityCouldNotBeAsked(err) {
				t.Fatal("deleted authority remained issuable", err)
			}
			if err := standby.create("tenant_c"); err != nil {
				t.Fatal(err)
			}
			restarted := authorityClient(t, kind, b)
			if _, err := restarted.issue("tenant_a"); err == nil {
				t.Fatal("deleted authority resurrected")
			}
		})
	}
}

func TestPKIConflictRefusesUncommittedAuthority(t *testing.T) {
	for _, kind := range []string{"transport", "device", "interception"} {
		t.Run(kind, func(t *testing.T) {
			b := &authorityMemoryCAS{}
			leader := authorityClient(t, kind, b)
			if err := leader.create("tenant_a"); err != nil {
				t.Fatal(err)
			}
			standby := authorityClient(t, kind, b)
			// Interleave a different CP's rotation between the standby's read and write.
			b.beforeSave = func() {
				if err := leader.rotate("tenant_a"); err != nil {
					t.Fatal(err)
				}
			}
			if err := standby.create("tenant_b"); !errors.Is(err, errAuthorityConflict) {
				t.Fatal("stale write was not rejected", err)
			}
			if _, err := standby.issue("tenant_b"); err == nil {
				t.Fatal("failed creation was issued")
			}
			if err := standby.create("tenant_b"); err != nil {
				t.Fatal("explicit retry did not reload", err)
			}
			if err := leader.retire("tenant_a"); err != nil {
				t.Fatal("conflict reverted another tenant", err)
			}

			// A failed erase must not make the local footprint say that the authority is gone.
			b.writeErr = errors.New("disk unavailable")
			before := materialFingerprint(standby.parts())
			if standby.remove("tenant_b") != 0 {
				t.Fatal("failed erase reported success")
			}
			b.readErr = errors.New("db unavailable")
			if materialFingerprint(standby.parts()) != before {
				t.Fatal("failed erase changed cached committed state")
			}
			if _, err := standby.issue("tenant_b"); !authorityCouldNotBeAsked(err) {
				t.Fatal("unverified cached authority was issued", err)
			}
		})
	}
}

func TestPKICorruptSnapshotRefusesIssuanceAndMutation(t *testing.T) {
	for _, kind := range []string{"transport", "device", "interception"} {
		t.Run(kind, func(t *testing.T) {
			for _, raw := range [][]byte{nil, []byte("null"), []byte("{}"), []byte("[null]"), []byte("[")} {
				b := &authorityMemoryCAS{}
				a := authorityClient(t, kind, b)
				if err := a.create("tenant_a"); err != nil {
					t.Fatal(err)
				}
				before := materialFingerprint(a.parts())
				b.data = raw
				if _, err := a.issue("tenant_a"); !authorityCouldNotBeAsked(err) {
					t.Fatal("invalid snapshot was usable", err)
				}
				if err := a.rotate("tenant_a"); err == nil {
					t.Fatal("invalid snapshot allowed mutation")
				}
				if materialFingerprint(a.parts()) != before {
					t.Fatal("invalid snapshot erased last committed metadata")
				}
			}
		})
	}
}

func TestPKIMaterialRouteRefusesUnavailableStoreBeforeUnchanged(t *testing.T) {
	b := &authorityMemoryCAS{}
	p := &authorityCASPersister{backend: b}
	seed, _ := p.Load()
	a := newTenantTransportAuthorityWithReload(seed, p.Save, p.Load, time.Now)
	if _, err := a.EnsureCA("tenant_a", "a.dsse.invalid"); err != nil {
		t.Fatal(err)
	}
	generation := materialGeneration(a, nil, nil)
	mux := http.NewServeMux()
	registerTenantTransportMaterialRoute(mux, a, nil, nil, "test-token", time.Hour, nil, true)
	b.readErr = errors.New("unavailable")
	req := httptest.NewRequest(http.MethodPost, "/tenant-edge-material", strings.NewReader(fmt.Sprintf(`{"tenants":["tenant_a"],"known_generation":%d}`, generation)))
	req.Header.Set("Authorization", "Bearer test-token")
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, req)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable store returned %d: %s", response.Code, response.Body.String())
	}
}

func TestPKIPostgresCAS(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Separate pools exercise independent CP connections to the same row.
	other, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS cp_state_blobs (store_key text PRIMARY KEY,payload bytea NOT NULL,updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("test_pki_cas_%d", time.Now().UnixNano())
	defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key)
	backends := []postgresBlobPersister{{db: db, key: key}, {db: other, key: key}}
	for _, phase := range []string{"initialization", "update"} {
		t.Run(phase, func(t *testing.T) {
			old, err := backends[0].Load()
			if err != nil {
				t.Fatal(err)
			}
			start := make(chan struct{})
			results := make(chan error, 2)
			for i, p := range backends {
				go func(i int, p postgresBlobPersister) {
					<-start
					results <- p.CompareAndSwap(old, []byte(fmt.Sprintf("%s-%d", phase, i)))
				}(i, p)
			}
			close(start)
			wins, conflicts := 0, 0
			for range backends {
				err := <-results
				if err == nil {
					wins++
				} else if errors.Is(err, errAuthorityConflict) {
					conflicts++
				} else {
					t.Fatal(err)
				}
			}
			if wins != 1 || conflicts != 1 {
				t.Fatalf("wins=%d conflicts=%d", wins, conflicts)
			}
		})
	}
	// Run the actual authority create/rotate/retire sequence through both connections.
	if _, err := db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key); err != nil {
		t.Fatal(err)
	}
	leader := authorityClient(t, "transport", backends[0])
	standby := authorityClient(t, "transport", backends[1])
	if err := leader.create("tenant_a"); err != nil {
		t.Fatal(err)
	}
	if _, err := standby.issue("tenant_a"); err != nil {
		t.Fatal(err)
	}
	if err := leader.rotate("tenant_a"); err != nil {
		t.Fatal(err)
	}
	if err := standby.create("tenant_b"); err != nil {
		t.Fatal(err)
	}
	if err := leader.retire("tenant_a"); err != nil {
		t.Fatal(err)
	}
	expected, _ := leader.issue("tenant_a")
	actual, err := standby.issue("tenant_a")
	if err != nil || actual != expected {
		t.Fatal("postgres standby did not issue committed rotation", err)
	}
}

// Both authorities have read the same committed state before either CAS runs.
type barrierAuthorityBackend struct {
	authorityCASBackend
	arrived chan<- struct{}
	release <-chan struct{}
}

func (b barrierAuthorityBackend) CompareAndSwap(old, next []byte) error {
	b.arrived <- struct{}{}
	<-b.release
	return b.authorityCASBackend.CompareAndSwap(old, next)
}

func TestPKIPostgresConcurrentRotation(t *testing.T) {
	dsn := os.Getenv("POSTGRES_QUEUE_E2E_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_QUEUE_E2E_DSN not set")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	other, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS cp_state_blobs (store_key text PRIMARY KEY,payload bytea NOT NULL,updated_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"transport", "device", "interception"} {
		t.Run(kind, func(t *testing.T) {
			key := fmt.Sprintf("test_pki_parallel_%s_%d", kind, time.Now().UnixNano())
			defer db.Exec("DELETE FROM cp_state_blobs WHERE store_key=$1", key)
			backends := []postgresBlobPersister{{db: db, key: key}, {db: other, key: key}}
			original := authorityClient(t, kind, backends[0])
			if err := original.create("tenant_a"); err != nil {
				t.Fatal(err)
			}
			arrived := make(chan struct{}, 2)
			release := make(chan struct{})
			results := make(chan error, 2)
			for _, backend := range backends {
				client := authorityClient(t, kind, barrierAuthorityBackend{backend, arrived, release})
				go func() { results <- client.rotate("tenant_a") }()
			}
			for range backends {
				select {
				case <-arrived:
				case <-time.After(10 * time.Second):
					close(release)
					t.Fatal("rotation did not reach CAS")
				}
			}
			close(release)
			wins, conflicts := 0, 0
			for range backends {
				select {
				case err := <-results:
					if err == nil {
						wins++
					} else if errors.Is(err, errAuthorityConflict) {
						conflicts++
					} else {
						t.Fatal(err)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("rotation did not finish")
				}
			}
			if wins != 1 || conflicts != 1 {
				t.Fatalf("wins=%d conflicts=%d", wins, conflicts)
			}
			// The persisted winner remains usable and can finish the transition.
			if err := original.retire("tenant_a"); err != nil {
				t.Fatal(err)
			}
			if _, err := original.issue("tenant_a"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPKIMaterialSnapshotKeepsFingerprintAndBothAuthoritiesTogether(t *testing.T) {
	b := &authorityMemoryCAS{}
	p := &authorityCASPersister{backend: b}
	seed, _ := p.Load()
	a := newTenantTransportAuthorityWithReload(seed, p.Save, p.Load, time.Now)
	if _, err := a.EnsureCA("tenant_a", "a.dsse.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RotateCA("tenant_a"); err != nil {
		t.Fatal(err)
	}
	snapshot, err := a.materialSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	generation := materialGeneration(snapshot, nil, nil)
	if _, err := a.RetirePrevious("tenant_a"); err != nil {
		t.Fatal(err)
	}
	materials, err := snapshot.IssueAllFor("tenant_a", "edge", time.Hour)
	if err != nil || len(materials) != 2 {
		t.Fatal("response mixed states across retirement", err)
	}
	if materialGeneration(snapshot, nil, nil) != generation || materialGeneration(a, nil, nil) == generation {
		t.Fatal("fingerprint did not describe its snapshot")
	}
}

func TestPKIConcurrentLocalRenameAndIssue(t *testing.T) {
	a := newTenantTransportAuthority(nil, nil, time.Now)
	if _, err := a.EnsureCA("tenant_a", "a.dsse.invalid"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RotateCA("tenant_a"); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		for i := 0; i < 20; i++ {
			if _, err := a.RenameServerName("tenant_a", fmt.Sprintf("a%d.dsse.invalid", i)); err != nil {
				done <- err
				return
			}
			if _, err := a.RetirePreviousServerName("tenant_a"); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 20; i++ {
		mats, err := a.IssueAllFor("tenant_a", "edge", time.Hour)
		if err != nil || len(mats) != 2 {
			t.Fatal("issue failed", err)
		}
		if mats[0].ServerName != mats[1].ServerName {
			t.Fatal("one response mixed two rename states")
		}
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestPKIRuntimeLoaderRejectsCorruptSeed(t *testing.T) {
	for _, kind := range []string{"transport", "device", "interception"} {
		for _, raw := range []string{"null", "{}", "[null]", "[{}]", "[{\"tenant_id\":\"a\"},{\"tenant_id\":\" A \"}]"} {
			b := &authorityMemoryCAS{data: []byte(raw)}
			p := protectPKIAuthorityPersister(b, "tenant_"+kind+"_authorities")
			if _, err := p.Load(); err == nil {
				t.Fatalf("%s accepted corrupt initial snapshot", kind)
			}
		}
	}
}
