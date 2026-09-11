package certreload

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
)

// Management-plane certificate hot-reload (slice 1).
//
// ReloadableCert holds a TLS server certificate that can be swapped from its backing source WITHOUT
// restarting the listener. Every handshake reads the active cert lock-free via GetCertificate; Reload
// re-reads the cert/key and swaps the new pair in atomically — but ONLY if it loads cleanly (the key⇄cert
// match is validated by tls.LoadX509KeyPair). A failed reload keeps the previous good cert (fail-safe), so a
// bad rotation can never brick the link. The backing source is a file path today; the central, versioned
// cert store (slice 2) will reuse the same atomic-swap provider.
type ReloadableCert struct {
	certFile string
	keyFile  string
	current  atomic.Pointer[tls.Certificate]
}

// NewReloadableCert loads the initial cert/key and returns a provider; it errors if the initial load fails
// (the listener must not come up certless).
func NewReloadableCert(certFile, keyFile string) (*ReloadableCert, error) {
	r := &ReloadableCert{certFile: strings.TrimSpace(certFile), keyFile: strings.TrimSpace(keyFile)}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// GetCertificate is the tls.Config callback: it returns the currently active certificate for each handshake,
// so a rotation takes effect on the next connection with no restart.
func (r *ReloadableCert) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c := r.current.Load(); c != nil {
		return c, nil
	}
	return nil, fmt.Errorf("no certificate loaded for %s", r.certFile)
}

// Reload re-reads the cert/key from disk and atomically swaps it in. On any error the previous certificate is
// retained (the caller logs; the link keeps working with the last good material).
func (r *ReloadableCert) Reload() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("reload cert %s/%s: %w", r.certFile, r.keyFile, err)
	}
	r.current.Store(&cert)
	return nil
}

// --- package registry + SIGHUP trigger -------------------------------------------------------------------
// Every listener that serves with a ReloadableCert registers it here; SIGHUP reloads them all at once with no
// restart (the operational trigger until the store-driven admin rotation endpoint lands in slice 2).

var (
	reloadablesMu sync.Mutex
	reloadables   []*ReloadableCert
)

func RegisterReloadable(r *ReloadableCert) {
	reloadablesMu.Lock()
	reloadables = append(reloadables, r)
	reloadablesMu.Unlock()
}

// ReloadAll re-reads every registered cert; returns the count successfully reloaded and the first error.
func ReloadAll() (int, error) {
	reloadablesMu.Lock()
	rs := append([]*ReloadableCert(nil), reloadables...)
	reloadablesMu.Unlock()
	var firstErr error
	n := 0
	for _, r := range rs {
		if err := r.Reload(); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			log.Printf("cert reload FAILED (keeping previous good cert): %v", err)
			continue
		}
		n++
	}
	return n, firstErr
}

var certSignalOnce sync.Once

// InstallSignalHandler arranges for SIGHUP to hot-reload every registered certificate with no
// restart. Idempotent; called once from main before serving.
func InstallSignalHandler() {
	certSignalOnce.Do(func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGHUP)
		go func() {
			for range ch {
				if n, err := ReloadAll(); err != nil {
					log.Printf("SIGHUP cert reload: %d reloaded, error: %v", n, err)
				} else {
					log.Printf("SIGHUP cert reload: %d certificate(s) reloaded with no restart", n)
				}
			}
		}()
	})
}

// CertFile / KeyFile expose the backing file paths (the admin rotation endpoint writes new material to them).
func (r *ReloadableCert) CertFile() string { return r.certFile }
func (r *ReloadableCert) KeyFile() string  { return r.keyFile }

// Registered returns a snapshot of every registered reloadable cert (used by the admin cert inventory).
func Registered() []*ReloadableCert {
	reloadablesMu.Lock()
	defer reloadablesMu.Unlock()
	return append([]*ReloadableCert(nil), reloadables...)
}

// SetRegistryForTest replaces the registry wholesale; tests snapshot/restore around registration to stay
// isolated. Not for production use.
func SetRegistryForTest(rs []*ReloadableCert) {
	reloadablesMu.Lock()
	defer reloadablesMu.Unlock()
	reloadables = append([]*ReloadableCert(nil), rs...)
}

// Current returns the certificate currently being served (nil if none loaded).
func (r *ReloadableCert) Current() *tls.Certificate {
	return r.current.Load()
}
