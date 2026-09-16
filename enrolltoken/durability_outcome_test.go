package enrolltoken

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Model both possible restart outcomes after an unconfirmed flush. This is not
// a power-loss test: pending is visible to Save, data is what a new Store reads.
type durabilityPersister struct {
	data, pending []byte
	err           error
	retained      bool
	saves         int
}

func (p *durabilityPersister) Load() ([]byte, error) { return bytes.Clone(p.data), nil }
func (p *durabilityPersister) Save(b []byte) error {
	p.saves++
	p.pending = bytes.Clone(b)
	if p.err == nil || p.retained {
		p.data = bytes.Clone(b)
	}
	return p.err
}

func TestTokenMutationDistinguishesDurableSaveFromUnconfirmedFlush(t *testing.T) {
	// FilePersister's compatibility warning matches BOTH sentinels. Checking
	// only the legacy sentinel would acknowledge an unconfirmed credential change.
	bridge := errors.Join(blobstore.ErrSavedWithoutAtomicity, blobstore.ErrDurabilityUnconfirmed)
	for _, outcome := range []struct {
		name               string
		err                error
		retained, accepted bool
	}{
		{"atomic", nil, true, true},
		{"synced_in_place", blobstore.ErrSavedWithoutAtomicity, true, true},
		{"wrapped_synced_in_place", fmt.Errorf("save: %w", blobstore.ErrSavedWithoutAtomicity), true, true},
		{"unconfirmed_lost", blobstore.ErrDurabilityUnconfirmed, false, false},
		{"unconfirmed_retained", blobstore.ErrDurabilityUnconfirmed, true, false},
		{"bridge_lost", bridge, false, false},
		{"bridge_retained", bridge, true, false},
		{"wrapped_bridge_lost", fmt.Errorf("save: %w", bridge), false, false},
		{"wrapped_bridge_retained", fmt.Errorf("save: %w", bridge), true, false},
	} {
		for _, op := range []string{"issue", "consume", "spend", "revoke", "remove"} {
			t.Run(outcome.name+"/"+op, func(t *testing.T) {
				p := &durabilityPersister{}
				s := NewStore()
				s.SetPersister(p)
				now := time.Now().UTC()
				tok, secret, err := s.Issue(DefaultPolicy(), "tenant", "", "label", "admin", "", now.Add(time.Hour), now)
				if err != nil {
					t.Fatal(err)
				}
				if _, _, err := s.Issue(DefaultPolicy(), "foreign", "", "control", "admin", "", now.Add(time.Hour), now); err != nil {
					t.Fatal(err)
				}
				before, foreign, generation := s.List("tenant"), s.List("foreign"), s.Generation()
				p.err, p.retained = outcome.err, outcome.retained
				var accepted bool
				switch op {
				case "issue":
					issued, raw, err := s.Issue(DefaultPolicy(), "tenant", "", "second", "admin", "", now.Add(time.Hour), now)
					accepted = err == nil
					if !outcome.accepted && (raw != "" || issued.ID != "" || !errors.Is(err, ErrStateUnavailable)) {
						t.Fatal("uncertain issue disclosed credential or wrong error")
					}
				case "consume", "spend":
					var err error
					if op == "consume" {
						_, err = s.Consume(secret, "tenant", "device", now)
					} else {
						_, err = s.Spend(tok.ID, "tenant", "device", now)
					}
					accepted = err == nil
					if !outcome.accepted && !errors.Is(err, ErrStateUnavailable) {
						t.Fatal("uncertain use returned wrong error")
					}
				case "revoke":
					_, accepted = s.Revoke(tok.ID, "admin", now)
				case "remove":
					accepted = s.RemoveTenant("tenant") == 1
				}
				if accepted != outcome.accepted {
					t.Fatalf("accepted=%v; want %v", accepted, outcome.accepted)
				}
				if !reflect.DeepEqual(foreign, s.List("foreign")) {
					t.Fatal("changed foreign tenant")
				}
				if outcome.accepted {
					if s.Health() != nil || s.Generation() != generation+1 {
						t.Fatal("completed save not published")
					}
				} else {
					if !errors.Is(s.Health(), ErrStateUnavailable) || s.Generation() != generation || !reflect.DeepEqual(before, s.List("tenant")) {
						t.Fatal("unconfirmed state published or not latched")
					}
					writes := p.saves
					p.err = nil // Restoring storage alone must not resume this process.
					if _, err := s.Verify(secret, "tenant", now); !errors.Is(err, ErrStateUnavailable) {
						t.Fatal("verify ignored latch")
					}
					if _, err := s.Consume(secret, "tenant", "other", now); !errors.Is(err, ErrStateUnavailable) {
						t.Fatal("consume ignored latch")
					}
					if _, err := s.Spend(tok.ID, "tenant", "other", now); !errors.Is(err, ErrStateUnavailable) {
						t.Fatal("spend ignored latch")
					}
					if _, raw, err := s.Issue(DefaultPolicy(), "tenant", "", "retry", "admin", "", now.Add(time.Hour), now); !errors.Is(err, ErrStateUnavailable) || raw != "" {
						t.Fatal("issue ignored latch")
					}
					if _, ok := s.Revoke(tok.ID, "admin", now); ok {
						t.Fatal("revoke ignored latch")
					}
					if s.RemoveTenant("tenant") != 0 || p.saves != writes {
						t.Fatal("retry overwrote uncertain state")
					}
				}
				reopened := NewStore()
				reopened.SetPersister(p)
				if reopened.Health() != nil || !reflect.DeepEqual(foreign, reopened.List("foreign")) {
					t.Fatal("restart state invalid")
				}
				_, verifyErr := reopened.Verify(secret, "tenant", now)
				if (verifyErr == nil) != (!outcome.retained || op == "issue") {
					t.Fatal("restart token usability differs from modeled durable outcome")
				}
				if outcome.retained {
					switch op {
					case "issue":
						if len(reopened.List("tenant")) != 2 {
							t.Fatal("retained issuance missing")
						}
					case "consume", "spend":
						if !errors.Is(verifyErr, ErrTokenUsed) {
							t.Fatalf("expected spent token: %v", verifyErr)
						}
					case "revoke":
						if reopened.List("tenant")[0].RevokedAt == "" {
							t.Fatal("retained revocation missing")
						}
					case "remove":
						if len(reopened.List("tenant")) != 0 {
							t.Fatal("retained removal missing")
						}
					}
				} else if !reflect.DeepEqual(before, reopened.List("tenant")) {
					t.Fatal("unretained mutation appeared on restart")
				}
			})
		}
	}
}
