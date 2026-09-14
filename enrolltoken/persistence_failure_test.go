package enrolltoken

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

type failurePersister struct {
	data            []byte
	fail, uncertain bool
}

func (p *failurePersister) Load() ([]byte, error) { return bytes.Clone(p.data), nil }
func (p *failurePersister) Save(b []byte) error {
	if !p.fail || p.uncertain {
		p.data = bytes.Clone(b)
	}
	if p.fail {
		return errors.New("synthetic save failure")
	}
	return nil
}
func TestPersistenceFailureNeverAcknowledgesTokenMutation(t *testing.T) {
	for _, op := range []string{"issue", "consume", "revoke", "remove"} {
		for _, uncertain := range []bool{false, true} {
			t.Run(op+map[bool]string{false: "/unsaved", true: "/uncertain"}[uncertain], func(t *testing.T) {
				p := &failurePersister{}
				s := NewStore()
				s.SetPersister(p)
				now := time.Now().UTC()
				tok, secret, err := s.Issue(DefaultPolicy(), "tenant", "", "label", "admin", "", now.Add(time.Hour), now)
				if err != nil {
					t.Fatal(err)
				}
				generation := s.Generation()
				before := s.List("tenant")
				p.fail = true
				p.uncertain = uncertain
				switch op {
				case "issue":
					_, raw, err := s.Issue(DefaultPolicy(), "tenant", "", "second", "admin", "", now.Add(time.Hour), now)
					if !errors.Is(err, ErrStateUnavailable) || raw != "" {
						t.Fatal("issue acknowledged failed save")
					}
				case "consume":
					if _, err := s.Consume(secret, "tenant", "device", now); !errors.Is(err, ErrStateUnavailable) {
						t.Fatal("consume acknowledged failed save")
					}
				case "revoke":
					if _, ok := s.Revoke(tok.ID, "admin", now); ok {
						t.Fatal("revoke acknowledged failed save")
					}
				case "remove":
					if n := s.RemoveTenant("tenant"); n != 0 {
						t.Fatal("remove acknowledged failed save")
					}
				}
				if s.Generation() != generation || len(s.List("tenant")) != 1 || s.List("tenant")[0] != before[0] {
					t.Fatal("failed save published state")
				}
				if !errors.Is(s.Health(), ErrStateUnavailable) {
					t.Fatal("failure not latched")
				}
				p.fail = false
				if _, err := s.Verify(secret, "tenant", now); !errors.Is(err, ErrStateUnavailable) {
					t.Fatal("verify ignored failed state")
				}
				if _, err := s.Spend(tok.ID, "tenant", "other", now); !errors.Is(err, ErrStateUnavailable) {
					t.Fatal("spend ignored failed state")
				}
				if _, _, err := s.Issue(DefaultPolicy(), "tenant", "", "new", "admin", "", now.Add(time.Hour), now); !errors.Is(err, ErrStateUnavailable) {
					t.Fatal("issue ignored failed state")
				}
				reloaded := NewStore()
				reloaded.SetPersister(p)
				_, err = reloaded.Verify(secret, "tenant", now)
				// A failed Save can have committed. No success was returned in either case.
				if uncertain && op != "issue" {
					if err == nil {
						t.Fatal("committed removal/spend/revoke lost on reload")
					}
				} else if err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

type loadFailurePersister struct{}

func (loadFailurePersister) Load() ([]byte, error) { return nil, errors.New("read failure") }
func (loadFailurePersister) Save([]byte) error     { return errors.New("must not save") }
func TestInvalidLoadedTokenStateStopsIssuance(t *testing.T) {
	for _, body := range []string{"{", "null", `{"schema_version":"future","tokens":{}}`, `{"schema_version":"dsse.enrolment_tokens.v1"}`} {
		s := NewStore()
		s.SetPersister(&failurePersister{data: []byte(body)})
		if s.Health() == nil {
			t.Fatal("invalid loaded state accepted")
		}
		now := time.Now()
		if _, secret, err := s.Issue(DefaultPolicy(), "tenant", "", "label", "admin", "", now.Add(time.Hour), now); err == nil || secret != "" {
			t.Fatal("issued with invalid state")
		}
	}
	s := NewStore()
	s.SetPersister(loadFailurePersister{})
	if s.Health() == nil {
		t.Fatal("load failure ignored")
	}
}
