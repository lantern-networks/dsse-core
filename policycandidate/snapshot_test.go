package policycandidate

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func candidateSnapshotFixture(t *testing.T) (Candidate, []byte) {
	t.Helper()
	s := NewStore()
	p := &candidateTestPersister{}
	if e := s.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	c, e := s.ObserveCertPinFailure(context.Background(), "own", "named.example", "named.example", 443, "rejected", time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if e != nil {
		t.Fatal(e)
	}
	return c, bytes.Clone(p.data)
}
func TestCandidateSnapshotRejectsInvalidWholeStateAndRetainsWriter(t *testing.T) {
	c, valid := candidateSnapshotFixture(t)
	encode := func(tenant, id string, c Candidate) string {
		b, _ := json.Marshal(map[string]map[string]Candidate{tenant: {id: c}})
		return string(b)
	}
	invalid := []string{"", " ", "null", "[]", "{} {}", `{"own":null}`, `{" ":{}}`, encode("other", c.CandidateID, c), encode("own", "different", c), `{"own":{},"own":{}}`, strings.Replace(string(valid), `"tenant_id": "own"`, `"tenant_id": "own", "TENANT_ID": "own"`, 1), strings.Replace(string(valid), `"tenant_id": "own"`, `"tenant_id": "own", "tenant_id": "own"`, 1), strings.Replace(string(valid), `"tenant_id": "own"`, `"tenant_id": "own", "future_field": "PRIVATE"`, 1), `{"own":{"absent":null}}`}
	for _, change := range []func(*Candidate){func(c *Candidate) { c.TenantID = "" }, func(c *Candidate) { c.CandidateID = "" }, func(c *Candidate) { c.Source = "PRIVATE" }, func(c *Candidate) { c.CandidateType = "bad" }, func(c *Candidate) { c.ProposedAction = "" }, func(c *Candidate) { c.Status = "" }, func(c *Candidate) { c.Status = "bad" }, func(c *Candidate) { c.Port = 65536 }, func(c *Candidate) { c.FailureCount = -1 }, func(c *Candidate) { c.Host = ""; c.SNI = "" }, func(c *Candidate) { c.PublishProtocol = "bad" }, func(c *Candidate) { c.ObservedFromConnectorID = "bad/ref" }} {
		changed := copyCandidate(c)
		change(&changed)
		invalid = append(invalid, encode("own", c.CandidateID, changed))
	}
	for i, data := range invalid {
		s := NewStore()
		old := &candidateTestPersister{data: bytes.Clone(valid)}
		if e := s.SetPersister(old); e != nil {
			t.Fatal(e)
		}
		replacement := &candidateTestPersister{data: []byte(data)}
		if e := s.SetPersister(replacement); e == nil {
			t.Fatalf("case %d accepted invalid state", i)
		} else if strings.Contains(e.Error(), "PRIVATE") {
			t.Fatal("saved content leaked")
		}
		got, found, _ := s.Get(context.Background(), "own", c.CandidateID)
		if !found || !reflect.DeepEqual(got, c) || s.persister != old || s.dirty {
			t.Fatalf("case %d changed live state/writer", i)
		}
		if _, _, e := s.Review(context.Background(), "own", c.CandidateID, ReviewRequest{Decision: "approved"}, time.Now()); e != nil {
			t.Fatal(e)
		}
		if !bytes.Equal(replacement.data, []byte(data)) || bytes.Equal(old.data, valid) {
			t.Fatalf("case %d stole future writes", i)
		}
	}
	t.Logf("rejected %d complete snapshots", len(invalid))
}
func TestCandidateSnapshotRestoresAllSourcesWithoutChangingHistory(t *testing.T) {
	s := NewStore()
	p := &candidateTestPersister{}
	s.SetPersister(p)
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tenant := range []string{"own", "other"} {
		if _, e := s.ObserveCertPinFailure(ctx, tenant, "named.example", "", 443, "pin", now); e != nil {
			t.Fatal(e)
		}
		if _, e := s.ObserveUnmatchedFlow(ctx, tenant, "learn.example", "", 443, "", now); e != nil {
			t.Fatal(e)
		}
		if _, e := s.ObserveConnectorDiscovered(ctx, tenant, "private.example", 443, "web", "connector", "site", "namespace", []string{"route"}, now); e != nil {
			t.Fatal(e)
		}
		for _, source := range []string{"policy_learning", "operator", "import"} {
			if _, e := s.Upsert(ctx, Candidate{CandidateID: source, Source: source, ApplicationID: "app", ServiceFamily: "https", Status: "dismissed"}, tenant, now); e != nil {
				t.Fatal(e)
			}
		}
	}
	original := bytes.Clone(p.data)
	fresh := NewStore()
	if e := fresh.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(s.candidates, fresh.candidates) || !bytes.Equal(original, p.data) {
		t.Fatal("load rewrote history")
	}
	// A valid row cannot hide another invalid row in the same snapshot.
	var mixed map[string]map[string]Candidate
	json.Unmarshal(original, &mixed)
	bad := mixed["other"]["import"]
	bad.TenantID = "own"
	mixed["other"]["import"] = bad
	raw, _ := json.Marshal(mixed)
	if e := fresh.SetPersister(&candidateTestPersister{data: raw}); e == nil || !reflect.DeepEqual(s.candidates, fresh.candidates) {
		t.Fatal("mixed snapshot was partly adopted")
	}
	if e := fresh.SetPersister(&candidateTestPersister{data: []byte(`{}`)}); e != nil || len(fresh.candidates) != 0 {
		t.Fatal("explicit empty did not clear", e)
	}
	if e := fresh.SetPersister(p); e != nil {
		t.Fatal(e)
	}
	// Missing storage preserves the historical attachment behavior; the next
	// mutation saves the retained complete snapshot to the new writer.
	missing := &candidateTestPersister{}
	if e := fresh.SetPersister(missing); e != nil || !reflect.DeepEqual(s.candidates, fresh.candidates) {
		t.Fatal("missing load lost state")
	}
	if _, _, e := fresh.Review(ctx, "own", "import", ReviewRequest{Decision: "approved"}, now); e != nil {
		t.Fatal(e)
	}
	if len(missing.data) == 0 || !bytes.Equal(p.data, original) {
		t.Fatal("writer change did not isolate future saves")
	}
}
func TestCandidateAdmissionRejectsUnrestorableEvidence(t *testing.T) {
	for _, source := range []string{SourceCertPinningDetection, SourceUnmatchedFlow, SourceConnectorDiscovered} {
		for _, field := range []string{"port", "count", "timestamp", "review"} {
			s := NewStore()
			p := &candidateTestPersister{}
			s.SetPersister(p)
			c := Candidate{CandidateID: "test", Source: source, Host: "named.example", ApplicationID: "app", ServiceFamily: "https"}
			switch field {
			case "port":
				c.Port = -1
			case "count":
				c.FailureCount = -1
			case "timestamp":
				bad := "invalid"
				c.LastObserved = &bad
			case "review":
				c.ReviewReasonCode = "bad/ref"
			}
			if _, e := s.Upsert(context.Background(), c, "own", time.Now()); e == nil || len(p.data) > 0 || len(s.candidates) > 0 {
				t.Fatalf("%s %s accepted unrestorable evidence", source, field)
			}
		}
	}
}
