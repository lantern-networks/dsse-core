package internalca

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type faultPersistence struct {
	rows                     []Authority
	failUpsert, failDelete   bool
	loadErr                  error
	loads, writes            int
	loadStarted, loadRelease chan struct{}
}

func (p *faultPersistence) LoadAll() ([]Authority, error) {
	p.loads++
	if p.loadStarted != nil {
		close(p.loadStarted)
		<-p.loadRelease
	}
	return append([]Authority(nil), p.rows...), p.loadErr
}
func (p *faultPersistence) Upsert(a Authority) error {
	p.writes++
	if p.failUpsert {
		return fmt.Errorf("private-storage-location")
	}
	for i, old := range p.rows {
		if key(old.ID, old.TenantID) == key(a.ID, a.TenantID) {
			p.rows[i] = a
			return nil
		}
	}
	p.rows = append(p.rows, a)
	return nil
}
func (p *faultPersistence) Delete(id, tenant string) error {
	p.writes++
	if p.failDelete {
		return fmt.Errorf("private-storage-location")
	}
	next := []Authority{}
	for _, a := range p.rows {
		if key(a.ID, a.TenantID) != key(id, tenant) {
			next = append(next, a)
		}
	}
	p.rows = next
	return nil
}
func TestPersistenceFailureNeverPublishesUnconfirmedTrust(t *testing.T) {
	now := time.Now()
	p := &faultPersistence{}
	s, _ := NewStore(p)
	a := Authority{ID: "one", TenantID: "tenant", Name: "Original", CertificatePEM: caPEM(t, "Original", now.Add(time.Hour), true)}
	p.failUpsert = true
	if _, err := s.Upsert(a, now); !errors.Is(err, ErrPersistence) {
		t.Fatal(err)
	}
	if len(s.ListAll(now)) != 0 || s.ConfigGeneration() != 0 {
		t.Fatal("failed add changed live trust")
	}
	p.failUpsert = false
	original, err := s.Upsert(a, now)
	if err != nil {
		t.Fatal(err)
	}
	rev := s.ConfigGeneration()
	a.CertificatePEM = caPEM(t, "Replacement", now.Add(time.Hour), true)
	p.failUpsert = true
	if _, err := s.Upsert(a, now); !errors.Is(err, ErrPersistence) {
		t.Fatal(err)
	}
	if got := s.List("tenant", now); len(got) != 1 || got[0] != original || s.ConfigGeneration() != rev {
		t.Fatal("failed update replaced trusted CA")
	}
	p.failDelete = true
	if deleted, err := s.DeleteChecked("one", "tenant", now); deleted || !errors.Is(err, ErrPersistence) {
		t.Fatal(deleted, err)
	}
	if s.Delete("one", "tenant", now) {
		t.Fatal("compatibility delete reported success")
	}
	if s.ConfigGeneration() != rev || len(s.AnchorsPEM("tenant", now)) != 1 {
		t.Fatal("failed delete changed live")
	}
	restarted, err := NewStore(p)
	if err != nil || !reflect.DeepEqual(restarted.List("tenant", now), s.List("tenant", now)) {
		t.Fatal("restart disagrees with failed operation", err)
	}
	p.failDelete = false
	if deleted, err := s.DeleteChecked("one", "TENANT", now); deleted || err != nil {
		t.Fatal("foreign delete")
	}
	if s.ConfigGeneration() != rev {
		t.Fatal("missing delete moved revision")
	}
	if deleted, err := s.DeleteChecked("one", "tenant", now); !deleted || err != nil {
		t.Fatal(deleted, err)
	}
	restarted, err = NewStore(p)
	if err != nil || len(restarted.ListAll(now)) != 0 || len(s.AnchorsPEM("tenant", now)) != 0 || s.ConfigGeneration() <= rev {
		t.Fatal("successful delete not durable")
	}
}
func TestMixedPEMRejectedAcrossEveryStoreIntake(t *testing.T) {
	now := time.Now()
	pem := caPEM(t, "Safe", now.Add(time.Hour), true)
	a := Authority{ID: "one", TenantID: "tenant", CertificatePEM: pem}
	for label, material := range map[string]string{"key": pem + "-----BEGIN PRIVATE KEY-----\nc2VjcmV0\n-----END PRIVATE KEY-----", "secondCA": pem + pem, "prefix": "secret\n" + pem, "trailing": pem + "secret", "header": strings.Replace(pem, "-----BEGIN CERTIFICATE-----", "-----BEGIN CERTIFICATE-----\nComment: secret\n", 1), "malformedFirst": "-----BEGIN CERTIFICATE-----\ninvalid\n" + pem} {
		t.Run(label, func(t *testing.T) {
			p := &faultPersistence{}
			s, _ := NewStore(p)
			if _, err := s.Upsert(a, now); err != nil {
				t.Fatal(err)
			}
			old := s.ListAll(now)
			rev := s.ConfigGeneration()
			bad := a
			bad.CertificatePEM = material
			if _, err := s.Upsert(bad, now); err == nil {
				t.Fatal("upsert accepted mixed material")
			}
			if err := s.ReplaceAll([]Authority{bad}); err == nil {
				t.Fatal("bundle accepted mixed material")
			}
			if err := s.ReplaceTenant("tenant", []Authority{bad}); err == nil {
				t.Fatal("tenant replace accepted mixed material")
			}
			p.rows = []Authority{bad}
			if err := s.Reload(); err == nil {
				t.Fatal("reload accepted mixed material")
			}
			if _, err := NewStore(p); err == nil {
				t.Fatal("startup accepted mixed material")
			}
			if !reflect.DeepEqual(old, s.ListAll(now)) || s.ConfigGeneration() != rev || len(s.AnchorsPEM("tenant", now)) != 1 {
				t.Fatal("rejection changed previous trust")
			}
		})
	}
}
func TestAuthoritySnapshotValidationAndMetadataRefresh(t *testing.T) {
	now := time.Now()
	a := Authority{ID: "one", TenantID: "tenant", Name: "Before", CertificatePEM: caPEM(t, "Safe", now.Add(time.Hour), true)}
	p := &faultPersistence{rows: []Authority{a}}
	s, err := NewStore(p)
	if err != nil {
		t.Fatal(err)
	}
	p.rows[0].Name = "After"
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if s.List("tenant", now)[0].Name != "After" {
		t.Fatal("rename ignored")
	}
	rev := s.ConfigGeneration()
	if err := s.Reload(); err != nil || s.ConfigGeneration() != rev {
		t.Fatal("unchanged reload invalidates cache")
	}
	for _, rows := range [][]Authority{{a, a}, {{ID: "", TenantID: "tenant", CertificatePEM: a.CertificatePEM}}, {{ID: "a\x00b", TenantID: "tenant", CertificatePEM: a.CertificatePEM}}, {{ID: "a", TenantID: "", CertificatePEM: a.CertificatePEM}}} {
		p.rows = rows
		if err := s.Reload(); err == nil {
			t.Fatal("invalid snapshot accepted")
		}
		if s.ConfigGeneration() != rev || s.List("tenant", now)[0].Name != "After" {
			t.Fatal("invalid load replaced snapshot")
		}
	}
	expired := a
	expired.CertificatePEM = caPEM(t, "Expired", now.Add(-time.Hour), true)
	p.rows = []Authority{expired}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	if !s.List("tenant", now)[0].Expired || len(s.AnchorsPEM("tenant", now)) != 0 {
		t.Fatal("expired CA must be visible but untrusted")
	}
}
func TestReloadCannotOverwriteConcurrentCompletedMutation(t *testing.T) {
	now := time.Now()
	a := Authority{ID: "one", TenantID: "tenant", CertificatePEM: caPEM(t, "Safe", now.Add(time.Hour), true)}
	p := &faultPersistence{rows: []Authority{a}}
	s, _ := NewStore(p)
	p.loadStarted = make(chan struct{})
	p.loadRelease = make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := s.Reload(); err != nil {
			t.Error(err)
		}
	}()
	<-p.loadStarted
	started := make(chan struct{})
	go func() {
		defer wg.Done()
		close(started)
		if ok, err := s.DeleteChecked("one", "tenant", now); !ok || err != nil {
			t.Error(ok, err)
		}
	}()
	<-started
	close(p.loadRelease)
	wg.Wait()
	if len(s.ListAll(now)) != 0 || len(p.rows) != 0 {
		t.Fatal("reload restored deleted CA")
	}
}

func TestTrustReadersRemainAvailableDuringSlowReload(t *testing.T) {
	now := time.Now()
	a := Authority{ID: "one", TenantID: "tenant", CertificatePEM: caPEM(t, "Safe", now.Add(time.Hour), true)}
	p := &faultPersistence{rows: []Authority{a}}
	s, _ := NewStore(p)
	p.loadStarted = make(chan struct{})
	p.loadRelease = make(chan struct{})
	done := make(chan error, 1)
	go func() { done <- s.Reload() }()
	<-p.loadStarted
	read := make(chan int, 1)
	go func() { read <- len(s.AnchorsPEM("tenant", now)) }()
	select {
	case n := <-read:
		if n != 1 {
			t.Error("last good trust unavailable")
		}
	case <-time.After(time.Second):
		t.Error("trust reader blocked on storage")
	}
	close(p.loadRelease)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
