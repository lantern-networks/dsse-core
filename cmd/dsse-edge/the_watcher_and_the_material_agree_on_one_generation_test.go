package main

import (
	"sync"
	"testing"
	"time"
)

// ★★★ THE TIMER, THE JUDGEMENT AND THE SELECTOR MUST BE LOOKING AT ONE GENERATION OF MATERIAL
// (2026-09-08, asked for by review after three rounds of "one is fixed and the next transition breaks").
//
// A mutex stops two goroutines corrupting a map. It does not stop a decision taken about material that has
// since been replaced — which is what actually happened here three ways: a deadline computed before a
// promotion, applied after it; an interval derived before an install, slept through after it; a refusal
// written from a snapshot that was already old.
func TestTheWatcherFollowsMaterialInstalledAfterItStartedSleeping(t *testing.T) {
	useEmptyTenantCertificateIndex(t)
	at := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	useTransportInstallClock(t, func() time.Time { return at })
	useTransportSelectorClock(t, func() time.Time { return at })
	f := &tenantTransportMaterialFetcher{log: func(string, ...any) {}}

	// Twelve hours of material: the watcher would sleep its ordinary minute.
	installForTest(t, f, "tenant_long", 12*time.Hour, at)
	if got := f.watchInterval(at); got != time.Minute {
		t.Fatalf("with twelve hours held the watcher looked every %s", got)
	}

	// ★ AND NOW MATERIAL WITH ONE MINUTE OF LIFE ARRIVES, which under time.Sleep would have been watched on
	// an interval chosen before it existed.
	waiting := f.deadlineChanged()
	installForTest(t, f, "tenant_short", time.Minute, at)
	select {
	case <-waiting:
	default:
		t.Fatal("installing material with a shorter life did not wake the expiry watcher, so it would finish " +
			"a sleep chosen for the material it held before")
	}
	if got := f.watchInterval(at); got >= time.Minute {
		t.Fatalf("the watcher did not follow the shorter deadline: %s", got)
	}
}

// ★★ A JUDGEMENT TAKEN BEFORE A PROMOTION MUST NOT BE APPLIED AFTER IT. This is the crossing the review
// asked for: the old observation is genuinely stale, and re-running it must consult what is being served now
// rather than what was being served when it was taken.
func TestAJudgementTakenBeforeAPromotionIsNotAppliedAfterIt(t *testing.T) {
	useEmptyTenantCertificateIndex(t)
	at := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	useTransportInstallClock(t, func() time.Time { return at })
	useTransportSelectorClock(t, func() time.Time { return at })
	fatals := []string{}
	f := &tenantTransportMaterialFetcher{
		log:   func(string, ...any) {},
		fatal: func(format string, a ...any) { fatals = append(fatals, sprintf(format, a...)) },
	}
	authority := newTenantTransportAuthority(nil, nil, func() time.Time { return at })
	if _, err := authority.EnsureCA("tenant_a", "tenant-a.example.com"); err != nil {
		t.Fatal(err)
	}
	short, err := authority.IssueFor("tenant_a", "edge-a", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := installTenantTransportMaterial(short); err != nil {
		t.Fatal(err)
	}
	if _, err := authority.RotateCA("tenant_a"); err != nil {
		t.Fatal(err)
	}
	both, err := authority.IssueAllFor("tenant_a", "edge-a", 12*time.Hour)
	if err != nil || len(both) != 2 {
		t.Fatalf("fixture did not stage an authority: %v", err)
	}
	for _, m := range both {
		if err := installTenantTransportMaterial(m); err != nil {
			t.Fatal(err)
		}
	}
	// The promotion happens, and only then is the judgement run at a moment past the OLD material's end.
	if !transportTenantCertificates.PromotePending("tenant_a") {
		t.Fatal("the fixture did not promote")
	}
	after := at.Add(2 * time.Minute)
	useTransportSelectorClock(t, func() time.Time { return after })
	if _, leaving := f.judgeMaterialExpiry(after); leaving || len(fatals) != 0 {
		t.Fatalf("a node serving a certificate valid for twelve hours left on the deadline of material it had "+
			"already replaced: %v", fatals)
	}
	if reason, refused := transportTenantCertificates.refusalFor("tenant-a.example.com"); refused {
		t.Fatalf("the promoted certificate was refused on the superseded material's deadline: %s", reason)
	}
}

// ★ AND THE CERTIFICATE AND ITS DEADLINE ARE WRITTEN TOGETHER, so a reader can never see one without the
// other. Run under -race this also covers the data race; the assertion is about the pairing, which -race
// cannot see.
func TestACertificateAndItsDeadlineAreNeverReadFromDifferentGenerations(t *testing.T) {
	useEmptyTenantCertificateIndex(t)
	at := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	useTransportInstallClock(t, func() time.Time { return at })
	useTransportSelectorClock(t, func() time.Time { return at })
	f := &tenantTransportMaterialFetcher{log: func(string, ...any) {}}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			// Alternating lifetimes, so a torn read would pair one generation's certificate with another's
			// deadline and the check below would see a deadline that belongs to neither.
			life := 12 * time.Hour
			if i%2 == 1 {
				life = 6 * time.Hour
			}
			installForTest(t, f, "tenant_a", life, at)
		}
	}()
	for i := 0; i < 300; i++ {
		deadlines := transportTenantCertificates.ActiveDeadlines()
		for tenant, deadline := range deadlines {
			if tenant != "tenant_a" {
				continue
			}
			d := deadline.Sub(at)
			if d != 12*time.Hour && d != 6*time.Hour {
				t.Fatalf("a deadline that belongs to no generation of this material: %s", d)
			}
		}
	}
	close(stop)
	wg.Wait()
}

func installForTest(t *testing.T, f *tenantTransportMaterialFetcher, tenant string, ttl time.Duration, at time.Time) {
	t.Helper()
	authority := newTenantTransportAuthority(nil, nil, func() time.Time { return at })
	if _, err := authority.EnsureCA(tenant, tenant+".example.com"); err != nil {
		t.Fatal(err)
	}
	mat, err := authority.IssueFor(tenant, "edge-a", ttl)
	if err != nil {
		t.Fatal(err)
	}
	if err := installTenantTransportMaterial(mat); err != nil {
		t.Fatal(err)
	}
	f.noteDeadlineChanged()
}
