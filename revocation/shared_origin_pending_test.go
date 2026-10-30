package revocation

import (
	"context"
	"testing"
)

func TestSharedOriginFirstUnconfirmedRevokeCanRetry(t *testing.T) {
	p := &automaticSharedStore{failAfter: true}
	a := NewAdmissionRevocations()
	if err := a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	applied, err := a.RevokeCheckedContext(context.Background(), "first", "incident")
	if !applied || err != ErrAdmissionSave {
		t.Fatalf("unconfirmed revoke applied=%v err=%v", applied, err)
	}
	if _, blocked := a.IsRevoked("first"); !blocked {
		t.Fatal("authorized unconfirmed revoke failed open")
	}
	p.failAfter = false
	if applied, err := a.RevokeCheckedContext(context.Background(), "first", "incident"); !applied || err != nil {
		t.Fatalf("first-row retry applied=%v err=%v", applied, err)
	}
	reloaded := NewAdmissionRevocations()
	if err := reloaded.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, blocked := reloaded.IsRevoked("first"); !blocked {
		t.Fatal("retry did not durably save the first revocation")
	}
}

func TestSharedOriginPendingSurvivesIndependentConfirmedWrites(t *testing.T) {
	for _, next := range []string{"origin", "mesh", "erasure"} {
		t.Run(next, func(t *testing.T) {
			p := &automaticSharedStore{}
			a := NewAdmissionRevocations()
			if err := a.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if _, err := a.RevokeCheckedContext(context.Background(), "existing", "existing reason"); err != nil {
				t.Fatal(err)
			}
			p.failAfter = true
			if applied, err := a.RevokeCheckedContext(context.Background(), "pending", "pending reason"); !applied || err != ErrAdmissionSave {
				t.Fatalf("pending revoke applied=%v err=%v", applied, err)
			}
			p.failAfter = false
			switch next {
			case "origin":
				if _, err := a.RevokeCheckedContext(context.Background(), "other", "other reason"); err != nil {
					t.Fatal(err)
				}
			case "mesh":
				if _, err := a.RevokeFromMeshCheckedContext(context.Background(), "peer", "peer reason"); err != nil {
					t.Fatal(err)
				}
			case "erasure":
				if n, err := a.RemoveDevicesContext(context.Background(), []string{"existing"}); err != nil || n != 1 {
					t.Fatalf("erase n=%d err=%v", n, err)
				}
			}
			reloaded := NewAdmissionRevocations()
			if err := reloaded.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if _, blocked := a.IsRevoked("pending"); !blocked {
				t.Fatal("independent write removed live pending origin block")
			}
			if _, blocked := reloaded.IsRevoked("pending"); !blocked {
				t.Fatal("independent commit omitted pending origin block")
			}
		})
	}
}

func TestSharedOriginPendingRequiresConfirmedExplicitRestore(t *testing.T) {
	p := &automaticSharedStore{failAfter: true}
	a := NewAdmissionRevocations()
	if err := a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RevokeCheckedContext(context.Background(), "target", "incident"); err != ErrAdmissionSave {
		t.Fatal(err)
	}
	if err := a.RestoreCheckedContext(context.Background(), "target"); err != ErrAdmissionSave {
		t.Fatalf("unconfirmed restore err=%v", err)
	}
	if _, blocked := a.IsRevoked("target"); !blocked {
		t.Fatal("unconfirmed restore lifted local block")
	}
	p.failAfter = false
	if err := a.RestoreCheckedContext(context.Background(), "target"); err != nil {
		t.Fatal(err)
	}
	if _, blocked := a.IsRevoked("target"); blocked {
		t.Fatal("confirmed explicit restore did not lift local block")
	}
	reloaded := NewAdmissionRevocations()
	if err := reloaded.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, blocked := reloaded.IsRevoked("target"); blocked {
		t.Fatal("confirmed explicit restore left durable block")
	}
}

func TestSharedOriginPendingSurvivesLeadershipReload(t *testing.T) {
	p := &automaticSharedStore{}
	a := NewAdmissionRevocations()
	if err := a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if _, err := a.RevokeCheckedContext(context.Background(), "existing", "existing reason"); err != nil {
		t.Fatal(err)
	}
	p.failAfter = true
	if applied, err := a.RevokeCheckedContext(context.Background(), "pending", "pending reason"); !applied || err != ErrAdmissionSave {
		t.Fatalf("unconfirmed revoke applied=%v err=%v", applied, err)
	}
	p.failAfter = false
	if err := a.ReloadFromStore(); err != nil {
		t.Fatal(err)
	}
	if _, blocked := a.IsRevoked("pending"); !blocked {
		t.Fatal("leadership reload discarded unconfirmed local block")
	}
	if _, err := a.RevokeCheckedContext(context.Background(), "other", "other reason"); err != nil {
		t.Fatal(err)
	}
	reloaded := NewAdmissionRevocations()
	if err := reloaded.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"existing", "pending", "other"} {
		if _, blocked := reloaded.IsRevoked(id); !blocked {
			t.Fatalf("%q missing after confirmed shared write", id)
		}
	}
}

func TestSharedOriginAuthorityRefusalAppliesNothing(t *testing.T) {
	p := &automaticSharedStore{failBefore: true}
	a := NewAdmissionRevocations()
	if err := a.SetPersister(p); err != nil {
		t.Fatal(err)
	}
	if applied, err := a.RevokeCheckedContext(context.Background(), "target", "incident"); applied || err != ErrAdmissionSave {
		t.Fatalf("refused edit applied=%v err=%v", applied, err)
	}
	if _, blocked := a.IsRevoked("target"); blocked {
		t.Fatal("pre-callback authority refusal applied a revocation")
	}
}

func TestSharedMeshPendingSurvivesOriginAndErasure(t *testing.T) {
	for _, next := range []string{"origin", "erasure"} {
		t.Run(next, func(t *testing.T) {
			p := &automaticSharedStore{}
			a := NewAdmissionRevocations()
			if err := a.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if _, err := a.RevokeCheckedContext(context.Background(), "existing", "origin"); err != nil {
				t.Fatal(err)
			}
			p.failAfter = true
			if changed, err := a.RevokeFromMeshCheckedContext(context.Background(), "peer", "received"); !changed || err != ErrAdmissionSave {
				t.Fatalf("unconfirmed mesh changed=%v err=%v", changed, err)
			}
			p.failAfter = false
			switch next {
			case "origin":
				if _, err := a.RevokeCheckedContext(context.Background(), "other", "origin"); err != nil {
					t.Fatal(err)
				}
			case "erasure":
				if n, err := a.RemoveDevicesContext(context.Background(), []string{"existing"}); n != 1 || err != nil {
					t.Fatalf("erase n=%d err=%v", n, err)
				}
			}
			reloaded := NewAdmissionRevocations()
			if err := reloaded.SetPersister(p); err != nil {
				t.Fatal(err)
			}
			if _, blocked := reloaded.IsRevoked("peer"); !blocked {
				t.Fatal("independent commit omitted pending received block")
			}
		})
	}
}
