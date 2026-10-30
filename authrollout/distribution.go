package authrollout

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Distribution must travel inside the existing signed config bundle. Its lease
// bounds use of legacy evidence when an Edge can no longer hear the authority.
// Completion is retained durably even after that lease expires.
type Distribution struct {
	State     State     `json:"state"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	// Receiver-local, monotonic lease. Never decoded from the wire or restored on restart.
	receivedAt time.Time
	leaseUntil time.Time
}

func (s *Store) Distribute(now time.Time) (*Distribution, error) {
	v, e := s.Read()
	if e != nil {
		return nil, e
	}
	if v.Schema == 0 {
		return nil, nil
	}
	return &Distribution{State: v, IssuedAt: now.UTC(), ExpiresAt: now.UTC().Add(FreshFor), receivedAt: now, leaseUntil: now.Add(FreshFor)}, nil
}
func (d Distribution) Validate(_ time.Time) error {
	if e := d.State.Validate(); e != nil {
		return e
	}
	if d.IssuedAt.IsZero() || !d.ExpiresAt.After(d.IssuedAt) || d.ExpiresAt.Sub(d.IssuedAt) > FreshFor {
		return fmt.Errorf("expired or invalid rollout distribution")
	}
	return nil
}

// Cache uses the same transactional persistence seam as Store. It must have its
// own key/file; an unsigned local file or a reporter body is not a distribution.
type Cache struct {
	store                  *Store
	leaseRevision          uint64
	receivedAt, leaseUntil time.Time // guarded by store.mu
}

var errUnchangedDistribution = errors.New("unchanged rollout distribution")

func NewCache(s *Store) *Cache { return &Cache{store: s} }

func (c *Cache) LocalRevision() uint64 { return c.store.LocalRevision() }

// Cache persistence contains the distribution, not an authority State.
func (c *Cache) Read() (Distribution, error) {
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.store.p == nil {
		return Distribution{}, fmt.Errorf("rollout cache persistence is required")
	}
	b, e := c.store.p.Load()
	if e != nil {
		return Distribution{}, e
	}
	var d Distribution
	if len(b) > 0 {
		if e = json.Unmarshal(b, &d); e != nil {
			return d, e
		}
		if e = d.State.Validate(); e != nil {
			return d, e
		}
	}
	if d.State.Revision == c.leaseRevision {
		d.receivedAt, d.leaseUntil = c.receivedAt, c.leaseUntil
	}
	return d, nil
}
func (c *Cache) Adopt(ctx context.Context, next Distribution, now time.Time) error {
	if e := next.Validate(now); e != nil {
		return e
	}
	c.store.mu.Lock()
	defer c.store.mu.Unlock()
	if c.store.p == nil {
		return fmt.Errorf("rollout cache persistence is required")
	}
	apply := func(b []byte) ([]byte, error) {
		if len(b) > 0 {
			var old Distribution
			if e := json.Unmarshal(b, &old); e != nil {
				return nil, e
			}
			if e := old.State.Validate(); e != nil {
				return nil, e
			}
			a, z := old.State, next.State
			if a.Manifest.Deployment != z.Manifest.Deployment || a.Revision > z.Revision || a.Manifest.Generation > z.Manifest.Generation || (a.Complete && !z.Complete) {
				return nil, ErrConflict
			}
			for _, f := range a.Enabled {
				if !contains(z.Enabled, f) {
					return nil, ErrConflict
				}
			}
			if a.Revision == z.Revision {
				ab, _ := json.Marshal(a)
				zb, _ := json.Marshal(z)
				if string(ab) != string(zb) {
					return nil, ErrConflict
				}
				return nil, errUnchangedDistribution
			}
		}
		return json.Marshal(next)
	}
	var err error
	if p, ok := c.store.p.(interface {
		UpdateContext(context.Context, func([]byte) ([]byte, error)) error
	}); ok {
		err = p.UpdateContext(ctx, apply)
	} else {
		if err = ctx.Err(); err == nil {
			var b []byte
			b, err = c.store.p.Load()
			if err == nil {
				b, err = apply(b)
			}
			if err == nil {
				err = ctx.Err()
			}
			if err == nil {
				err = c.store.p.Save(b)
			}
		}
	}
	if errors.Is(err, errUnchangedDistribution) {
		return nil
	} // replay never renews a mixed lease
	if err != nil {
		return err
	}
	c.store.localRevision++
	c.leaseRevision = next.State.Revision
	c.receivedAt = now
	c.leaseUntil = now.Add(next.ExpiresAt.Sub(next.IssuedAt))
	return nil
}

func (d Distribution) AcceptLegacy(tenant, idp, digest string, now time.Time) bool {
	if d.Validate(now) != nil || d.receivedAt.IsZero() || now.Before(d.receivedAt) || !now.Before(d.leaseUntil) || d.State.Complete || digest == "" || d.State.Manifest.Providers[ProviderKey(tenant, idp)] != digest {
		return false
	}
	for _, n := range d.State.Manifest.Members {
		if n.Retired {
			continue
		}
		if _, observed := d.State.Observed[n.ID]; !observed && (n.Version == "awaiting-first-report" || n.Version == "unknown") {
			return false
		}
	}
	return true
}
func (d Distribution) FeatureEnabled(feature string, now time.Time) bool {
	return d.Validate(now) == nil && d.State.Complete && contains(d.State.Enabled, feature)
}
