// Package seatallocation is how an MSSP divides the seats its licence grants among the tenants it operates.
//
// The licence says how many devices may exist in total; this says how many belong to each customer. Without it a
// single tenant could consume the whole pool and the MSSP would find out when somebody else's enrolment failed
// for a reason their own administrator cannot see or fix.
//
// Two rules shape everything here.
//
// Running out of seats refuses NEW enrolments and never touches a working device. A seat shortfall is a
// commercial fact — a contract being renegotiated, an allocation trimmed, a fleet that grew — and none of those
// are reasons to take a customer's network down. Taking a device out of service in this product is an explicit
// administrative act; it is never derived from a number going the wrong way.
//
// Over-allocation is refused by default. Letting an MSSP hand out more than it holds moves the failure to
// whichever tenant happens to enrol last, whose administrator is inside their own allocation, cannot see the
// cause, and cannot fix it. The refusal belongs with the party who knows what they promised.
package seatallocation

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/lantern-networks/dsse-core/blobstore"
)

// Allocation is one tenant's share of the pool.
type Allocation struct {
	TenantID  string `json:"tenant_id"`
	Seats     int    `json:"seats"`
	UpdatedAt string `json:"updated_at,omitempty"`
	UpdatedBy string `json:"updated_by,omitempty"`
	Note      string `json:"note,omitempty"`
}

// Store holds the allocations. Durable, because an allocation is operator configuration: losing it on restart
// would reset every tenant to nothing and stop enrolment across the whole fleet.
type Store struct {
	mu          sync.Mutex
	allocations map[string]Allocation
	persister   blobstore.Persister
	generation  atomic.Int64
}

func NewStore() *Store {
	return &Store{allocations: map[string]Allocation{}}
}

// Generation advances on every change so callers can cheaply detect one.
func (s *Store) Generation() int64 { return s.generation.Load() }

// Policy is what the MSSP is allowed to do with its pool.
type Policy struct {
	// PoolSeats is what the licence grants right now. It changes over time as blocks start and lapse, so it is
	// passed in per call rather than stored — a copy kept here would go stale on the day it mattered.
	PoolSeats int
	// AllowOversubscription lets the total exceed the pool. Off by default; see the package comment for why the
	// failure belongs with the MSSP rather than with whichever tenant enrols last.
	AllowOversubscription bool
}

var (
	ErrPoolExceeded = fmt.Errorf("the allocations would exceed the licensed pool")
	ErrNoTenant     = fmt.Errorf("tenant is required")
	ErrNegative     = fmt.Errorf("an allocation cannot be negative")
)

// Allocate sets a tenant's share.
//
// Reducing an allocation below what a tenant is already using is ALLOWED, and is not an error: an MSSP
// reclaiming seats is a legitimate act, and the consequence is that the tenant cannot enrol more — not that
// anything it already runs stops. Refusing the reduction would leave the MSSP unable to reorganise its own pool
// without first persuading a customer to decommission machines.
func (s *Store) Allocate(policy Policy, tenantID string, seats int, by, note, now string) (Allocation, error) {
	return s.AllocateContext(context.Background(), policy, tenantID, seats, by, note, now)
}

// AllocateContext applies pool checks to the latest shared snapshot and carries
// the caller's write authority through storage. Live state follows commit only.
func (s *Store) AllocateContext(ctx context.Context, policy Policy, tenantID string, seats int, by, note, now string) (Allocation, error) {
	tenantID = strings.TrimSpace(tenantID)
	if tenantID == "" {
		return Allocation{}, ErrNoTenant
	}
	if seats < 0 {
		return Allocation{}, ErrNegative
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := Allocation{TenantID: tenantID, Seats: seats, UpdatedAt: now, UpdatedBy: strings.TrimSpace(by), Note: strings.TrimSpace(note)}
	err := s.mutateLocked(ctx, func(candidate map[string]Allocation) error {
		if !policy.AllowOversubscription {
			total := 0
			for id, a := range candidate {
				if !strings.EqualFold(id, tenantID) {
					total += a.Seats
				}
			}
			if total+seats > policy.PoolSeats {
				return fmt.Errorf("%w: %d already allocated to other tenants, %d in the pool", ErrPoolExceeded, total, policy.PoolSeats)
			}
		}
		candidate[strings.ToLower(tenantID)] = a
		return nil
	})
	if err != nil {
		return Allocation{}, err
	}
	return a, nil
}

// SeatsFor is a tenant's allocation. Zero for a tenant nobody has allocated to, which is deliberate: under an
// MSSP the act of taking on a customer includes giving them seats, and silently drawing from the unallocated
// remainder would let a tenant nobody accounted for consume somebody else's.
func (s *Store) SeatsFor(tenantID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.allocations[strings.ToLower(strings.TrimSpace(tenantID))].Seats
}

// Allocated is the sum handed out.
func (s *Store) Allocated() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for _, a := range s.allocations {
		total += a.Seats
	}
	return total
}

// Unallocated is what the MSSP still holds back. Negative when oversubscribed, which is worth showing rather
// than clamping — an operator needs to see by how much.
func (s *Store) Unallocated(poolSeats int) int {
	return poolSeats - s.Allocated()
}

// List returns the allocations, largest first, so the Console shows where the pool actually went.
// Has reports whether a quota has been SET for this tenant, which is a different question from how many seats
// it names.
//
// ★ THE DIFFERENCE IS THE WHOLE POINT (2026-08-14). SeatsFor returns 0 both for "this tenant is allowed none"
// and for "nobody has said anything about this tenant", and the enrolment path used to treat the two the same —
// so allocating seats to one tenant silently refused every other one. An operator who means zero sets zero;
// silence means the operator has not spoken, and code that cannot tell them apart will eventually act on the
// wrong one.
func (s *Store) Has(tenantID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.allocations[strings.ToLower(strings.TrimSpace(tenantID))]
	return ok
}

func (s *Store) List() []Allocation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Allocation, 0, len(s.allocations))
	for _, a := range s.allocations {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Seats != out[j].Seats {
			return out[i].Seats > out[j].Seats
		}
		return out[i].TenantID < out[j].TenantID
	})
	return out
}

// Remove drops a tenant's allocation entirely, returning its seats to the pool.
func (s *Store) Remove(tenantID string) bool {
	removed, _ := s.RemoveConfirmed(tenantID)
	return removed
}

// RemoveConfirmed distinguishes absent allocations from unconfirmed storage writes.
func (s *Store) RemoveConfirmed(tenantID string) (bool, error) {
	return s.RemoveConfirmedContext(context.Background(), tenantID)
}
func (s *Store) RemoveConfirmedContext(ctx context.Context, tenantID string) (bool, error) {
	k := strings.ToLower(strings.TrimSpace(tenantID))
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := false
	err := s.mutateLocked(ctx, func(candidate map[string]Allocation) error {
		_, removed = candidate[k]
		delete(candidate, k)
		return nil
	})
	if err != nil {
		return false, err
	}
	return removed, nil
}

// Verdict is the answer to "may this tenant enrol another device", with enough detail to say why.
type Verdict struct {
	Allowed   bool
	Allocated int
	Used      int
	// Reason is empty when allowed. It is written for an operator, not for the device: the enrolment endpoint
	// gives the caller one generic refusal so a public endpoint cannot be used to probe a tenant's capacity.
	Reason string
}

// MayEnrol answers whether one more device fits.
//
// used is the tenant's devices that are enrolled AND enabled. Disabled ones do not hold a seat — an operator who
// retires fifty machines expects to be able to enrol fifty more, and a seat occupied by a device nobody may use
// would make the count measure history instead of reality.
func MayEnrol(allocated, used int) Verdict {
	v := Verdict{Allocated: allocated, Used: used}
	switch {
	case allocated <= 0:
		v.Reason = "this tenant has no seats allocated; the MSSP allocates from its licensed pool before devices can enrol"
	case used >= allocated:
		v.Reason = fmt.Sprintf("this tenant is using all %d of its allocated seats; existing devices are unaffected", allocated)
	default:
		v.Allowed = true
	}
	return v
}

// CountForTenant reports whether this organization still has a seat allocation, and RemoveTenant erases it.
// A terminated customer's seat quota is theirs — it names them and it is what they were sold — so it belongs
// in the data footprint and in the erasure (2026-08-18).
func (s *Store) CountForTenant(tenantID string) int {
	if s == nil {
		return 0
	}
	tenantID = strings.ToLower(strings.TrimSpace(tenantID))
	if tenantID == "" {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.allocations[tenantID]; ok {
		return 1
	}
	return 0
}

func (s *Store) RemoveTenant(tenantID string) (int, error) {
	return s.RemoveTenantContext(context.Background(), tenantID)
}

func (s *Store) RemoveTenantContext(ctx context.Context, tenantID string) (int, error) {
	if s == nil {
		return 0, nil
	}
	removed, err := s.RemoveConfirmedContext(ctx, tenantID)
	if err != nil {
		return 0, err
	}
	if removed {
		return 1, nil
	}
	return 0, nil
}
