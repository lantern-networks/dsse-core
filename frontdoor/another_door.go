package frontdoor

// another_door.go — leaving through another of this deployment's doors when the one on this machine does not
// answer.
//
// ★★★ A STOPPED DOOR LOCKED OUT A DEPLOYMENT WITH TWO WORKING ONES, TWICE (2026-11-08, acceptance C).
//
// Every machine of the profiles that have a door per machine resolves the deployment's names — admin.<host> for
// sign-in and the control plane, <node>.admin.<host> for an Edge, authority.<region>.<host> for what an Edge
// reports — to the door on the same machine. Stopping that one door therefore stopped everything on the machine
// that asked those names, even though the machine itself, and the doors of the others, were fine.
//
//   - Second walk: the Console beside the leader answered 502 for every sign-in, at every door. Fixed by letting
//     the Console leave through the other doors.
//   - Third walk: the Edge on the same machine lost the control plane — no session checks, no configuration, no
//     revocations, no audit — and answered 401 after a long wait for every screen that asked it directly, while
//     the Console in front of it had already moved to another door. The same remedy, for the Edge.
//
// The other doors route the same names to the same places in a one-region profile, so leaving through any of
// them reaches the same service. Only where the connection is MADE changes: the TLS server name, the Host and
// the certificate check stay those of the name in the URL, so a door that routes a name somewhere else is
// answered by whatever it routes to, and nothing outside the deployment's own doors is ever in the list.
//
// The door on this machine stays first: it is one hop, and it is the one everything has always used. When it
// refuses, new connections go to the other doors for a short while before it is tried again, so a stopped door
// costs one short wait, not one per request. A connection already open is not moved.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Dialer connects to this machine's door, or to the other doors when it does not answer.
type Dialer struct {
	// Who is leaving, for the log ("the Console", "this Edge").
	Who string
	// FirstWait bounds the attempt on this machine's door when there is somewhere else to go. A door on the same
	// machine answers in well under a millisecond; one whose container is stopped does not answer at all.
	FirstWait time.Duration
	OtherWait time.Duration
	// Rest is how long new connections go to the other doors first after this machine's door refused.
	Rest time.Duration
	Now  func() time.Time
	Dial func(ctx context.Context, network, address string, wait time.Duration) (net.Conn, error)
	// Lookup resolves a name the way the process does (the container's hosts file first). Only used with
	// OnlyFor, to tell whether a name is this machine's door.
	Lookup func(ctx context.Context, host string) ([]string, error)

	fallbacks []string
	// local, when set, is the set of addresses that ARE this machine's door. Anything else is dialled as it is,
	// with no detour: an Edge also talks to identity providers and connectors, and sending one of those to the
	// deployment's doors would be wrong even though the certificate check would refuse the answer.
	local map[string]bool

	mu        sync.Mutex
	firstDown map[string]time.Time
}

// Parse reads a comma-separated host:port list of the other doors. setting names where the list came from, for
// the error. An empty list is no Dialer at all (nil, nil): there is nowhere else to go.
func Parse(raw, setting string) (*Dialer, error) {
	d := &Dialer{
		Who:       "this service",
		FirstWait: time.Second,
		OtherWait: 3 * time.Second,
		Rest:      15 * time.Second,
		Now:       time.Now,
		firstDown: map[string]time.Time{},
		Dial: func(ctx context.Context, network, address string, wait time.Duration) (net.Conn, error) {
			return (&net.Dialer{Timeout: wait, KeepAlive: 30 * time.Second}).DialContext(ctx, network, address)
		},
		Lookup: net.DefaultResolver.LookupHost,
	}
	list, err := parseDoors(raw, setting)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, nil
	}
	d.fallbacks = list
	return d, nil
}

// OnlyFor limits the detour to dials of these addresses (this machine's door). raw is a host:port list like the
// one Parse reads; an empty list leaves every dial eligible.
func (d *Dialer) OnlyFor(raw, setting string) error {
	list, err := parseDoors(raw, setting)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		d.local = nil
		return nil
	}
	d.local = make(map[string]bool, len(list))
	for _, a := range list {
		d.local[a] = true
	}
	return nil
}

// Fallbacks is the other doors, in the order they are tried.
func (d *Dialer) Fallbacks() []string { return append([]string(nil), d.fallbacks...) }

func parseDoors(raw, setting string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		host, port, err := net.SplitHostPort(part)
		number, perr := strconv.Atoi(port)
		if err != nil || perr != nil || number < 1 || number > 65535 || host == "" || strings.ContainsAny(host, "/@?# \t") {
			return nil, fmt.Errorf("%s: %q is not host:port", setting, part)
		}
		if !seen[part] {
			seen[part] = true
			out = append(out, part)
		}
	}
	return out, nil
}

// DialContext connects to address — the door the name resolves to on this machine — or, when that door does not
// answer, to the other doors in order. An address that is not this machine's door (see OnlyFor) is dialled as
// it is.
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if d.local != nil && !d.isLocalDoor(ctx, address) {
		return (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext(ctx, network, address)
	}
	d.mu.Lock()
	resting := d.Now().Before(d.firstDown[address])
	d.mu.Unlock()
	order := append([]string{address}, d.fallbacks...)
	if resting {
		order = append(append([]string{}, d.fallbacks...), address)
	}
	var errs []error
	for _, target := range order {
		if ctx.Err() != nil {
			break
		}
		wait := d.OtherWait
		if target == address {
			wait = d.FirstWait
		}
		conn, err := d.Dial(ctx, network, target, wait)
		if err == nil {
			if target == address {
				d.mu.Lock()
				delete(d.firstDown, address)
				d.mu.Unlock()
			} else if !resting {
				log.Printf("front door: %s did not answer; %s reached it through the door at %s", address, d.Who, target)
			}
			return conn, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", target, err))
		if target == address {
			d.mu.Lock()
			d.firstDown[address] = d.Now().Add(d.Rest)
			d.mu.Unlock()
		}
	}
	if err := ctx.Err(); err != nil {
		errs = append(errs, err)
	}
	return nil, errors.Join(errs...)
}

// isLocalDoor says whether address leads to this machine's door.
//
// ★★ THE NAME, NOT THE STRING (review C3-R1, 2026-11-08). An HTTP transport hands DialContext the URL's host —
// "admin.region-a.<host>:443" — before anything resolves it, and this machine's door is configured as an
// address. Comparing the two strings, the fallback was never taken on a generated deployment: every test used an
// address in the URL and passed. A name is resolved the way the process resolves it (the container's hosts file
// answers first) and counts as the door when any of its addresses is the door.
func (d *Dialer) isLocalDoor(ctx context.Context, address string) bool {
	if d.local[address] {
		return true
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return false
	}
	if ip := net.ParseIP(host); ip != nil {
		return d.local[net.JoinHostPort(ip.String(), port)]
	}
	lookup := d.Lookup
	if lookup == nil {
		lookup = net.DefaultResolver.LookupHost
	}
	lctx, cancel := context.WithTimeout(ctx, d.FirstWait+time.Second)
	defer cancel()
	addrs, err := lookup(lctx, host)
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip != nil && d.local[net.JoinHostPort(ip.String(), port)] {
			return true
		}
	}
	return false
}
