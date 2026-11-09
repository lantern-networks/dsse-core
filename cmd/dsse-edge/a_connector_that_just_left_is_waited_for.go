package main

// a_connector_that_just_left_is_waited_for.go — the node a connector just left holds what arrives for it, for
// as long as a tunnel open is already given to answer, instead of refusing it.
//
// ★★★ EIGHT SECONDS OF REFUSALS EVERY TIME A CONNECTOR WENT HOME (2026-11-07, measured on 0.4.1 acceptance B,
// three regions, one machine each). The connector had failed over to region-b with the device, as designed;
// region-a came back and the connector went home. A device that is running does not follow — also by design —
// so the device stayed on region-b, and region-b was the one Edge in the deployment that had no way to reach
// what the connector fronts:
//
//	01:53:41 connector  let go of [c25dd1b09a5f] so its workers re-dial at region-a
//	01:53:43 region-a   connector_tunnel_attached … region=region-a
//	01:53:49 region-b   connector_unreachable host="10.43.1.30" … has no live tunnel on this node
//	01:53:49 region-b   connector_attached_region_learned connector=… region=region-a
//
// Two seconds with the connector attached nowhere (it paused before redialling a door it had just proved), then
// six more while region-b's catalogue still said "region-b" and the next configuration poll had not come. One
// of 109 measurements fell in it. After any regional outage, every connector that goes home does this to
// whatever its estate is being asked for at that moment.
//
// ★ ONLY THIS NODE KNOWS A MOVE IS UNDER WAY. It saw the tunnel end. Everywhere else "no tunnel" is ambiguous
// between moving and gone, so the wait is armed by a DEPARTURE seen here and by nothing else, and it lasts as long
// as a flow is already allowed to wait for a connector to answer an open (tunnel.DefaultRequestTimeout). A
// connector that is not coming back costs a flow that much and then the same refusal as before.
//
// ★ AND IT HURRIES THE ANSWER WITHOUT LETTING TRAFFIC DECIDE THE LOAD. The new node reports the attachment the
// moment the tunnel lands; what is slow is this node asking. So a departure asks the control plane early — one
// second after, then doubling, stopping as soon as the answer has moved or the wait is over. That is at most a
// handful of extra pulls per departure, however many flows are waiting: the cost follows connector moves, which
// are rare, never flow volume, which is not.

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/tunnel"
)

// connectorDepartureLog remembers which connectors just left this node, and wakes the flows waiting for one of
// them whenever something happens that can change where the deployment says it is.
//
// restart-durability: ephemeral — every entry lives for one tunnel request timeout after a departure, and a
// restart ends every tunnel this node held anyway; nothing an operator reads comes from it. Losing it costs a
// flow arriving in those seconds the immediate refusal it got before this existed.
//
// populated-by: side_effect — the connector tunnel handler, the one path a connector's tunnel to this node ends
// on (tunnelManager.Unregister). A connector that never held a tunnel here is absent, which is the point: only a
// departure seen here makes "no tunnel" mean "on its way".
type connectorDepartureLog struct {
	mu   sync.Mutex
	left map[string]time.Time
	// news is closed and replaced every time something that can change a reach decision happens: a pull from
	// the control plane finished, or a connector's tunnel arrived here. Waiters look again; most will find
	// nothing new and wait for the next.
	news chan struct{}
	// hurry asks the configuration pull to run now. Buffered by one, so requests made while one is pending
	// collapse into it.
	hurry chan struct{}
	// window is how long a departure is waited for, and firstHurry when the first early pull is asked for.
	window     time.Duration
	firstHurry time.Duration
	now        func() time.Time
}

func newConnectorDepartureLog(window, firstHurry time.Duration) *connectorDepartureLog {
	return &connectorDepartureLog{
		left: map[string]time.Time{}, news: make(chan struct{}), hurry: make(chan struct{}, 1),
		window: window, firstHurry: firstHurry, now: time.Now,
	}
}

// connectorDepartures is this node's log. The wait is what a flow already allows a connector to answer an
// open; the first early pull is a second after the departure — a connector moving on purpose redials at
// once, and lands and reports well inside that on any healthy deployment.
var connectorDepartures = newConnectorDepartureLog(tunnel.DefaultRequestTimeout, time.Second)

// departed records that this node no longer holds any tunnel for the connector, and starts asking the control
// plane early where it went.
func (d *connectorDepartureLog) departed(connectorID string) {
	id := strings.TrimSpace(connectorID)
	if d == nil || id == "" {
		return
	}
	at := d.now()
	d.mu.Lock()
	d.left[id] = at
	d.mu.Unlock()
	go d.hurryLearning(id, at)
}

// arrived records that a tunnel for the connector registered here again: there is nothing left to wait for.
func (d *connectorDepartureLog) arrived(connectorID string) {
	d.settle(connectorID)
}

// learned records that the control plane named a new region for the connector: the waiting flows can be
// routed there now.
func (d *connectorDepartureLog) learned(connectorID string) {
	d.settle(connectorID)
}

func (d *connectorDepartureLog) settle(connectorID string) {
	id := strings.TrimSpace(connectorID)
	if d == nil || id == "" {
		return
	}
	d.mu.Lock()
	delete(d.left, id)
	d.mu.Unlock()
	d.announce()
}

// announce wakes every waiting flow to look again.
func (d *connectorDepartureLog) announce() {
	if d == nil {
		return
	}
	d.mu.Lock()
	close(d.news)
	d.news = make(chan struct{})
	d.mu.Unlock()
}

// hurryRequests is what the configuration pull listens to for an early pull.
func (d *connectorDepartureLog) hurryRequests() <-chan struct{} {
	if d == nil {
		return nil
	}
	return d.hurry
}

// hurryLearning asks for an early pull at firstHurry after the departure and then at doubling intervals, for
// as long as this departure is still the one recorded and the wait is not over.
func (d *connectorDepartureLog) hurryLearning(id string, at time.Time) {
	for delay := d.firstHurry; delay > 0 && delay < d.window; delay *= 2 {
		if wait := at.Add(delay).Sub(d.now()); wait > 0 {
			time.Sleep(wait)
		}
		d.mu.Lock()
		recorded, still := d.left[id]
		d.mu.Unlock()
		if !still || !recorded.Equal(at) {
			return
		}
		select {
		case d.hurry <- struct{}{}:
		default: // one is already pending; it will carry the same answer
		}
	}
}

// await is ConnectorMoveAwaiter for this node. False at once for a connector that has not just left; for one
// that has, true when there is news worth looking again for, false when the wait is over.
func (d *connectorDepartureLog) await(ctx context.Context, connectorID string) bool {
	id := strings.TrimSpace(connectorID)
	if d == nil || id == "" {
		return false
	}
	d.mu.Lock()
	at, ok := d.left[id]
	if !ok {
		d.mu.Unlock()
		return false
	}
	remaining := at.Add(d.window).Sub(d.now())
	if remaining <= 0 {
		delete(d.left, id)
		d.mu.Unlock()
		return false
	}
	news := d.news
	d.mu.Unlock()
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-news:
		return true
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	}
}

// tunnelsThatRememberDepartures is the tunnel manager as the egress paths see it: the live tunnels, and
// which connectors just left. See edgeplane.ConnectorMoveAwaiter.
type tunnelsThatRememberDepartures struct {
	*tunnel.Manager
	departures *connectorDepartureLog
}

func (t tunnelsThatRememberDepartures) AwaitConnectorMove(ctx context.Context, connectorID string) bool {
	return t.departures.await(ctx, connectorID)
}
