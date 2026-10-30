package main

import (
	"log"
	"sync"
	"time"

	"github.com/lantern-networks/dsse-core/edgeplane"
)

// One final result per held flow. A bridge error after an established upstream
// must not reverse an already-confirmed resumed result. Persist before sending;
// when the write is uncertain the endpoint sees unknown and may requery.
type authResultNotifier struct {
	once  sync.Once
	store authFlowResultStore
	flow  *edgeplane.MuxVirtualConn
	base  authFlowResult
}

func (n *authResultNotifier) Final(result string) {
	n.final(result, false)
}

// A successful upstream connection must start carrying data without waiting
// for the CP result ledger. The terminal result is still stored before the
// agent is notified; a failed or ambiguous store write remains unknown.
func (n *authResultNotifier) FinalAsync(result string) {
	n.final(result, true)
}

var authResultAsyncSlots = make(chan struct{}, 256)

func (n *authResultNotifier) final(result string, async bool) {
	if n == nil || n.base.RequestID == "" {
		return
	}
	n.once.Do(func() {
		if async {
			select {
			case authResultAsyncSlots <- struct{}{}:
				go func() {
					defer func() { <-authResultAsyncSlots }()
					n.persistAndNotify(result)
				}()
			default:
				log.Printf("auth_flow_result_unconfirmed reason=async_capacity")
			}
			return
		}
		n.persistAndNotify(result)
	})
}

func (n *authResultNotifier) persistAndNotify(result string) {
	if n.store == nil {
		log.Printf("auth_flow_result_unconfirmed reason=authority_unavailable")
		return
	}
	entry := n.base
	entry.Result = result
	entry.FinalAt = time.Now().UTC().Unix()
	entry.ExpiresAt = entry.FinalAt + int64(authFlowResultTTL/time.Second)
	if err := n.store.Record(entry); err != nil {
		log.Printf("auth_flow_result_unconfirmed reason=store_failed: %v", err)
		return
	}
	if n.flow != nil {
		_ = n.flow.SendAuthResult(entry.RequestID, result)
	}
}
