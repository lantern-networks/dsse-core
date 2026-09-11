package main

// goes_home_when_it_can.go — a connector that failed over returns to the operator's first door once that door
// has been answering for long enough to trust.
//
// ★★★ NOTHING ENDS A TUNNEL THAT IS WORKING, SO A CONNECTOR THAT FAILED OVER NEVER WENT HOME. Failback was
// evaluated in one place: after a tunnel ENDED, having held long enough to count the door as good. That
// covers a connector bouncing between doors. It does not cover the ordinary case — the second region answers,
// the tunnel holds for hours, and the loop that would send the connector home is never reached. A five-minute
// outage in the first region therefore became a permanent change to where a customer's private estate is
// reached from, and nothing in the deployment ever revisited it.
//
// The door ORDER is an operator decision — the first door is normally the region nearest the estate behind
// this connector — so staying away means every flow to it is relayed across regions for ever, quietly.
//
// ★ GOING HOME COSTS A RECONNECT, SO IT IS EARNED, NOT GUESSED. The preferred door has to answer as an EDGE
// (the same authenticated call the routes poll makes, not a TCP connect) on several consecutive checks before
// anything moves. A door that is flapping never accumulates the run, so this can never turn one bad region
// into a loop of cutovers.

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

const (
	// connectorHomeCheckEvery is how often a connector that is away looks at the door it prefers.
	connectorHomeCheckEvery = 60 * time.Second
	// connectorHomeStableChecks is how many consecutive answers that door must give before the connector moves
	// back. With the interval above this is several minutes of proven health — long enough that a region
	// coming up, falling over and coming up again cannot drag the connector back and forth.
	connectorHomeStableChecks = 3
)

// watchForHome sends this connector back to the operator's first door once that door has answered on
// connectorHomeStableChecks consecutive checks. It does nothing while the connector is already there.
func watchForHome(ctx context.Context, doors *connectorEndpoints, attachments *connectorFleetAttachments,
	connectorID, connectorSecret string, tlsConfig *tls.Config) {
	answered := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(connectorHomeCheckEvery):
		}
		if doors.atPreferred() {
			answered = 0
			continue
		}
		home, region := doors.preferred()
		if home == "" {
			continue
		}
		if err := connectorDoorAnswers(ctx, home, connectorID, connectorSecret, tlsConfig); err != nil {
			if answered > 0 {
				log.Printf("connector: %s%s is not answering yet (%v) — staying where it is", home, regionSuffix(region), err)
			}
			answered = 0
			continue
		}
		answered++
		if answered < connectorHomeStableChecks {
			continue
		}
		answered = 0
		log.Printf("connector: %s%s has answered %d checks in a row — going back to it. Everything behind this "+
			"connector is briefly unreachable while the tunnels move, which is the cost of returning to the "+
			"door the operator put first", home, regionSuffix(region), connectorHomeStableChecks)
		doors.resetToPreferred()
		if letGo := attachments.letGoOfEverything(); len(letGo) > 0 {
			log.Printf("connector let go of %v so its workers re-dial at %s%s", letGo, home, regionSuffix(region))
		}
	}
}

// connectorDoorAnswers asks a door for this connector's effective routes — the same authenticated call the
// routes poll makes. It has to reach an EDGE and be recognised as this connector, so a front door that is
// listening with nothing healthy behind it does not count as an answer.
func connectorDoorAnswers(ctx context.Context, edgeURL, connectorID, connectorSecret string, tlsConfig *tls.Config) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	url := fmt.Sprintf("%s/connectors/%s/effective-routes", strings.TrimRight(edgeURL, "/"), connectorID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if connectorSecret != "" {
		req.Header.Set(connectorSecretHeader, connectorSecret)
	}
	resp, err := newConnectorEdgeHTTPClient(tlsConfig).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}
